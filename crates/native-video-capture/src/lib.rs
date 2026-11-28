// Native camera discovery and RGB capture isolated in a same-executable helper.
//
// A killed helper releases blocking driver reads before its owned pipe reader is joined.

use anyhow::{anyhow, bail, Context, Result};
use nokhwa::{
    pixel_format::RgbFormat,
    utils::{CameraFormat, CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType},
    Camera, FormatDecoder,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const LIST_FLAG: &str = "--native-camera-list";
const CAPTURE_FLAG: &str = "--native-camera-capture";
const MAX_LIST_BYTES: usize = 1024 * 1024;
const MAX_DEVICES: usize = 128;
const MAX_ID_BYTES: usize = 4096;
const MAX_WIDTH: u32 = 1920;
const MAX_HEIGHT: u32 = 1088;
const MAGIC: &[u8; 8] = b"ZCAMRGB1";
const HEADER_LEN: usize = 20;
const CAMERA_STOPPED: &str =
    "Camera đã dừng hoặc không khả dụng. Kiểm tra kết nối, quyền camera và định dạng được hỗ trợ.";

/// A native backend identifier and its human-readable camera name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CameraDevice {
    /// Backend-qualified device key; display names are never used as native indices.
    pub id: String,
    /// Camera name reported by the operating system.
    pub label: String,
}

/// An owned, tightly packed RGB888 camera frame.
#[derive(Debug)]
pub struct RawFrame {
    /// Image width in pixels, bounded to 1920.
    pub width: u32,
    /// Image height in pixels, bounded to 1088.
    pub height: u32,
    /// Row-major RGB bytes, exactly `width * height * 3` bytes.
    pub rgb: Vec<u8>,
}

/// Resolve an exact native key or an unambiguous legacy display name.
///
/// # Errors
/// Returns an error for unavailable devices, ambiguous labels or an empty device list.
pub fn resolve_device(devices: &[CameraDevice], selection: &str) -> Result<String> {
    validate_devices(devices)?;
    if selection.is_empty() {
        return devices
            .first()
            .map(|device| device.id.clone())
            .ok_or_else(|| anyhow!("Không tìm thấy camera."));
    }
    if let Some(device) = devices.iter().find(|device| device.id == selection) {
        return Ok(device.id.clone());
    }
    let mut matching = devices.iter().filter(|device| device.label == selection);
    let first = matching
        .next()
        .ok_or_else(|| anyhow!("Camera đã chọn không còn khả dụng."))?;
    if matching.next().is_some() {
        bail!("Có nhiều camera cùng tên. Hãy chọn lại camera bằng mã thiết bị.");
    }
    Ok(first.id.clone())
}

/// Discover native devices in a helper without opening their capture streams.
///
/// # Errors
/// Returns an error after five seconds, on invalid/oversized output or backend failure.
/// Call this from a worker; never from the UI thread (INV-3).
pub fn list_devices() -> Result<Vec<CameraDevice>> {
    let mut helper = HelperChild::spawn(&[LIST_FLAG])?;
    let stdout = helper
        .child
        .stdout
        .take()
        .context("Không đọc được danh sách camera.")?;
    let (tx, rx) = mpsc::sync_channel(1);
    let reader = thread::Builder::new()
        .name("native-camera-list".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take((MAX_LIST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            // The owner may already have timed out and closed the receiver.
            let _ = tx.send(result);
        })
        .context("Không tạo được luồng đọc camera.")?;
    let output = rx.recv_timeout(Duration::from_secs(5));
    let cleanup = helper.stop();
    let joined = reader.join();
    cleanup?;
    joined.map_err(|_| anyhow!("Luồng đọc danh sách camera đã dừng."))?;
    let output = output
        .context("Camera không trả lời trong 5 giây.")?
        .context("Không đọc được danh sách camera.")?;
    parse_devices(&output)
}

/// Execute a private native helper command before loading application credentials.
///
/// # Errors
/// Returns an error for invalid helper arguments or unavailable native capture.
/// `args` includes the executable name; `false` means normal application startup.
pub fn run_helper_if_requested(args: &[String]) -> Result<bool> {
    match args.get(1).map(String::as_str) {
        Some(LIST_FLAG) => {
            if args.len() != 2 {
                bail!("Tham số liệt kê camera không hợp lệ.");
            }
            let devices = native_devices()?;
            let bytes = serde_json::to_vec(&devices)?;
            if bytes.len() > MAX_LIST_BYTES {
                bail!("Danh sách camera vượt giới hạn.");
            }
            std::io::stdout().lock().write_all(&bytes)?;
            Ok(true)
        }
        Some(CAPTURE_FLAG) => {
            if args.len() != 3 {
                bail!("Tham số mở camera không hợp lệ.");
            }
            capture_native(&args[2])?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[derive(Default)]
struct FrameSlot {
    latest: Option<RawFrame>,
    error: Option<String>,
}

type Mailbox = Arc<(Mutex<FrameSlot>, Condvar)>;

/// Owns one capture helper and its bounded, coalescing pipe reader.
pub struct CameraProcess {
    helper: HelperChild,
    reader: Option<JoinHandle<()>>,
    mailbox: Mailbox,
    stopped: bool,
}

impl CameraProcess {
    /// Start capture for an exact key returned by native discovery.
    ///
    /// # Errors
    /// Returns an error if the key is malformed or the helper cannot be started.
    /// Device-open failures are reported by `poll_frame` without blocking the caller.
    pub fn spawn(device_id: &str) -> Result<Self> {
        parse_index(device_id)?;
        let mut helper = HelperChild::spawn(&[CAPTURE_FLAG, device_id])?;
        let stdout = helper
            .child
            .stdout
            .take()
            .context("Không đọc được hình ảnh camera.")?;
        let mailbox: Mailbox = Arc::default();
        let producer = Arc::clone(&mailbox);
        let reader = thread::Builder::new()
            .name("native-camera-frames".into())
            .spawn(move || read_frames(stdout, producer))
            .context("Không tạo được luồng đọc camera.")?;
        Ok(Self {
            helper,
            reader: Some(reader),
            mailbox,
            stopped: false,
        })
    }

    /// Take the newest available frame, waiting at most `timeout` for pipe input.
    ///
    /// # Errors
    /// Returns an error and stops/reaps the helper on malformed input or disconnection.
    /// This blocking method belongs on the media worker, not the UI thread (INV-3).
    pub fn poll_frame(&mut self, timeout: Duration) -> Result<Option<RawFrame>> {
        if self.stopped {
            bail!("Camera đã dừng.");
        }
        let (lock, ready) = &*self.mailbox;
        let state = lock.lock().unwrap_or_else(|error| error.into_inner());
        let (mut state, _) = ready
            .wait_timeout_while(state, timeout, |state| {
                state.latest.is_none() && state.error.is_none()
            })
            .unwrap_or_else(|error| error.into_inner());
        if let Some(frame) = state.latest.take() {
            return Ok(Some(frame));
        }
        let error = state.error.take();
        drop(state);
        if let Some(error) = error {
            self.stop()?;
            bail!(error);
        }
        Ok(None)
    }

    /// Kill and reap the helper, then join its pipe reader; repeated calls are safe.
    ///
    /// # Errors
    /// Returns an error if the operating system cannot terminate/reap the helper,
    /// or the pipe reader panicked. Driver reads run only in the killed process.
    pub fn stop(&mut self) -> Result<()> {
        self.stopped = true;
        self.helper.stop()?;
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| anyhow!("Luồng đọc camera đã dừng bất thường."))?;
        }
        let mut slot = self
            .mailbox
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        slot.latest = None;
        Ok(())
    }
}

impl Drop for CameraProcess {
    fn drop(&mut self) {
        // Cleanup cannot report errors during unwinding; stop remains available explicitly.
        let _ = self.stop();
    }
}

struct HelperChild {
    child: Child,
    reaped: bool,
}

impl HelperChild {
    /// Start the current executable in helper mode with a dedicated stdout
    /// pipe and an environment limited to OS and temporary-directory paths.
    ///
    /// # Errors
    /// Returns an error if the executable path cannot be resolved or the child
    /// cannot be launched.
    fn spawn(args: &[&str]) -> Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // No backend diagnostics may corrupt RGB stdout or accumulate without bounds.
            .stderr(Stdio::null());
        for key in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW avoids a console flash.
        }
        Ok(Self {
            child: command
                .spawn()
                .context("Không khởi chạy được camera gốc.")?,
            reaped: false,
        })
    }

    /// Terminate the helper if it is still running and reap it exactly once.
    ///
    /// # Errors
    /// Returns an error if the child's status is unavailable, termination
    /// fails while the child is still running, or reaping fails.
    fn stop(&mut self) -> Result<()> {
        if self.reaped {
            return Ok(());
        }
        if self.child.try_wait()?.is_none() {
            // The owned helper spawns no descendants; killing it closes the sole pipe writer.
            if let Err(error) = self.child.kill() {
                if self.child.try_wait()?.is_none() {
                    return Err(error).context("Không dừng được camera gốc.");
                }
            }
        }
        self.child
            .wait()
            .context("Không thu hồi được camera gốc.")?;
        self.reaped = true;
        Ok(())
    }
}

impl Drop for HelperChild {
    fn drop(&mut self) {
        // Every early return must still release the native driver process.
        let _ = self.stop();
    }
}

/// Drain the helper pipe into a single replaceable frame slot. A terminal
/// read error wakes the consumer with the failure reason.
fn read_frames(mut reader: impl Read, mailbox: Mailbox) {
    loop {
        let result = read_frame(&mut reader);
        // A single replaceable slot prevents a slow encoder from accumulating raw frames.
        // This short lock protects metadata/ownership only; pipe I/O occurs before it.
        let mut slot = mailbox.0.lock().unwrap_or_else(|error| error.into_inner());
        match result {
            Ok(frame) => slot.latest = Some(frame),
            Err(error) => {
                slot.error = Some(error.to_string());
                mailbox.1.notify_one();
                break;
            }
        }
        mailbox.1.notify_one();
    }
}

/// Return the byte length of a packed RGB frame within the capture bounds.
///
/// # Errors
/// Returns an error for empty dimensions or dimensions above 1920 by 1088.
fn rgb_len(width: u32, height: u32) -> Result<usize> {
    if width == 0 || height == 0 || width > MAX_WIDTH || height > MAX_HEIGHT {
        bail!("Kích thước hình ảnh camera vượt giới hạn 1920×1088.");
    }
    Ok(width as usize * height as usize * 3)
}

/// Read one helper frame, validating its version, dimensions, and declared
/// length before allocating the pixel buffer.
///
/// # Errors
/// Returns an error for invalid headers, unsupported dimensions, or an
/// incomplete read of the header or pixels.
fn read_frame(reader: &mut impl Read) -> Result<RawFrame> {
    let mut header = [0_u8; HEADER_LEN];
    reader.read_exact(&mut header).context(CAMERA_STOPPED)?;
    if &header[..8] != MAGIC {
        bail!("Dữ liệu camera không đúng phiên bản.");
    }
    let width = u32::from_le_bytes(header[8..12].try_into()?);
    let height = u32::from_le_bytes(header[12..16].try_into()?);
    let declared_len = u32::from_le_bytes(header[16..20].try_into()?) as usize;
    let expected_len = rgb_len(width, height)?;
    if declared_len != expected_len {
        bail!("Độ dài hình ảnh camera không hợp lệ.");
    }
    let mut rgb = vec![0; expected_len];
    reader.read_exact(&mut rgb).context(CAMERA_STOPPED)?;
    Ok(RawFrame { width, height, rgb })
}

/// Write and flush a versioned frame so the parent can consume it immediately.
///
/// # Errors
/// Returns an error for invalid dimensions, a mismatched RGB length, or an
/// output failure.
fn write_frame(writer: &mut impl Write, frame: &RawFrame) -> Result<()> {
    let len = rgb_len(frame.width, frame.height)?;
    if frame.rgb.len() != len {
        bail!("Độ dài hình ảnh camera không hợp lệ.");
    }
    let mut header = [0; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&frame.width.to_le_bytes());
    header[12..16].copy_from_slice(&frame.height.to_le_bytes());
    header[16..20].copy_from_slice(&(len as u32).to_le_bytes());
    writer.write_all(&header)?;
    writer.write_all(&frame.rgb)?;
    writer.flush()?;
    Ok(())
}

/// Encode the backend index for storage with distinct prefixes for numeric
/// and string identifiers.
fn index_key(index: &CameraIndex) -> String {
    match index {
        CameraIndex::Index(index) => format!("nokhwa:index:{index}"),
        CameraIndex::String(index) => format!("nokhwa:string:{index}"),
    }
}

/// Recover the backend index from a stored camera identifier.
///
/// # Errors
/// Returns an error for unknown prefixes, invalid numeric values, empty
/// string identifiers, embedded NULs, or identifiers that exceed the limit.
fn parse_index(key: &str) -> Result<CameraIndex> {
    if key.len() > MAX_ID_BYTES || key.contains('\0') {
        bail!("Mã camera không hợp lệ.");
    }
    if let Some(index) = key.strip_prefix("nokhwa:index:") {
        return Ok(CameraIndex::Index(
            index.parse().context("Mã camera không hợp lệ.")?,
        ));
    }
    if let Some(index) = key
        .strip_prefix("nokhwa:string:")
        .filter(|id| !id.is_empty())
    {
        return Ok(CameraIndex::String(index.to_owned()));
    }
    bail!("Mã camera không hợp lệ.")
}

/// Validate that each helper-discovered camera has a unique, usable key
/// within the discovery output limits.
///
/// # Errors
/// Returns an error for too many devices, invalid or duplicate identifiers,
/// or labels that exceed the byte limit.
fn validate_devices(devices: &[CameraDevice]) -> Result<()> {
    if devices.len() > MAX_DEVICES {
        bail!("Danh sách camera vượt giới hạn 128 thiết bị.");
    }
    for (position, device) in devices.iter().enumerate() {
        parse_index(&device.id)?;
        if device.label.len() > MAX_ID_BYTES
            || devices[..position]
                .iter()
                .any(|other| other.id == device.id)
        {
            bail!("Danh sách camera không hợp lệ.");
        }
    }
    Ok(())
}

/// Decode the helper's JSON output after bounding the input size.
///
/// # Errors
/// Returns an error for oversized or malformed JSON or an invalid device list.
fn parse_devices(bytes: &[u8]) -> Result<Vec<CameraDevice>> {
    if bytes.len() > MAX_LIST_BYTES {
        bail!("Danh sách camera vượt giới hạn 1 MiB.");
    }
    let devices: Vec<CameraDevice> = serde_json::from_slice(bytes).context(CAMERA_STOPPED)?;
    validate_devices(&devices)?;
    Ok(devices)
}

/// Query native camera devices without triggering capture permission.
///
/// # Errors
/// Returns an error if enumeration fails or returns an invalid device list.
fn native_devices() -> Result<Vec<CameraDevice>> {
    // Enumeration does not call initialization: macOS permission is requested only on capture.
    let devices = nokhwa::query(nokhwa::utils::ApiBackend::Auto)
        .context("Không liệt kê được camera gốc trên hệ điều hành này.")?
        .into_iter()
        .map(|info| CameraDevice {
            id: index_key(info.index()),
            label: info.human_name(),
        })
        .collect::<Vec<_>>();
    validate_devices(&devices)?;
    Ok(devices)
}

/// Choose a decodable mode nearest 640 by 480, breaking resolution ties by
/// proximity to 15 frames per second.
///
/// # Errors
/// Returns an error if there is no bounded mode with valid chroma geometry
/// and a positive frame rate.
fn nearest_format(formats: impl IntoIterator<Item = CameraFormat>) -> Result<CameraFormat> {
    formats
        .into_iter()
        .filter(|format| {
            let width = format.resolution().width();
            let height = format.resolution().height();
            let valid_chroma = match format.format() {
                FrameFormat::YUYV => width % 2 == 0,
                FrameFormat::NV12 => width % 2 == 0 && height % 2 == 0,
                _ => true,
            };
            RgbFormat::FORMATS.contains(&format.format())
                && valid_chroma
                && rgb_len(width, height).is_ok()
                && format.frame_rate() > 0
        })
        .min_by_key(|format| {
            let resolution = format.resolution();
            let distance = u64::from(resolution.width().abs_diff(640)).pow(2)
                + u64::from(resolution.height().abs_diff(480)).pow(2);
            (distance, format.frame_rate().abs_diff(15))
        })
        .ok_or_else(|| anyhow!("Camera không hỗ trợ định dạng RGB/YUYV/NV12/MJPEG trong giới hạn."))
}

/// Convert a camera buffer to packed RGB with allocation limits derived from
/// the reported dimensions.
///
/// # Errors
/// Returns an error for invalid dimensions, unexpected data lengths,
/// unsupported pixel formats, or conversion failures.
fn decode_rgb(buffer: &nokhwa::Buffer) -> Result<RawFrame> {
    let resolution = buffer.resolution();
    let width = resolution.width();
    let height = resolution.height();
    let expected = rgb_len(width, height)?;
    let pixels = expected / 3;
    let data = buffer.buffer();
    if data.len() > MAX_WIDTH as usize * MAX_HEIGHT as usize * 4 {
        bail!("Dữ liệu camera vượt giới hạn.");
    }
    let rgb = if buffer.source_frame_format() == FrameFormat::MJPEG {
        // JPEG carries its own dimensions; enforce those before allocating decoded pixels.
        let mut reader =
            image::ImageReader::with_format(std::io::Cursor::new(data), image::ImageFormat::Jpeg);
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(width);
        limits.max_image_height = Some(height);
        limits.max_alloc = Some(expected as u64 * 4);
        reader.limits(limits);
        let image = reader.decode().context(CAMERA_STOPPED)?;
        if image.width() != width || image.height() != height {
            bail!("Kích thước JPEG của camera không hợp lệ.");
        }
        image.into_rgb8().into_raw()
    } else {
        let input_len = match buffer.source_frame_format() {
            FrameFormat::YUYV if width % 2 == 0 => pixels * 2,
            FrameFormat::NV12 if width % 2 == 0 && height % 2 == 0 => pixels * 3 / 2,
            FrameFormat::RAWRGB | FrameFormat::RAWBGR => expected,
            FrameFormat::GRAY => pixels,
            _ => bail!("Định dạng hình ảnh camera không hợp lệ."),
        };
        if data.len() != input_len {
            bail!("Độ dài dữ liệu camera không hợp lệ.");
        }
        let mut rgb = vec![0; expected];
        if buffer.source_frame_format() == FrameFormat::RAWBGR {
            // nokhwa-core 0.1.9 incorrectly requires even dimensions for packed BGR888.
            // BGR has no chroma subsampling: every validated three-byte pixel stands alone.
            for (input, output) in data.chunks_exact(3).zip(rgb.chunks_exact_mut(3)) {
                output.copy_from_slice(&[input[2], input[1], input[0]]);
            }
        } else {
            buffer
                .decode_image_to_buffer::<RgbFormat>(&mut rgb)
                .context(CAMERA_STOPPED)?;
        }
        rgb
    };
    if rgb.len() != expected {
        bail!("Độ dài hình ảnh camera không hợp lệ.");
    }
    Ok(RawFrame { width, height, rgb })
}

/// Run native capture in the helper process and stream packed RGB frames to
/// stdout at a target cadence of 15 frames per second.
///
/// # Errors
/// Returns an error if the camera selection, permission, native capture,
/// conversion, or pipe write fails.
fn capture_native(device_id: &str) -> Result<()> {
    let index = parse_index(device_id)?;
    #[cfg(target_os = "macos")]
    {
        let (tx, rx) = mpsc::sync_channel(1);
        nokhwa::nokhwa_initialize(move |granted| {
            // The helper can be killed while a system permission dialog is still open.
            let _ = tx.send(granted);
        });
        if !rx.recv_timeout(Duration::from_secs(120)).unwrap_or(false) {
            bail!("Chưa được cấp quyền truy cập camera.");
        }
    }
    if !native_devices()?
        .iter()
        .any(|device| device.id == device_id)
    {
        bail!("Camera đã chọn không còn khả dụng.");
    }
    let initial = RequestedFormat::new::<RgbFormat>(RequestedFormatType::None);
    let mut camera = Camera::new(index, initial).context(CAMERA_STOPPED)?;
    let format = nearest_format(camera.compatible_camera_formats().context(CAMERA_STOPPED)?)?;
    camera
        .set_camera_requset(RequestedFormat::new::<RgbFormat>(
            RequestedFormatType::Exact(format),
        ))
        .context(CAMERA_STOPPED)?;
    camera.open_stream().context(CAMERA_STOPPED)?;
    let mut stdout = std::io::stdout().lock();
    let cadence = Duration::from_millis(1000 / 15);
    loop {
        let started = Instant::now();
        let buffer = camera.frame().context(CAMERA_STOPPED)?;
        write_frame(&mut stdout, &decode_rgb(&buffer)?)?;
        if let Some(delay) = cadence.checked_sub(started.elapsed()) {
            thread::sleep(delay);
        }
    }
}
