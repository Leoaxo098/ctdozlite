#![allow(dead_code)]
include!("../src/lib.rs");

mod tests {
    use super::*;
    use nokhwa::utils::Resolution;

    fn frame_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &RawFrame {
                width: 2,
                height: 1,
                rgb: vec![1, 2, 3, 4, 5, 6],
            },
        )
        .unwrap();
        bytes
    }

    #[test]
    fn reads_rgb_frame_when_header_is_valid() {
        let frame = read_frame(&mut frame_bytes().as_slice()).unwrap();
        assert_eq!((frame.width, frame.height), (2, 1));
        assert_eq!(frame.rgb, [1, 2, 3, 4, 5, 6]);
    }

    /// Exercise both truncated reads and corrupt version or size fields.
    #[test]
    fn rejects_frame_when_header_or_payload_is_invalid() {
        for len in [0, 7, 19, 20, 25] {
            assert!(read_frame(&mut &frame_bytes()[..len]).is_err());
        }
        for (offset, value) in [(0, 0), (7, b'2'), (8, 0), (16, 255)] {
            let mut bytes = frame_bytes();
            bytes[offset] = value;
            assert!(read_frame(&mut bytes.as_slice()).is_err());
        }
    }

    #[test]
    fn rejects_oversized_dimensions_before_reading_payload() {
        let mut bytes = frame_bytes();
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_frame(&mut bytes.as_slice()).is_err());
        assert!(rgb_len(MAX_WIDTH, MAX_HEIGHT).is_ok());
        assert!(rgb_len(MAX_WIDTH + 1, 1).is_err());
        assert!(rgb_len(1, MAX_HEIGHT + 1).is_err());
    }

    #[test]
    fn coalesces_frames_when_consumer_is_slow() {
        let mut bytes = frame_bytes();
        let mut second = frame_bytes();
        *second.last_mut().unwrap() = 99;
        bytes.extend(second);
        let mailbox: Mailbox = Arc::default();
        read_frames(bytes.as_slice(), Arc::clone(&mailbox));
        let mut slot = mailbox.0.lock().unwrap();
        assert_eq!(slot.latest.take().unwrap().rgb.last(), Some(&99));
        assert!(slot.error.is_some());
    }

    #[test]
    fn resolves_exact_ids_when_names_are_duplicated() {
        let devices = vec![
            CameraDevice {
                id: "nokhwa:index:0".into(),
                label: "USB Camera".into(),
            },
            CameraDevice {
                id: "nokhwa:index:1".into(),
                label: "USB Camera".into(),
            },
        ];
        assert_eq!(
            resolve_device(&devices, "nokhwa:index:1").unwrap(),
            "nokhwa:index:1"
        );
        assert_eq!(resolve_device(&devices, "").unwrap(), "nokhwa:index:0");
        assert!(resolve_device(&devices, "USB Camera").is_err());
        assert!(resolve_device(&devices, "missing").is_err());
        assert!(resolve_device(&[], "").is_err());
    }

    #[test]
    fn preserves_string_native_indices_without_shell_parsing() {
        let index = CameraIndex::String("/dev/video2; $camera with spaces".into());
        assert_eq!(parse_index(&index_key(&index)).unwrap(), index);
        assert!(parse_index("camera-name").is_err());
        assert!(parse_index("nokhwa:index:-1").is_err());
        assert!(parse_index("nokhwa:string:\0").is_err());
    }

    #[test]
    fn bounds_device_json_and_count() {
        assert!(parse_devices(&vec![b' '; MAX_LIST_BYTES + 1]).is_err());
        let devices = (0..=MAX_DEVICES)
            .map(|index| CameraDevice {
                id: format!("nokhwa:index:{index}"),
                label: "Camera".into(),
            })
            .collect::<Vec<_>>();
        assert!(parse_devices(&serde_json::to_vec(&devices).unwrap()).is_err());
        let duplicate = vec![devices[0].clone(), devices[0].clone()];
        assert!(parse_devices(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    }

    #[test]
    fn negotiates_nearest_supported_native_format() {
        let formats = [
            CameraFormat::new_from(4000, 3000, FrameFormat::MJPEG, 30),
            CameraFormat::new_from(1280, 720, FrameFormat::NV12, 30),
            CameraFormat::new_from(640, 480, FrameFormat::YUYV, 30),
            CameraFormat::new_from(640, 480, FrameFormat::MJPEG, 15),
        ];
        assert_eq!(nearest_format(formats).unwrap(), formats[3]);
        assert!(nearest_format([formats[0]]).is_err());
    }

    #[test]
    fn selects_usable_color_mode_when_gray_has_closer_frame_rate() {
        let gray = CameraFormat::new_from(640, 480, FrameFormat::GRAY, 15);
        let yuyv = CameraFormat::new_from(640, 480, FrameFormat::YUYV, 30);
        assert_eq!(nearest_format([gray, yuyv]).unwrap(), yuyv);
        assert!(nearest_format([gray]).is_err());
    }

    #[test]
    fn excludes_subsampled_modes_when_dimensions_cannot_be_decoded() {
        let odd_yuyv = CameraFormat::new_from(639, 480, FrameFormat::YUYV, 15);
        let odd_nv12_width = CameraFormat::new_from(639, 480, FrameFormat::NV12, 15);
        let odd_nv12_height = CameraFormat::new_from(640, 479, FrameFormat::NV12, 15);
        let bgr = CameraFormat::new_from(639, 479, FrameFormat::RAWBGR, 30);
        assert!(nearest_format([odd_yuyv]).is_err());
        assert!(nearest_format([odd_nv12_width]).is_err());
        assert!(nearest_format([odd_nv12_height]).is_err());
        assert_eq!(
            nearest_format([odd_yuyv, odd_nv12_height, bgr]).unwrap(),
            bgr
        );
        let odd_height_yuyv = CameraFormat::new_from(640, 479, FrameFormat::YUYV, 15);
        assert_eq!(nearest_format([odd_height_yuyv]).unwrap(), odd_height_yuyv);
    }

    #[test]
    fn decodes_native_rgb_yuyv_and_nv12_without_external_tools() {
        let raw = nokhwa::Buffer::new(
            Resolution::new(2, 1),
            &[1, 2, 3, 4, 5, 6],
            FrameFormat::RAWRGB,
        );
        assert_eq!(decode_rgb(&raw).unwrap().rgb, [1, 2, 3, 4, 5, 6]);
        let bgr = nokhwa::Buffer::new(
            Resolution::new(2, 1),
            &[3, 2, 1, 6, 5, 4],
            FrameFormat::RAWBGR,
        );
        assert_eq!(decode_rgb(&bgr).unwrap().rgb, [1, 2, 3, 4, 5, 6]);
        let yuyv = nokhwa::Buffer::new(
            Resolution::new(2, 1),
            &[16, 128, 16, 128],
            FrameFormat::YUYV,
        );
        assert_eq!(decode_rgb(&yuyv).unwrap().rgb.len(), 6);
        let nv12 = nokhwa::Buffer::new(
            Resolution::new(2, 2),
            &[16, 16, 16, 16, 128, 128],
            FrameFormat::NV12,
        );
        assert_eq!(decode_rgb(&nv12).unwrap().rgb.len(), 12);
        let truncated = nokhwa::Buffer::new(Resolution::new(2, 2), &[16], FrameFormat::NV12);
        assert!(decode_rgb(&truncated).is_err());
    }

    #[test]
    fn decodes_jpeg_only_when_embedded_dimensions_match_native_frame() {
        let image = image::RgbImage::from_raw(2, 2, vec![128; 12]).unwrap();
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .encode_image(&image)
            .unwrap();
        let matching = nokhwa::Buffer::new(Resolution::new(2, 2), &jpeg, FrameFormat::MJPEG);
        assert_eq!(decode_rgb(&matching).unwrap().rgb.len(), 12);
        let mismatched = nokhwa::Buffer::new(Resolution::new(1, 1), &jpeg, FrameFormat::MJPEG);
        assert!(decode_rgb(&mismatched).is_err());
    }

    #[test]
    fn leaves_normal_startup_untouched() {
        assert!(!run_helper_if_requested(&["app".into(), "--gui".into()]).unwrap());
        assert!(
            run_helper_if_requested(&["app".into(), LIST_FLAG.into(), "extra".into()]).is_err()
        );
        assert!(run_helper_if_requested(&["app".into(), CAPTURE_FLAG.into()]).is_err());
    }

    /// Verify that stopping a blocked helper closes its stdout pipe and lets
    /// the reader thread finish within the shutdown budget.
    #[test]
    fn stops_and_reaps_blocked_helper_within_two_seconds() {
        const CHILD_ENV: &str = "CTDO_CAMERA_LIFECYCLE_TEST_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            // The test harness is a controlled helper with no driver or credential access.
            thread::sleep(Duration::from_secs(60));
            return;
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "tests::stops_and_reaps_blocked_helper_within_two_seconds",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let mut output = Vec::new();
            // A blocked owned pipe read must reach EOF when its sole writer is killed.
            stdout.take(1024).read_to_end(&mut output).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut process = CameraProcess {
            helper: HelperChild {
                child,
                reaped: false,
            },
            reader: Some(reader),
            mailbox: Arc::default(),
            stopped: false,
        };
        let started = Instant::now();
        process.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(process.helper.reaped);
        assert!(process.reader.is_none());
        process.stop().unwrap();
    }
}
