//! Deterministic property-based fuzz tests for core UI layout, album grouping,
//! settings sanitization, and QR protocol parsers.

use crate::account_manager::{
    has_any_saved_credentials_in, wipe_all_saved_session_credentials_in,
};
use crate::app_lock::{
    mask_notification_content, mask_toast_text, pbkdf2_hmac_sha256, popup_allows_interaction,
    validate_passcode, AppLockConfig, PasscodeMode, VerifyOutcome, APP_LOCK_FILE,
    CURRENT_VERSION, LOCKOUT_SECS, MAX_FAILED_ATTEMPTS, MIN_ITERATIONS, SALT_LEN,
};
use crate::chat::{
    apply_recall_merge, build_native_video_forward_params, build_recall_payload,
    build_set_mute_payload, probe_mp4_metadata, ChatMessage, MediaGroupLayout, MUTE_ACTION_SET,
    MUTE_ACTION_UNSET,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use crate::gui::attachments::is_video_path;
use crate::gui::lucide;
use crate::gui::messages::{album_run_lengths, compute_video_thumb_size};
use crate::gui::workspace::{
    compute_chat_header_actions_width_exact, compute_thread_row_reserved_right, format_sidebar_time,
};
use crate::gui::{AppSettings, IncomingPopupState};
use crate::qr::parse_rate_limit_wait_secs;

struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_f32_adversarial(&mut self) -> f32 {
        match self.next_u64() % 16 {
            0 => 0.0,
            1 => -0.0,
            2 => -150.0,
            3 => 1.0,
            4 => 119.9,
            5 => 140.0,
            6 => 10_000.0,
            7 => f32::NAN,
            8 => f32::INFINITY,
            9 => f32::NEG_INFINITY,
            _ => ((self.next_u64() % 2000) as f32) * 0.5 - 50.0,
        }
    }

    fn next_usize_adversarial(&mut self) -> usize {
        match self.next_u64() % 10 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 320,
            4 => 1920,
            5 => u32::MAX as usize,
            _ => (self.next_u64() % 4096) as usize,
        }
    }
}

#[test]
fn prop_video_thumb_size_never_panics_and_fits_bounds() {
    let mut rng = Xorshift64::new(0xC7D0_0001);
    for _ in 0..2000 {
        let tw = rng.next_usize_adversarial();
        let th = rng.next_usize_adversarial();
        let max_w = rng.next_f32_adversarial();
        let (w, h) = compute_video_thumb_size(tw, th, max_w);
        assert!(w.is_finite() && w >= 0.0, "invalid w={w} for ({tw},{th},{max_w})");
        assert!(h.is_finite() && h >= 0.0, "invalid h={h} for ({tw},{th},{max_w})");
    }
}

#[test]
fn prop_header_actions_width_monotonic_and_finite() {
    for is_group in [false, true] {
        for is_narrow in [false, true] {
            let no_calls = compute_chat_header_actions_width_exact(is_group, is_narrow, false);
            let with_calls = compute_chat_header_actions_width_exact(is_group, is_narrow, true);
            assert!(no_calls.is_finite() && no_calls > 0.0);
            assert!(with_calls.is_finite() && with_calls > no_calls);
        }
        let narrow = compute_chat_header_actions_width_exact(is_group, true, true);
        let wide = compute_chat_header_actions_width_exact(is_group, false, true);
        assert!(wide > narrow);
    }
}

#[test]
fn prop_album_run_lengths_partitions_all_messages() {
    let mut rng = Xorshift64::new(0xC7D0_0002);
    let senders = ["Hoang", "Đỗ Thành", "Lan", "Minh"];
    let group_ids = ["grp_a", "grp_b", "grp_c"];

    for _ in 0..500 {
        let len = (rng.next_u64() % 28) as usize;
        let mut msgs = Vec::with_capacity(len);
        let mut ts: i64 = 1_795_000_000_000;

        for idx in 0..len {
            let is_photo = (rng.next_u64() % 5) != 0;
            let recalled = (rng.next_u64() % 12) == 0;
            let is_outgoing = (rng.next_u64() % 2) == 0;
            let sender = senders[(rng.next_u64() as usize) % senders.len()].to_string();
            ts += match rng.next_u64() % 4 {
                0 => 1_000,
                1 => 8_000,
                2 => 30_000,
                _ => 0,
            };
            let media_group = match rng.next_u64() % 4 {
                0 => Some(MediaGroupLayout::new(
                    group_ids[(rng.next_u64() as usize) % group_ids.len()],
                    idx as u32,
                    4,
                )),
                _ => None,
            };

            msgs.push(ChatMessage {
                id: format!("m_{idx}"),
                sender,
                text: if recalled {
                    "[Tin nhắn đã thu hồi]".to_string()
                } else if is_photo {
                    "[Hình ảnh]".to_string()
                } else {
                    "tin nhắn thường".to_string()
                },
                is_outgoing,
                ts,
                link_src: is_photo.then(|| "Hình ảnh Zalo".to_string()),
                link_url: is_photo.then(|| format!("https://b-f10-zpg-r.zdn.vn/photo_{idx}.jpg")),
                media_group,
                ..Default::default()
            });
        }

        let refs: Vec<&ChatMessage> = msgs.iter().collect();
        let runs = album_run_lengths(&refs);
        assert_eq!(runs.len(), msgs.len());
        assert_eq!(runs.iter().sum::<usize>(), msgs.len());

        let mut i = 0;
        while i < runs.len() {
            let r = runs[i];
            assert!(r >= 1);
            for slot in &runs[i + 1..i + r] {
                assert_eq!(*slot, 0);
            }
            if r >= 2 && msgs[i].media_group.is_none() {
                assert!(r <= 9, "burst album without media_group exceeded cap: {r}");
            }
            i += r;
        }
    }

    let drift_outgoing = vec![
        ChatMessage {
            id: "d1".into(),
            sender: "Hoang".into(),
            text: "[Hình ảnh]".into(),
            is_outgoing: true,
            ts: 1000,
            link_src: Some("Hình ảnh Zalo".into()),
            media_group: Some(MediaGroupLayout::new("shared_123", 0, 2)),
            ..Default::default()
        },
        ChatMessage {
            id: "d2".into(),
            sender: "Đỗ Thành".into(),
            text: "[Hình ảnh]".into(),
            is_outgoing: true,
            ts: 1001,
            link_src: Some("Hình ảnh Zalo".into()),
            media_group: Some(MediaGroupLayout::new("shared_123", 1, 2)),
            ..Default::default()
        },
    ];
    let drift_refs: Vec<&ChatMessage> = drift_outgoing.iter().collect();
    assert_eq!(album_run_lengths(&drift_refs), vec![2, 0]);
}

#[test]
fn prop_app_settings_clamp_bounds_always_valid() {
    let mut rng = Xorshift64::new(0xC7D0_0003);
    for _ in 0..500 {
        let mut s = AppSettings::default();
        s.font_scale = rng.next_f32_adversarial();
        s.animation_speed = rng.next_f32_adversarial();
        s.scroll_speed = rng.next_f32_adversarial();

        let fs = s.normalized_font_scale();
        let an = s.normalized_animation_speed();
        let sc = s.normalized_scroll_speed();

        assert!(fs.is_finite() && (0.5..=3.0).contains(&fs), "font_scale={fs}");
        assert!(an.is_finite() && (0.5..=2.0).contains(&an), "animation_speed={an}");
        assert!(sc.is_finite() && (0.5..=4.0).contains(&sc), "scroll_speed={sc}");
    }
}

#[test]
fn prop_qr_rate_limit_parser_never_panics() {
    let mut rng = Xorshift64::new(0xC7D0_0004);
    let fragments = [
        "",
        "(",
        "(chờ ",
        "(chờ 0s)",
        "(chờ -5s)",
        "(chờ 99999999999999999999999999s)",
        "(chờ 42s)",
        "s)",
        "😀(chờ 15s)🔥",
        "18012",
    ];
    for _ in 0..500 {
        let a = fragments[(rng.next_u64() as usize) % fragments.len()];
        let b = fragments[(rng.next_u64() as usize) % fragments.len()];
        let sample = format!("{a}{b}");
        let parsed = parse_rate_limit_wait_secs(&sample);
        if let Some(secs) = parsed {
            assert!(secs > 0);
        }
    }
}

#[test]
fn test_set_mute_payload_uses_zalo_action_1_and_3() {
    assert_eq!(MUTE_ACTION_SET, 1);
    assert_eq!(MUTE_ACTION_UNSET, 3);

    let muted_dm = build_set_mute_payload("7602591761395115371", false, 3600, true, 1_795_365_460, "pc-imei");
    assert_eq!(muted_dm["toid"], "7602591761395115371");
    assert_eq!(muted_dm["action"], 1);
    assert_eq!(muted_dm["duration"], 3600);
    assert_eq!(muted_dm["muteType"], 1);

    let unmuted_dm = build_set_mute_payload("7602591761395115371", false, 0, false, 1_795_365_600, "pc-imei");
    assert_eq!(unmuted_dm["toid"], "7602591761395115371");
    assert_eq!(unmuted_dm["action"], 3);
    assert_ne!(unmuted_dm["action"], 2);
    assert_eq!(unmuted_dm["duration"], -1);
    assert_eq!(unmuted_dm["muteType"], 1);

    let unmuted_grp = build_set_mute_payload("group_3247153953139077370", true, -1, false, 1_795_365_600, "pc-imei");
    assert_eq!(unmuted_grp["toid"], "3247153953139077370");
    assert_eq!(unmuted_grp["action"], 3);
    assert_eq!(unmuted_grp["duration"], -1);
    assert_eq!(unmuted_grp["muteType"], 2);
}

#[test]
fn test_incoming_popup_state_unread_floor_and_draft_reset() {
    let p = IncomingPopupState::new(
        "7602591761395115371".into(),
        "Đtc".into(),
        "U".into(),
        None,
        false,
        0,
    );
    assert_eq!(p.unread_total, 1);
    assert!(p.reply_draft.is_empty());
}

#[test]
fn prop_thread_row_reserved_right_prevents_time_and_icon_overlap() {
    for &tw in &[-5.0_f32, 0.0, 28.0, 42.0, f32::NAN] {
        let base = compute_thread_row_reserved_right(tw, false, false);
        let pinned = compute_thread_row_reserved_right(tw, true, false);
        let muted = compute_thread_row_reserved_right(tw, false, true);
        let both = compute_thread_row_reserved_right(tw, true, true);
        assert!(base.is_finite() && base >= 14.0);
        if tw.is_finite() && tw > 0.0 {
            assert!(base > tw + 9.0);
            assert!(pinned > base);
            assert!(muted > base);
            assert!(both > pinned && both > muted);
        }
    }
}

#[test]
fn test_format_sidebar_time_today_same_year_and_older() {
    use chrono::TimeZone;
    let now_local = chrono::Local
        .with_ymd_and_hms(2026, 11, 22, 14, 30, 0)
        .single()
        .expect("valid local noon timestamp");
    let now_secs = now_local.timestamp();

    assert_eq!(format_sidebar_time(0, now_secs, "fallback"), "fallback");
    assert_eq!(format_sidebar_time(0, now_secs, "14:40:27"), "14:40");
    assert_eq!(format_sidebar_time(0, now_secs, "22/11"), "22/11");

    let today_secs = chrono::Local
        .with_ymd_and_hms(2026, 11, 22, 9, 5, 0)
        .single()
        .expect("valid today timestamp")
        .timestamp();
    assert_eq!(format_sidebar_time(today_secs, now_secs, "fb"), "09:05");
    assert_eq!(
        format_sidebar_time(today_secs * 1000, now_secs, "fb"),
        "09:05"
    );

    let earlier_same_year_secs = chrono::Local
        .with_ymd_and_hms(2026, 11, 15, 7, 10, 0)
        .single()
        .expect("valid same-year timestamp")
        .timestamp();
    assert_eq!(
        format_sidebar_time(earlier_same_year_secs * 1000, now_secs, "fb"),
        "15/11"
    );

    let older_year_secs = chrono::Local
        .with_ymd_and_hms(2025, 10, 18, 20, 0, 0)
        .single()
        .expect("valid older-year timestamp")
        .timestamp();
    assert_eq!(
        format_sidebar_time(older_year_secs * 1000, now_secs, "fb"),
        "18/10/25"
    );
}

#[test]
fn test_probe_mp4_metadata_extracts_duration_and_dimensions() {
    fn mk_box(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + body.len());
        out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(body);
        out
    }
    let mut mvhd_body = vec![0u8; 100];
    mvhd_body[12..16].copy_from_slice(&1000u32.to_be_bytes());
    mvhd_body[16..20].copy_from_slice(&5500u32.to_be_bytes());
    let mut tkhd_body = vec![0u8; 84];
    tkhd_body[76..80].copy_from_slice(&(1920u32 << 16).to_be_bytes());
    tkhd_body[80..84].copy_from_slice(&(1080u32 << 16).to_be_bytes());

    let mut moov_body = mk_box(b"mvhd", &mvhd_body);
    let tkhd_box = mk_box(b"tkhd", &tkhd_body);
    moov_body.extend_from_slice(&mk_box(b"trak", &tkhd_box));
    let mp4 = mk_box(b"moov", &moov_body);

    assert_eq!(probe_mp4_metadata(&mp4), Some((5500, 1920, 1080)));
    assert_eq!(probe_mp4_metadata(&[]), None);
}

#[test]
fn test_build_native_video_forward_params_dm_and_group() {
    let dm = build_native_video_forward_params(
        "7602591761395115371",
        false,
        1_795_375_000,
        "pc-imei",
        "https://f10.zdn.vn/vid.mp4",
        "https://f10.zdn.vn/thumb.jpg",
        5500,
        1920,
        1080,
        12_345,
        "demo video",
    );
    assert_eq!(dm["toId"], "7602591761395115371");
    assert_eq!(dm["msgType"], 5);
    assert_eq!(dm["zsource"], 704);
    let info: serde_json::Value =
        serde_json::from_str(dm["msgInfo"].as_str().expect("msgInfo JSON")).expect("valid msgInfo");
    assert_eq!(info["videoUrl"], "https://f10.zdn.vn/vid.mp4");
    assert_eq!(info["thumbUrl"], "https://f10.zdn.vn/thumb.jpg");
    assert_eq!(info["duration"], 5500);
    assert_eq!(info["width"], 1920);
    assert_eq!(info["height"], 1080);
    assert_eq!(info["fileSize"], 12_345);
    assert_eq!(info["properties"]["type"], 1003);
    assert_eq!(info["title"], "demo video");

    let grp = build_native_video_forward_params(
        "3247153953139077370",
        true,
        1_795_375_001,
        "pc-imei",
        "https://f10.zdn.vn/vid.mp4",
        "",
        0,
        1280,
        720,
        999,
        "",
    );
    assert_eq!(grp["grid"], "3247153953139077370");
    assert_eq!(grp["visibility"], 0);
    assert_eq!(grp["msgType"], 5);
}

#[test]
fn test_is_video_path_extensions() {
    use std::path::Path;
    for ext in ["mp4", "MOV", "mkv", "webm", "avi", "m4v"] {
        assert!(is_video_path(Path::new(&format!("clip.{ext}"))));
    }
    for ext in ["png", "jpg", "pdf", "zip"] {
        assert!(!is_video_path(Path::new(&format!("doc.{ext}"))));
    }
}

#[test]
fn test_build_recall_payload_prefers_client_message_id_over_ts() {
    let mut dm_msg = ChatMessage {
        id: "8518773491790".into(),
        client_message_id: "1795376379001".into(),
        ts: 1_795_376_380_456,
        is_outgoing: true,
        ..Default::default()
    };
    let dm = build_recall_payload("7602591761395115371", false, &dm_msg, 1_795_400_000_000, "pc-imei")
        .expect("valid dm recall payload");
    assert_eq!(dm["msgId"], "8518773491790");
    assert_eq!(dm["toid"], "7602591761395115371");
    assert_eq!(dm["cliMsgIdUndo"], "1795376379001");
    assert_eq!(dm["imei"], "pc-imei");

    dm_msg.client_message_id.clear();
    dm_msg.history_source = Some(serde_json::json!({ "cliMsgId": "1795376379555" }));
    let grp = build_recall_payload("group_3247153953139077370", true, &dm_msg, 1_795_400_000_000, "pc-imei")
        .expect("valid group recall payload");
    assert_eq!(grp["grid"], "3247153953139077370");
    assert_eq!(grp["visibility"], 0);
    assert_eq!(grp["cliMsgIdUndo"], "1795376379555");

    let local_msg = ChatMessage {
        id: "out_12345".into(),
        ..Default::default()
    };
    assert!(build_recall_payload("7602591761395115371", false, &local_msg, 1_795_400_000_000, "pc-imei").is_err());
}

#[test]
fn test_lucide_shield_check_codepoint_matches_ttf() {
    assert_eq!(lucide::SHIELD_CHECK, "\u{e1ff}");
}

#[test]
fn test_outgoing_recall_merge_clears_media_and_avoids_anti_recall() {
    let mut outgoing = ChatMessage {
        id: "m_out".into(),
        text: "[Hình ảnh]".into(),
        is_outgoing: true,
        link_url: Some("https://cdn.example/photo.jpg".into()),
        link_thumb: Some("https://cdn.example/thumb.jpg".into()),
        ..Default::default()
    };
    apply_recall_merge(&mut outgoing, "[Tin nhắn đã thu hồi]");
    assert_eq!(outgoing.text, "[Tin nhắn đã thu hồi]");
    assert!(outgoing.link_url.is_none());
    assert!(outgoing.link_thumb.is_none());

    let mut incoming = ChatMessage {
        id: "m_in".into(),
        text: "Bí mật".into(),
        is_outgoing: false,
        link_url: Some("https://cdn.example/photo.jpg".into()),
        ..Default::default()
    };
    apply_recall_merge(&mut incoming, "[Tin nhắn đã thu hồi]");
    assert_eq!(incoming.text, "[Đã thu hồi] Bí mật");
    assert_eq!(
        incoming.link_url.as_deref(),
        Some("https://cdn.example/photo.jpg")
    );
}

#[test]
fn test_target_decode_max_dim_bounds_avatars_and_hd_photos() {
    assert_eq!(crate::gui::worker::target_decode_max_dim("avt_abc123"), 128);
    assert_eq!(crate::gui::worker::target_decode_max_dim("ava_abc123"), 128);
    assert_eq!(crate::gui::worker::target_decode_max_dim("hd_abc123"), 2048);
    assert_eq!(crate::gui::worker::target_decode_max_dim("thumb_abc123"), 720);
    assert_eq!(crate::gui::worker::target_decode_max_dim("stk_123_456"), 720);
}

struct PropTempDir {
    path: PathBuf,
}

impl PropTempDir {
    fn new(prefix: &str, seed: u64) -> Self {
        static NEXT_PROP_TMP: AtomicU64 = AtomicU64::new(0);
        let seq = NEXT_PROP_TMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ctdozlite-prop-{prefix}-{}-{seq}-{seed:x}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create prop temp dir");
        Self { path }
    }
}

impl Drop for PropTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_prop_fixture(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture parent");
    }
    std::fs::write(path, bytes).expect("write fixture");
}

fn gen_pin4(rng: &mut Xorshift64) -> String {
    (0..4)
        .map(|_| (b'0' + (rng.next_u64() % 10) as u8) as char)
        .collect()
}

fn mutate_pin4(pin: &str) -> String {
    let mut chars: Vec<char> = pin.chars().collect();
    chars[0] = if chars[0] == '9' { '0' } else { '9' };
    chars.into_iter().collect()
}

fn gen_custom_passcode(rng: &mut Xorshift64, len_override: Option<usize>) -> String {
    const POOL: &[char] = &[
        'a', 'b', 'c', 'x', 'y', 'z', 'A', 'K', 'Z', '0', '4', '9', '!', '@', '#', '$', '%', '-',
        '_', '?', 'ă', 'ê', 'ô', 'ư', 'đ', 'Á', 'ệ', '🔒', '✨',
    ];
    let len = len_override.unwrap_or_else(|| 4 + (rng.next_u64() % 29) as usize);
    let mut out = String::new();
    for _ in 0..len {
        let idx = (rng.next_u64() as usize) % POOL.len();
        out.push(POOL[idx]);
    }
    out
}

fn mutate_custom(passcode: &str) -> String {
    let mut chars: Vec<char> = passcode.chars().collect();
    let replacement = if chars[0] == '~' { '*' } else { '~' };
    chars[0] = replacement;
    chars.into_iter().collect()
}

fn flip_b64_byte(b64: &str, idx_seed: u64, mask_seed: u64) -> String {
    let mut raw = STANDARD.decode(b64).expect("valid base64");
    let idx = (idx_seed as usize) % raw.len();
    let mask = ((mask_seed as u8) & 0xFE) | 0x01;
    raw[idx] ^= mask;
    STANDARD.encode(raw)
}

fn make_fast_lock_config(
    mode: PasscodeMode,
    passcode: &str,
    salt: &[u8; SALT_LEN],
    iterations: u32,
) -> AppLockConfig {
    let hash = pbkdf2_hmac_sha256(passcode.as_bytes(), salt, iterations);
    AppLockConfig {
        version: CURRENT_VERSION,
        enabled: true,
        mode,
        salt_b64: STANDARD.encode(salt),
        hash_b64: STANDARD.encode(hash),
        iterations,
        ..AppLockConfig::default()
    }
}

fn assert_serialized_redacts_passcode(cfg: &AppLockConfig, passcode: &str) {
    let json = serde_json::to_string_pretty(cfg).expect("serialize AppLockConfig");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse AppLockConfig JSON");
    let obj = value.as_object().expect("JSON root object");
    for (k, v) in obj {
        let lower_k = k.to_ascii_lowercase();
        assert!(
            !lower_k.contains("pass") && !lower_k.contains("pin") && !lower_k.contains("secret"),
            "unexpected plaintext key {k} in serialized AppLockConfig"
        );
        if let Some(s) = v.as_str() {
            assert_ne!(s, passcode, "JSON field {k} directly exposed passcode");
        }
    }
    let non_b64_or_long = passcode.chars().count() >= 6
        || !passcode
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
    if non_b64_or_long {
        assert!(
            !json.contains(passcode),
            "serialized AppLockConfig leaked plaintext passcode substring"
        );
    }
}

/// Verify PBKDF2-HMAC-SHA256 uniqueness, plaintext redaction, and tamper/mode rejection across
/// full `100_000`-round configs and 100+ randomized lower-iteration sweeps.
#[test]
fn prop_app_lock_pbkdf2_roundtrip_and_tamper_rejection() {
    let mut rng = Xorshift64::new(0xA991_0C01);
    let mut seen_salts = HashSet::new();
    let mut seen_hashes = HashSet::new();

    let full_cases = [
        (PasscodeMode::Pin4, "0427".to_string()),
        (PasscodeMode::Pin4, "0427".to_string()),
        (PasscodeMode::Custom, "ĐỗThành#2026".to_string()),
    ];

    for (idx, (mode, pass)) in full_cases.iter().enumerate() {
        let cfg = AppLockConfig::create_enabled(*mode, pass).expect("create_enabled succeeds");
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, *mode);
        assert!(seen_salts.insert(cfg.salt_b64.clone()));
        assert!(seen_hashes.insert(cfg.hash_b64.clone()));
        assert_serialized_redacts_passcode(&cfg, pass);

        let mut unlock_cfg = cfg.clone();
        assert_eq!(
            unlock_cfg.verify_attempt(pass, 1_700_000_000),
            VerifyOutcome::Unlocked
        );

        if idx == 2 {
            let mut wrong_cfg = cfg.clone();
            assert_eq!(
                wrong_cfg.verify_attempt(&mutate_custom(pass), 1_700_000_000),
                VerifyOutcome::Wrong {
                    remaining_attempts: MAX_FAILED_ATTEMPTS - 1,
                }
            );

            let mut tampered_hash = cfg.clone();
            tampered_hash.hash_b64 = flip_b64_byte(&cfg.hash_b64, rng.next_u64(), rng.next_u64());
            assert_eq!(
                tampered_hash.verify_attempt(pass, 1_700_000_000),
                VerifyOutcome::Wrong {
                    remaining_attempts: MAX_FAILED_ATTEMPTS - 1,
                }
            );
        }
    }

    assert!(AppLockConfig::create_enabled(PasscodeMode::Pin4, "12a4").is_err());
    assert!(AppLockConfig::create_enabled(PasscodeMode::Pin4, "123").is_err());
    assert!(AppLockConfig::create_enabled(PasscodeMode::Custom, "abc").is_err());
    assert!(AppLockConfig::create_enabled(PasscodeMode::Custom, &"x".repeat(33)).is_err());

    let tmp = PropTempDir::new("pbkdf2-tamper", 0xA991_0C01);
    for round in 0..4u64 {
        let mode = if round.is_multiple_of(2) {
            PasscodeMode::Pin4
        } else {
            PasscodeMode::Custom
        };
        let pass = match mode {
            PasscodeMode::Pin4 => gen_pin4(&mut rng),
            PasscodeMode::Custom => gen_custom_passcode(&mut rng, None),
        };
        let mut salt = [0u8; SALT_LEN];
        salt[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
        salt[8..].copy_from_slice(&rng.next_u64().to_le_bytes());

        let cfg = make_fast_lock_config(mode, &pass, &salt, MIN_ITERATIONS);
        assert!(seen_salts.insert(cfg.salt_b64.clone()));
        assert!(seen_hashes.insert(cfg.hash_b64.clone()));
        assert_serialized_redacts_passcode(&cfg, &pass);

        let mut ok_cfg = cfg.clone();
        assert_eq!(
            ok_cfg.verify_attempt(&pass, 1_700_000_000),
            VerifyOutcome::Unlocked
        );

        let wrong = match mode {
            PasscodeMode::Pin4 => mutate_pin4(&pass),
            PasscodeMode::Custom => mutate_custom(&pass),
        };
        assert_eq!(
            cfg.clone().verify_attempt(&wrong, 1_700_000_000),
            VerifyOutcome::Wrong {
                remaining_attempts: MAX_FAILED_ATTEMPTS - 1,
            }
        );

        let mut bad_hash = cfg.clone();
        bad_hash.hash_b64 = flip_b64_byte(&cfg.hash_b64, rng.next_u64(), rng.next_u64());
        assert!(matches!(
            bad_hash.verify_attempt(&pass, 1_700_000_000),
            VerifyOutcome::Wrong { .. }
        ));

        let mut bad_salt = cfg.clone();
        bad_salt.salt_b64 = flip_b64_byte(&cfg.salt_b64, rng.next_u64(), rng.next_u64());
        assert!(matches!(
            bad_salt.verify_attempt(&pass, 1_700_000_000),
            VerifyOutcome::Wrong { .. }
        ));

        let mut low_iter = cfg.clone();
        low_iter.iterations = MIN_ITERATIONS - 1;
        assert!(matches!(
            low_iter.verify_attempt(&pass, 1_700_000_000),
            VerifyOutcome::Wrong { .. }
        ));
        let bad_path = tmp.path.join(format!("low_iter_{round}.json"));
        low_iter.save_to_path(&bad_path).expect("save low iter");
        assert!(AppLockConfig::load_from_path(&bad_path).is_err());

        let mut disabled = cfg.clone();
        disabled.enabled = false;
        assert!(matches!(
            disabled.verify_attempt(&pass, 1_700_000_000),
            VerifyOutcome::Wrong { .. }
        ));

        if mode == PasscodeMode::Custom && !pass.chars().all(|c| c.is_ascii_digit()) {
            assert!(validate_passcode(PasscodeMode::Pin4, &pass).is_err());
        }
    }

    for sweep in 0..120u64 {
        let iter = 16 + (sweep as u32 % 64);
        let pass = if sweep.is_multiple_of(2) {
            gen_pin4(&mut rng)
        } else {
            gen_custom_passcode(&mut rng, None)
        };
        let wrong = if sweep.is_multiple_of(2) {
            mutate_pin4(&pass)
        } else {
            mutate_custom(&pass)
        };
        let mut salt = [0u8; SALT_LEN];
        salt[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
        salt[8..].copy_from_slice(&rng.next_u64().to_le_bytes());
        let expected = pbkdf2_hmac_sha256(pass.as_bytes(), &salt, iter);
        assert!(seen_hashes.insert(STANDARD.encode(expected)));
        assert_ne!(
            pbkdf2_hmac_sha256(wrong.as_bytes(), &salt, iter),
            expected,
            "wrong passcode collided at sweep {sweep}"
        );
        let mut mutated_salt = salt;
        mutated_salt[(sweep as usize) % SALT_LEN] ^= 0x01;
        assert_ne!(
            pbkdf2_hmac_sha256(pass.as_bytes(), &mutated_salt, iter),
            expected,
            "mutated salt collided at sweep {sweep}"
        );
        assert_ne!(
            pbkdf2_hmac_sha256(pass.as_bytes(), &salt, iter + 1),
            expected,
            "changed iteration count collided at sweep {sweep}"
        );
    }
}

/// Verify brute-force lockout boundary (`MAX_FAILED_ATTEMPTS`), JSON persistence across reload,
/// monotonic clamping (`0..=LOCKOUT_SECS`) on backward clock jumps, and counter reset on unlock.
#[test]
fn prop_app_lock_lockout_persists_across_reload_and_clamps_clock_rollback() {
    let mut rng = Xorshift64::new(0xA991_0C02);
    let tmp = PropTempDir::new("lockout-reload", 0xA991_0C02);

    let full_pass = "9182";
    let mut full_cfg =
        AppLockConfig::create_enabled(PasscodeMode::Pin4, full_pass).expect("full config");
    full_cfg.failed_attempts = MAX_FAILED_ATTEMPTS - 1;
    let t0 = 1_750_000_000i64;
    assert_eq!(
        full_cfg.verify_attempt("0000", t0),
        VerifyOutcome::LockedOut {
            remaining_secs: LOCKOUT_SECS,
        }
    );
    let full_path = tmp.path.join("full_lockout.json");
    full_cfg.save_to_path(&full_path).expect("save full lockout");
    let mut reloaded_full = AppLockConfig::load_from_path(&full_path)
        .expect("load full lockout")
        .expect("present");
    assert_eq!(
        reloaded_full.verify_attempt(full_pass, t0 - 500),
        VerifyOutcome::LockedOut {
            remaining_secs: LOCKOUT_SECS,
        }
    );
    assert_eq!(
        reloaded_full.verify_attempt(full_pass, t0 + LOCKOUT_SECS),
        VerifyOutcome::Unlocked
    );
    assert_eq!(reloaded_full.failed_attempts, 0);
    assert_eq!(reloaded_full.lockout_until_unix, 0);

    let mut base_salt = [0u8; SALT_LEN];
    base_salt[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
    base_salt[8..].copy_from_slice(&rng.next_u64().to_le_bytes());

    for round in 0..4u64 {
        let mode = if round.is_multiple_of(2) {
            PasscodeMode::Pin4
        } else {
            PasscodeMode::Custom
        };
        let pass = match mode {
            PasscodeMode::Pin4 => gen_pin4(&mut rng),
            PasscodeMode::Custom => gen_custom_passcode(&mut rng, Some(10)),
        };
        let wrong = match mode {
            PasscodeMode::Pin4 => mutate_pin4(&pass),
            PasscodeMode::Custom => mutate_custom(&pass),
        };
        let mut salt = base_salt;
        salt[0] ^= round as u8;
        let mut cfg = make_fast_lock_config(mode, &pass, &salt, MIN_ITERATIONS);

        let start_unix = 1_700_000_000i64 + ((rng.next_u64() % 100_000_000) as i64);
        let attempts_to_run = MAX_FAILED_ATTEMPTS + (round as u32 % 4);
        for step in 1..=attempts_to_run {
            let outcome = cfg.verify_attempt(&wrong, start_unix);
            if step < MAX_FAILED_ATTEMPTS {
                assert_eq!(
                    outcome,
                    VerifyOutcome::Wrong {
                        remaining_attempts: MAX_FAILED_ATTEMPTS - step,
                    }
                );
                assert_eq!(cfg.remaining_lockout_secs(start_unix), 0);
            } else {
                assert_eq!(
                    outcome,
                    VerifyOutcome::LockedOut {
                        remaining_secs: LOCKOUT_SECS,
                    }
                );
                assert_eq!(cfg.remaining_lockout_secs(start_unix), LOCKOUT_SECS);
            }
        }

        let cfg_path = tmp.path.join(format!("round_{round}.json"));
        cfg.save_to_path(&cfg_path).expect("save round config");
        let mut reloaded = AppLockConfig::load_from_path(&cfg_path)
            .expect("load round config")
            .expect("round config present");
        assert_eq!(reloaded.failed_attempts, cfg.failed_attempts);
        assert_eq!(reloaded.lockout_until_unix, cfg.lockout_until_unix);

        let boundary_deltas = [-10_000i64, -500, -1, 0, 1, 15, 29, 30, 31, 100];
        for delta in boundary_deltas
            .into_iter()
            .chain((0..12).map(|_| -10_000 + ((rng.next_u64() % 10_101) as i64)))
        {
            let probe_now = start_unix.saturating_add(delta);
            let rem = reloaded.remaining_lockout_secs(probe_now);
            assert!(
                (0..=LOCKOUT_SECS).contains(&rem),
                "clamped lockout {rem} out of range for delta {delta}"
            );
            let expected_rem = if delta < 0 {
                LOCKOUT_SECS
            } else if delta < LOCKOUT_SECS {
                LOCKOUT_SECS - delta
            } else {
                0
            };
            assert_eq!(rem, expected_rem, "unexpected lockout for delta {delta}");
        }

        assert!(matches!(
            reloaded.verify_attempt(&pass, start_unix),
            VerifyOutcome::LockedOut {
                remaining_secs: LOCKOUT_SECS
            }
        ));
        assert_eq!(
            reloaded.verify_attempt(&pass, start_unix + LOCKOUT_SECS),
            VerifyOutcome::Unlocked
        );
        assert_eq!(reloaded.failed_attempts, 0);
        assert_eq!(reloaded.lockout_until_unix, 0);
        reloaded.save_to_path(&cfg_path).expect("save reset config");
        let after_reset = AppLockConfig::load_from_path(&cfg_path)
            .expect("reload reset config")
            .expect("present");
        assert_eq!(after_reset.failed_attempts, 0);
        assert_eq!(after_reset.lockout_until_unix, 0);
    }

    let shared_cfg = make_fast_lock_config(PasscodeMode::Pin4, "4242", &base_salt, MIN_ITERATIONS);
    for sweep in 0..120u64 {
        let start_unix = 1_720_000_000i64 + ((rng.next_u64() % 50_000_000) as i64);
        let attempts = 1 + (rng.next_u64() % 8) as u32;
        let mut cfg = shared_cfg.clone();
        cfg.failed_attempts = attempts;
        cfg.lockout_until_unix = if attempts >= MAX_FAILED_ATTEMPTS {
            start_unix + LOCKOUT_SECS
        } else {
            0
        };
        let sweep_path = tmp.path.join("sweep_lockout.json");
        if sweep < 20 {
            cfg.save_to_path(&sweep_path).expect("save sweep");
            cfg = AppLockConfig::load_from_path(&sweep_path)
                .expect("load sweep")
                .expect("present");
        }
        let delta = -10_000 + ((rng.next_u64() % 10_101) as i64);
        let rem = cfg.remaining_lockout_secs(start_unix + delta);
        assert!((0..=LOCKOUT_SECS).contains(&rem));
        if attempts >= MAX_FAILED_ATTEMPTS {
            let expected_rem = if delta < 0 {
                LOCKOUT_SECS
            } else if delta < LOCKOUT_SECS {
                LOCKOUT_SECS - delta
            } else {
                0
            };
            assert_eq!(rem, expected_rem);
            if expected_rem > 0 {
                assert_eq!(
                    cfg.verify_attempt("4242", start_unix + delta),
                    VerifyOutcome::LockedOut {
                        remaining_secs: expected_rem
                    }
                );
            }
        } else {
            assert_eq!(rem, 0);
        }
    }
}

/// Verify notification title/body masking, fallback toast masking, and popup interaction denial
/// across randomized sender/body tokens and `(app_locked, hide_content)` combinations.
#[test]
fn prop_app_lock_notification_masking_never_leaks_sender_or_body() {
    let mut rng = Xorshift64::new(0xA991_0C03);
    let edge_counts = [0usize, 1, 2, 5, 42, 999, usize::MAX];

    for round in 0..200usize {
        let sender = format!("SECRET_SENDER_{:016x}_{round}", rng.next_u64());
        let body = format!(
            "SECRET_BODY_{:016x}_xin_chao_{round}",
            rng.next_u64()
        );
        let fallback = "SAFE_FALLBACK_TOAST_TEXT";
        let unread_count = if round < edge_counts.len() {
            edge_counts[round]
        } else {
            (rng.next_u64() % 500) as usize
        };

        for app_locked in [false, true] {
            for hide_content in [false, true] {
                assert_eq!(popup_allows_interaction(app_locked), !app_locked);
                if app_locked {
                    assert!(!popup_allows_interaction(true));
                }

                let (masked_title, masked_body) =
                    mask_notification_content(app_locked, hide_content, &sender, &body, unread_count);
                let masked_toast =
                    mask_toast_text(app_locked, hide_content, fallback, body.clone());

                if app_locked && hide_content {
                    assert_eq!(masked_title, "ctdozlite");
                    let expected_body = match unread_count {
                        0 => "Bạn có tin nhắn mới".to_string(),
                        1 => "Bạn có 1 tin nhắn mới".to_string(),
                        count => format!("Bạn có {count} tin nhắn mới"),
                    };
                    assert_eq!(masked_body, expected_body);
                    assert!(!masked_title.contains(&sender));
                    assert!(!masked_title.contains(&body));
                    assert!(!masked_body.contains(&sender));
                    assert!(!masked_body.contains(&body));
                    assert_eq!(masked_toast, fallback);
                    assert!(!masked_toast.contains(&sender));
                    assert!(!masked_toast.contains(&body));
                } else {
                    assert_eq!(masked_title, sender);
                    assert_eq!(masked_body, body);
                    assert_eq!(masked_toast, body);
                }
            }
        }
    }
}

/// Verify "Quên mã khoá? Đăng xuất" deletes `session.json`, `app_lock.json`, and all
/// `accounts/<uin>.json` credential snapshots while preserving history SQLite DBs, WALs,
/// thread caches, and per-account attachment directories verbatim.
#[test]
fn prop_forget_lock_wipe_removes_all_creds_and_preserves_history_db() {
    let mut rng = Xorshift64::new(0xA991_0C04);

    for round in 0..40usize {
        let dir = PropTempDir::new("forget-lock-wipe", round as u64);
        let accounts_dir = dir.path.join("accounts");
        let include_session_json = rng.next_u64().is_multiple_of(2) || round == 0;
        let include_app_lock = rng.next_u64().is_multiple_of(2) || round == 0;
        let account_count = match round {
            0 => 0,
            1 => 1,
            _ => (rng.next_u64() % 6) as usize,
        };

        if include_session_json {
            let session_path = dir.path.join("session.json");
            write_prop_fixture(&session_path, br#"{"uid":"root_cred"}"#);
        }
        if include_app_lock {
            let lock_path = dir.path.join(APP_LOCK_FILE);
            write_prop_fixture(&lock_path, br#"{"version":1,"enabled":true}"#);
        }

        let mut uins = Vec::with_capacity(account_count);
        let mut seen_uins = HashSet::new();
        while uins.len() < account_count {
            let uin = format!("{}", 100_000_000u64 + (rng.next_u64() % 899_999_999));
            if seen_uins.insert(uin.clone()) {
                uins.push(uin);
            }
        }

        let mut preserved_files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        for (idx, uin) in uins.iter().enumerate() {
            let cred_file = accounts_dir.join(format!("{uin}.json"));
            write_prop_fixture(&cred_file, format!(r#"{{"uin":"{uin}"}}"#).as_bytes());

            let threads_file = accounts_dir.join(format!("{uin}_threads.json"));
            let threads_bytes = format!(r#"{{"threads":[{idx}]}}"#).into_bytes();
            write_prop_fixture(&threads_file, &threads_bytes);
            preserved_files.push((threads_file, threads_bytes));

            let db_file = accounts_dir.join(format!("{uin}_history.db"));
            let db_bytes = format!("SQLite format 3\0round={round}\0uin={uin}").into_bytes();
            write_prop_fixture(&db_file, &db_bytes);
            preserved_files.push((db_file, db_bytes));

            let wal_file = accounts_dir.join(format!("{uin}_history.db-wal"));
            let wal_bytes = format!("WAL_PAYLOAD_{round}_{uin}").into_bytes();
            write_prop_fixture(&wal_file, &wal_bytes);
            preserved_files.push((wal_file, wal_bytes));

            let note_file = accounts_dir.join(uin).join("note.txt");
            let note_bytes = format!("attachment note {round}/{uin}").into_bytes();
            write_prop_fixture(&note_file, &note_bytes);
            preserved_files.push((note_file, note_bytes));
        }

        let expected_before = include_session_json || !uins.is_empty();
        assert_eq!(has_any_saved_credentials_in(&dir.path), expected_before);

        let expected_removed =
            usize::from(include_session_json) + usize::from(include_app_lock) + uins.len();
        let removed =
            wipe_all_saved_session_credentials_in(&dir.path).expect("wipe credentials succeeds");
        assert_eq!(removed, expected_removed);

        assert!(!dir.path.join("session.json").exists());
        assert!(!dir.path.join(APP_LOCK_FILE).exists());
        assert!(!has_any_saved_credentials_in(&dir.path));

        for uin in &uins {
            assert!(!accounts_dir.join(format!("{uin}.json")).exists());
        }
        for (path, expected_bytes) in &preserved_files {
            assert!(path.is_file(), "expected preserved file {}", path.display());
            let actual = std::fs::read(path).expect("read preserved file");
            assert_eq!(
                &actual,
                expected_bytes,
                "preserved file {} was modified",
                path.display()
            );
        }

        let second_removed =
            wipe_all_saved_session_credentials_in(&dir.path).expect("idempotent wipe");
        assert_eq!(second_removed, 0);
    }
}
