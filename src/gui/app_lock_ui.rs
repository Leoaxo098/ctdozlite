use std::time::Duration;

use eframe::egui::{
    self, Align, CursorIcon, FontId, Id, Key, Layout, Margin, RichText, Rounding, Sense, Stroke,
    Vec2,
};

use super::theme::{
    draw_lucide_icon, font_family_semibold, lucide, render_toggle_switch, styled_input_frame,
    ThemePalette,
};
use super::worker::{set_idle_lock_timeout_secs, WorkerCmd, WORKER_TX};
use super::{AppLockSettingsAction, ZaloGuiApp};
use crate::app_lock::{
    validate_passcode, AppLockConfig, ChangePasscodeOutcome, PasscodeMode, VerifyOutcome,
    IDLE_PRESETS_SECS,
};

/// Human-readable Vietnamese label for an idle auto-lock timeout preset in seconds.
pub(super) fn idle_timeout_label(secs: u64) -> &'static str {
    match secs {
        0 => "Tắt",
        300 => "5 phút",
        900 => "15 phút",
        1800 => "30 phút",
        _ => "Tuỳ chỉnh",
    }
}

/// Filter a 4-digit PIN input string to ASCII digits only, capped at 4 digits.
pub(super) fn sanitize_pin4_input(raw: &str) -> String {
    raw.chars().filter(char::is_ascii_digit).take(4).collect()
}

/// Sanitize a passcode draft according to [`PasscodeMode`].
fn sanitize_passcode_draft(mode: PasscodeMode, raw: &str) -> String {
    match mode {
        PasscodeMode::Pin4 => sanitize_pin4_input(raw),
        PasscodeMode::Custom => raw.chars().take(32).collect(),
    }
}

/// Persist `app_lock.json` atomically and log any storage failure without panicking.
fn persist_app_lock_config(cfg: &AppLockConfig) -> Result<(), String> {
    cfg.save_default().map_err(|err| {
        let msg = err.to_string();
        crate::logger::log_error("app_lock", &msg);
        msg
    })
}

/// Format a user-facing verification failure message for both lock screen and Settings prompts.
fn format_verify_error(outcome: VerifyOutcome) -> String {
    match outcome {
        VerifyOutcome::Unlocked => String::new(),
        VerifyOutcome::Wrong { remaining_attempts } => {
            format!("Mã khoá không đúng (còn {remaining_attempts} lần thử)")
        }
        VerifyOutcome::LockedOut { remaining_secs } => {
            format!("Quá nhiều lần nhập sai — thử lại sau {remaining_secs} giây")
        }
    }
}

/// Render a single-line masked passcode input inside a themed frame; returns `(response, enter_pressed)`.
fn render_passcode_field(
    ui: &mut egui::Ui,
    pal: &ThemePalette,
    id_salt: &str,
    buf: &mut String,
    mode: PasscodeMode,
    hint: &str,
    request_focus: bool,
) -> (egui::Response, bool) {
    let field_id = Id::new(id_salt);
    let has_focus = ui.memory(|m| m.has_focus(field_id));
    let mut enter_pressed = false;
    let resp = styled_input_frame(pal, has_focus)
        .show(ui, |ui| {
            let r = ui.add(
                egui::TextEdit::singleline(buf)
                    .id(field_id)
                    .frame(false)
                    .password(true)
                    .hint_text(hint)
                    .desired_width(f32::INFINITY),
            );
            if request_focus {
                r.request_focus();
            }
            if r.changed() {
                let cleaned = sanitize_passcode_draft(mode, buf);
                if cleaned != *buf {
                    *buf = cleaned;
                }
            }
            if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                enter_pressed = true;
            }
            r
        })
        .inner;
    (resp, enter_pressed)
}

/// Paint four visual PIN dot indicators (`●` / `○`) reflecting `entered_len`.
fn render_pin4_dots(ui: &mut egui::Ui, pal: &ThemePalette, entered_len: usize) {
    ui.horizontal(|ui| {
        let total_w = 4.0 * 38.0 + 3.0 * 10.0;
        let lead = ((ui.available_width() - total_w) * 0.5).max(0.0);
        ui.add_space(lead);
        ui.spacing_mut().item_spacing.x = 10.0;
        for idx in 0..4 {
            let filled = idx < entered_len;
            let (rect, _) = ui.allocate_exact_size(Vec2::new(38.0, 42.0), Sense::hover());
            ui.painter().rect_filled(rect, Rounding::same(8.0), pal.bg_input);
            ui.painter().rect_stroke(
                rect,
                Rounding::same(8.0),
                Stroke::new(
                    if filled { 1.4_f32 } else { 1.0_f32 },
                    if filled { pal.primary } else { pal.border },
                ),
            );
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                if filled { "●" } else { "○" },
                FontId::proportional(18.0),
                if filled { pal.primary } else { pal.text_muted },
            );
        }
    });
}

/// Render a radio selector for choosing between 4-digit PIN and custom passcode.
fn render_mode_selector(ui: &mut egui::Ui, pal: &ThemePalette, mode: &mut PasscodeMode) -> bool {
    let prev = *mode;
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new("Loại mã khoá:")
                .color(pal.text_secondary)
                .size(12.5),
        );
        ui.radio_value(mode, PasscodeMode::Pin4, "PIN 4 số");
        ui.radio_value(mode, PasscodeMode::Custom, "Mật khẩu tuỳ chỉnh (4-32 ký tự)");
    });
    *mode != prev
}

impl ZaloGuiApp {
    /// Render the full-screen passcode lock gate blocking workspace and login panels.
    pub(super) fn render_lock_screen(&mut self, ctx: &egui::Context, pal: &ThemePalette) {
        let cmd_label = if cfg!(target_os = "macos") {
            "Cmd+L"
        } else {
            "Ctrl+L"
        };
        let now = crate::login::unix_now();
        let lockout_rem = self.app_lock_config.remaining_lockout_secs(now);
        let mut submit_candidate: Option<String> = None;

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(pal.bg_chat_canvas))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let avail = ui.available_size();
                        let card_w = (avail.x - 32.0).clamp(240.0, 380.0);
                        ui.vertical_centered(|ui| {
                            ui.add_space(((avail.y - 360.0) * 0.42).max(24.0));

                            egui::Frame::none()
                                .fill(pal.bg_elevated)
                                .stroke(Stroke::new(1.0_f32, pal.border))
                                .rounding(Rounding::same(14.0))
                                .inner_margin(Margin::symmetric(26.0, 24.0))
                                .show(ui, |ui| {
                                    ui.set_width(card_w);
                                    ui.vertical_centered(|ui| {
                                        let (badge_rect, _) = ui.allocate_exact_size(
                                            Vec2::splat(48.0),
                                            Sense::hover(),
                                        );
                                        ui.painter().circle_filled(
                                            badge_rect.center(),
                                            24.0,
                                            pal.primary.linear_multiply(0.14),
                                        );
                                        draw_lucide_icon(
                                            ui.painter(),
                                            badge_rect.center(),
                                            lucide::LOCK,
                                            22.0,
                                            pal.primary,
                                        );
                                        ui.add_space(10.0);

                                        ui.label(
                                            RichText::new("Ứng dụng đang khoá")
                                                .font(FontId::new(18.0, font_family_semibold()))
                                                .color(pal.text_primary),
                                        );
                                        ui.add_space(4.0);
                                        ui.label(
                                            RichText::new(format!(
                                                "Nhập mã khoá để tiếp tục ({cmd_label} để khoá nhanh)"
                                            ))
                                            .color(pal.text_secondary)
                                            .size(12.3),
                                        );
                                        ui.add_space(14.0);

                                        if self.app_lock_ui.corrupted_config {
                                            egui::Frame::none()
                                                .fill(pal.danger.linear_multiply(0.10))
                                                .stroke(Stroke::new(1.0_f32, pal.danger_text))
                                                .rounding(Rounding::same(8.0))
                                                .inner_margin(Margin::symmetric(12.0, 10.0))
                                                .show(ui, |ui| {
                                                    ui.label(
                                                        RichText::new(
                                                            "Tệp cấu hình app_lock.json không đọc được hoặc đã bị hỏng. Vui lòng chọn \"Quên mã khoá? Đăng xuất\" bên dưới để đặt lại phiên đăng nhập.",
                                                        )
                                                        .color(pal.danger_text)
                                                        .size(12.2),
                                                    );
                                                });
                                            ui.add_space(12.0);
                                        } else if lockout_rem > 0 {
                                            ctx.request_repaint_after(Duration::from_millis(500));
                                            egui::Frame::none()
                                                .fill(pal.danger.linear_multiply(0.10))
                                                .stroke(Stroke::new(1.0_f32, pal.danger_text))
                                                .rounding(Rounding::same(8.0))
                                                .inner_margin(Margin::symmetric(12.0, 10.0))
                                                .show(ui, |ui| {
                                                    ui.label(
                                                        RichText::new(format!(
                                                            "Quá nhiều lần nhập sai — thử lại sau {lockout_rem} giây"
                                                        ))
                                                        .color(pal.danger_text)
                                                        .size(12.8)
                                                        .strong(),
                                                    );
                                                });
                                            ui.add_space(10.0);
                                            ui.add_enabled_ui(false, |ui| {
                                                let mut disabled_buf = String::new();
                                                let _ = render_passcode_field(
                                                    ui,
                                                    pal,
                                                    "app_lock_unlock_disabled",
                                                    &mut disabled_buf,
                                                    self.app_lock_config.mode,
                                                    "Đang tạm khoá…",
                                                    false,
                                                );
                                            });
                                            ui.add_space(12.0);
                                        } else {
                                            let req_focus = self.app_lock_ui.focus_requested;
                                            self.app_lock_ui.focus_requested = false;
                                            match self.app_lock_config.mode {
                                                PasscodeMode::Pin4 => {
                                                    let pin_len =
                                                        self.app_lock_ui.unlock_input.chars().count();
                                                    render_pin4_dots(ui, pal, pin_len);
                                                    ui.add_space(10.0);
                                                    let (_, enter_pressed) = render_passcode_field(
                                                        ui,
                                                        pal,
                                                        "app_lock_unlock_pin4",
                                                        &mut self.app_lock_ui.unlock_input,
                                                        PasscodeMode::Pin4,
                                                        "Nhập 4 chữ số PIN",
                                                        req_focus,
                                                    );
                                                    if self.app_lock_ui.unlock_input.len() == 4
                                                        || (enter_pressed
                                                            && !self
                                                                .app_lock_ui
                                                                .unlock_input
                                                                .is_empty())
                                                    {
                                                        submit_candidate = Some(
                                                            self.app_lock_ui.unlock_input.clone(),
                                                        );
                                                    }
                                                }
                                                PasscodeMode::Custom => {
                                                    let (_, enter_pressed) = render_passcode_field(
                                                        ui,
                                                        pal,
                                                        "app_lock_unlock_custom",
                                                        &mut self.app_lock_ui.unlock_input,
                                                        PasscodeMode::Custom,
                                                        "Nhập mật khẩu mở khoá",
                                                        req_focus,
                                                    );
                                                    ui.add_space(10.0);
                                                    let unlock_btn = egui::Button::new(
                                                        RichText::new("Mở khoá")
                                                            .color(pal.primary_fg)
                                                            .size(13.5)
                                                            .strong(),
                                                    )
                                                    .fill(pal.primary)
                                                    .rounding(Rounding::same(8.0))
                                                    .min_size(Vec2::new(ui.available_width(), 36.0));
                                                    let btn_clicked = ui
                                                        .add(unlock_btn)
                                                        .on_hover_cursor(CursorIcon::PointingHand)
                                                        .clicked();
                                                    if (enter_pressed || btn_clicked)
                                                        && !self
                                                            .app_lock_ui
                                                            .unlock_input
                                                            .is_empty()
                                                    {
                                                        submit_candidate = Some(
                                                            self.app_lock_ui.unlock_input.clone(),
                                                        );
                                                    }
                                                }
                                            }
                                            if let Some(ref err) = self.app_lock_ui.unlock_error {
                                                ui.add_space(8.0);
                                                ui.label(
                                                    RichText::new(err)
                                                        .color(pal.danger_text)
                                                        .size(12.2),
                                                );
                                            }
                                            ui.add_space(12.0);
                                        }

                                        if let Some(is_ringing) = self
                                            .active_call
                                            .as_ref()
                                            .map(|c| c.is_incoming_ringing)
                                        {
                                            let (strip_txt, action_txt) = if is_ringing {
                                                (
                                                    "📲 Cuộc gọi đến — mở khoá để xem & trả lời",
                                                    "Từ chối",
                                                )
                                            } else {
                                                ("📞 Cuộc gọi đang diễn ra", "Kết thúc")
                                            };
                                            egui::Frame::none()
                                                .fill(pal.bg_chat_canvas)
                                                .stroke(Stroke::new(1.0_f32, pal.border))
                                                .rounding(Rounding::same(8.0))
                                                .inner_margin(Margin::symmetric(12.0, 9.0))
                                                .show(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            RichText::new(strip_txt)
                                                                .color(pal.text_primary)
                                                                .size(12.2),
                                                        );
                                                        ui.with_layout(
                                                            Layout::right_to_left(Align::Center),
                                                            |ui| {
                                                                let btn = egui::Button::new(
                                                                    RichText::new(action_txt)
                                                                        .color(pal.primary_fg)
                                                                        .size(12.0)
                                                                        .strong(),
                                                                )
                                                                .fill(pal.danger)
                                                                .rounding(Rounding::same(6.0));
                                                                if ui
                                                                    .add(btn)
                                                                    .on_hover_cursor(
                                                                        CursorIcon::PointingHand,
                                                                    )
                                                                    .clicked()
                                                                {
                                                                    if let Some(tx) =
                                                                        WORKER_TX.get()
                                                                    {
                                                                        let cmd = if is_ringing {
                                                                            WorkerCmd::AnswerCall {
                                                                                accept: false,
                                                                                cam_start_off: false,
                                                                            }
                                                                        } else {
                                                                            WorkerCmd::EndCall
                                                                        };
                                                                        let _ = tx.send(cmd);
                                                                    }
                                                                    self.active_call = None;
                                                                }
                                                            },
                                                        );
                                                    });
                                                });
                                            ui.add_space(10.0);
                                        }

                                        let forgot_resp = ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("Quên mã khoá? Đăng xuất")
                                                        .color(pal.link_text)
                                                        .size(12.2),
                                                )
                                                .frame(false),
                                            )
                                            .on_hover_cursor(CursorIcon::PointingHand);
                                        if forgot_resp.clicked() {
                                            self.app_lock_ui.confirm_forgot_open =
                                                !self.app_lock_ui.confirm_forgot_open;
                                        }

                                        if self.app_lock_ui.confirm_forgot_open {
                                            ui.add_space(8.0);
                                            egui::Frame::none()
                                                .fill(pal.bg_chat_canvas)
                                                .stroke(Stroke::new(1.0_f32, pal.border))
                                                .rounding(Rounding::same(8.0))
                                                .inner_margin(Margin::symmetric(12.0, 10.0))
                                                .show(ui, |ui| {
                                                    ui.label(
                                                        RichText::new(
                                                            "Thao tác này sẽ đăng xuất toàn bộ tài khoản đang lưu trên thiết bị để gỡ khoá. Lịch sử tin nhắn SQLite (accounts/*_history.db) vẫn được giữ nguyên.",
                                                        )
                                                        .color(pal.text_secondary)
                                                        .size(11.8),
                                                    );
                                                    ui.add_space(8.0);
                                                    ui.horizontal(|ui| {
                                                        let confirm_btn = egui::Button::new(
                                                            RichText::new("Xác nhận đăng xuất")
                                                                .color(pal.primary_fg)
                                                                .size(12.2)
                                                                .strong(),
                                                        )
                                                        .fill(pal.danger)
                                                        .rounding(Rounding::same(6.0));
                                                        if ui
                                                            .add(confirm_btn)
                                                            .on_hover_cursor(
                                                                CursorIcon::PointingHand,
                                                            )
                                                            .clicked()
                                                        {
                                                            if let Some(tx) = WORKER_TX.get() {
                                                                let _ = tx.send(
                                                                    WorkerCmd::ForgetLockAndSignOutAll,
                                                                );
                                                            }
                                                            self.app_lock_ui.confirm_forgot_open =
                                                                false;
                                                            self.status_msg =
                                                                "Đang đăng xuất toàn bộ tài khoản…"
                                                                    .into();
                                                        }
                                                        if ui
                                                            .button(
                                                                RichText::new("Huỷ")
                                                                    .color(pal.text_primary)
                                                                    .size(12.2),
                                                            )
                                                            .on_hover_cursor(
                                                                CursorIcon::PointingHand,
                                                            )
                                                            .clicked()
                                                        {
                                                            self.app_lock_ui.confirm_forgot_open =
                                                                false;
                                                        }
                                                    });
                                                });
                                        }
                                    });
                                });
                            ui.add_space(24.0);
                        });
                    });
            });

        if let Some(candidate) = submit_candidate {
            let outcome = self.app_lock_config.verify_attempt(&candidate, now);
            let _ = persist_app_lock_config(&self.app_lock_config);
            self.app_lock_ui.unlock_input.clear();
            match outcome {
                VerifyOutcome::Unlocked => {
                    self.app_locked = false;
                    self.app_lock_ui.unlock_error = None;
                    self.app_lock_ui.corrupted_config = false;
                    self.app_lock_ui.confirm_forgot_open = false;
                    self.app_lock_ui.focus_requested = false;
                    self.app_lock_ui.last_activity_ui_time = ctx.input(|i| i.time);
                    ctx.request_repaint();
                }
                VerifyOutcome::Wrong { .. } => {
                    self.app_lock_ui.unlock_error = Some(format_verify_error(outcome));
                    self.app_lock_ui.focus_requested = true;
                }
                VerifyOutcome::LockedOut { .. } => {
                    self.app_lock_ui.unlock_error = Some(format_verify_error(outcome));
                    self.app_lock_ui.focus_requested = true;
                }
            }
        }
    }

    /// Render the Settings -> Privacy `Khoá bảo mật (App Lock)` card; returns `true` when `Khoá ngay` is clicked.
    pub(super) fn render_privacy_app_lock_section(
        &mut self,
        ui: &mut egui::Ui,
        _ctx: &egui::Context,
        pal: &ThemePalette,
    ) -> bool {
        let mut lock_now_requested = false;
        let quick_lock_shortcut = if cfg!(target_os = "macos") {
            "Cmd+L"
        } else {
            "Ctrl+L"
        };

        ui.add_space(14.0);
        ui.label(
            RichText::new("Khoá bảo mật (App Lock)")
                .color(pal.text_primary)
                .size(13.5)
                .strong(),
        );
        ui.add_space(6.0);

        egui::Frame::none()
            .fill(pal.bg_elevated)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(Rounding::same(8.0))
            .inner_margin(Margin::symmetric(14.0, 12.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                if !self.app_lock_config.enabled {
                    if self.app_lock_ui.settings_action != AppLockSettingsAction::Enabling {
                        ui.label(
                            RichText::new(
                                "Bảo vệ ứng dụng bằng mã PIN 4 số hoặc mật khẩu khi khởi động, máy ngủ, hoặc không thao tác.",
                            )
                            .color(pal.text_secondary)
                            .size(12.2),
                        );
                        ui.add_space(10.0);
                        let enable_btn = egui::Button::new(
                            RichText::new("Bật khoá bảo mật")
                                .color(pal.primary_fg)
                                .size(13.0)
                                .strong(),
                        )
                        .fill(pal.primary)
                        .rounding(Rounding::same(6.0));
                        if ui
                            .add(enable_btn)
                            .on_hover_cursor(CursorIcon::PointingHand)
                            .clicked()
                        {
                            self.app_lock_ui.reset_settings_drafts();
                            self.app_lock_ui.draft_mode = PasscodeMode::Pin4;
                            self.app_lock_ui.settings_action = AppLockSettingsAction::Enabling;
                        }
                    } else {
                        if render_mode_selector(ui, pal, &mut self.app_lock_ui.draft_mode) {
                            self.app_lock_ui.draft_new.clear();
                            self.app_lock_ui.draft_confirm.clear();
                            self.app_lock_ui.settings_error = None;
                        }
                        ui.add_space(8.0);
                        let new_hint = match self.app_lock_ui.draft_mode {
                            PasscodeMode::Pin4 => "Nhập mã PIN mới (4 chữ số)",
                            PasscodeMode::Custom => "Nhập mật khẩu mới (4-32 ký tự)",
                        };
                        let _ = render_passcode_field(
                            ui,
                            pal,
                            "app_lock_enable_new",
                            &mut self.app_lock_ui.draft_new,
                            self.app_lock_ui.draft_mode,
                            new_hint,
                            false,
                        );
                        ui.add_space(6.0);
                        let (_, confirm_enter) = render_passcode_field(
                            ui,
                            pal,
                            "app_lock_enable_confirm",
                            &mut self.app_lock_ui.draft_confirm,
                            self.app_lock_ui.draft_mode,
                            "Nhập lại mã khoá để xác nhận",
                            false,
                        );
                        if let Some(ref err) = self.app_lock_ui.settings_error {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(err)
                                    .color(pal.danger_text)
                                    .size(12.2),
                            );
                        }
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            let save_btn = egui::Button::new(
                                RichText::new("Lưu & Bật")
                                    .color(pal.primary_fg)
                                    .size(12.8)
                                    .strong(),
                            )
                            .fill(pal.primary)
                            .rounding(Rounding::same(6.0));
                            let clicked = ui
                                .add(save_btn)
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked();
                            if clicked || confirm_enter {
                                if let Err(msg) = validate_passcode(
                                    self.app_lock_ui.draft_mode,
                                    &self.app_lock_ui.draft_new,
                                ) {
                                    self.app_lock_ui.settings_error = Some(msg.to_string());
                                } else if self.app_lock_ui.draft_new
                                    != self.app_lock_ui.draft_confirm
                                {
                                    self.app_lock_ui.settings_error =
                                        Some("Mã xác nhận không khớp".to_string());
                                } else {
                                    match AppLockConfig::create_enabled(
                                        self.app_lock_ui.draft_mode,
                                        &self.app_lock_ui.draft_new,
                                    ) {
                                        Ok(cfg) => {
                                            if let Err(err) = persist_app_lock_config(&cfg) {
                                                self.app_lock_ui.settings_error = Some(format!(
                                                    "Không thể lưu app_lock.json: {err}"
                                                ));
                                            } else {
                                                self.app_lock_config = cfg;
                                                set_idle_lock_timeout_secs(
                                                    self.app_lock_config.idle_timeout_secs,
                                                );
                                                self.app_lock_ui.corrupted_config = false;
                                                self.app_lock_ui.reset_settings_drafts();
                                                self.show_toast("Đã bật khoá bảo mật ứng dụng");
                                            }
                                        }
                                        Err(err) => {
                                            self.app_lock_ui.settings_error =
                                                Some(format!("Không thể tạo mã khoá: {err}"));
                                        }
                                    }
                                }
                            }
                            if ui
                                .button("Huỷ")
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked()
                            {
                                self.app_lock_ui.reset_settings_drafts();
                            }
                        });
                    }
                } else {
                    let mode_label = match self.app_lock_config.mode {
                        PasscodeMode::Pin4 => "Đang bật · PIN 4 số",
                        PasscodeMode::Custom => "Đang bật · Mật khẩu tuỳ chỉnh",
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(mode_label)
                                .color(pal.accent_online)
                                .size(12.8)
                                .strong(),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let lock_btn = egui::Button::new(
                                RichText::new(format!("Khoá ngay ({quick_lock_shortcut})"))
                                    .color(pal.primary_fg)
                                    .size(12.2)
                                    .strong(),
                            )
                            .fill(pal.primary)
                            .rounding(Rounding::same(6.0));
                            if ui
                                .add(lock_btn)
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked()
                            {
                                lock_now_requested = true;
                            }
                            if ui
                                .button("Tắt khoá bảo mật")
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked()
                            {
                                self.app_lock_ui.reset_settings_drafts();
                                self.app_lock_ui.settings_action = AppLockSettingsAction::Disabling;
                            }
                            if ui
                                .button("Đổi mã khoá")
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked()
                            {
                                self.app_lock_ui.reset_settings_drafts();
                                self.app_lock_ui.draft_mode = self.app_lock_config.mode;
                                self.app_lock_ui.settings_action = AppLockSettingsAction::Changing;
                            }
                        });
                    });

                    if self.app_lock_ui.settings_action == AppLockSettingsAction::Changing {
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(8.0);
                        let _ = render_passcode_field(
                            ui,
                            pal,
                            "app_lock_change_current",
                            &mut self.app_lock_ui.draft_current,
                            self.app_lock_config.mode,
                            "Nhập mã khoá hiện tại",
                            false,
                        );
                        ui.add_space(6.0);
                        if render_mode_selector(ui, pal, &mut self.app_lock_ui.draft_mode) {
                            self.app_lock_ui.draft_new.clear();
                            self.app_lock_ui.draft_confirm.clear();
                            self.app_lock_ui.settings_error = None;
                        }
                        ui.add_space(6.0);
                        let new_hint = match self.app_lock_ui.draft_mode {
                            PasscodeMode::Pin4 => "Mã PIN mới (4 chữ số)",
                            PasscodeMode::Custom => "Mật khẩu mới (4-32 ký tự)",
                        };
                        let _ = render_passcode_field(
                            ui,
                            pal,
                            "app_lock_change_new",
                            &mut self.app_lock_ui.draft_new,
                            self.app_lock_ui.draft_mode,
                            new_hint,
                            false,
                        );
                        ui.add_space(6.0);
                        let (_, confirm_enter) = render_passcode_field(
                            ui,
                            pal,
                            "app_lock_change_confirm",
                            &mut self.app_lock_ui.draft_confirm,
                            self.app_lock_ui.draft_mode,
                            "Nhập lại mã khoá mới",
                            false,
                        );
                        if let Some(ref err) = self.app_lock_ui.settings_error {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(err)
                                    .color(pal.danger_text)
                                    .size(12.2),
                            );
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let apply_btn = egui::Button::new(
                                RichText::new("Xác nhận đổi mã")
                                    .color(pal.primary_fg)
                                    .size(12.5)
                                    .strong(),
                            )
                            .fill(pal.primary)
                            .rounding(Rounding::same(6.0));
                            let clicked = ui
                                .add(apply_btn)
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked();
                            if clicked || confirm_enter {
                                if self.app_lock_ui.draft_new != self.app_lock_ui.draft_confirm {
                                    self.app_lock_ui.settings_error =
                                        Some("Mã xác nhận không khớp".to_string());
                                } else {
                                    let now = crate::login::unix_now();
                                    let res = self.app_lock_config.change_passcode(
                                        &self.app_lock_ui.draft_current,
                                        self.app_lock_ui.draft_mode,
                                        &self.app_lock_ui.draft_new,
                                        now,
                                    );
                                    match res {
                                        Ok(ChangePasscodeOutcome::Changed) => {
                                            if let Err(err) =
                                                persist_app_lock_config(&self.app_lock_config)
                                            {
                                                self.app_lock_ui.settings_error = Some(format!(
                                                    "Không thể lưu app_lock.json: {err}"
                                                ));
                                            } else {
                                                self.app_lock_ui.reset_settings_drafts();
                                                self.show_toast("Đã đổi mã khoá ứng dụng");
                                            }
                                        }
                                        Ok(ChangePasscodeOutcome::InvalidNew(msg)) => {
                                            self.app_lock_ui.settings_error =
                                                Some(msg.to_string());
                                        }
                                        Ok(ChangePasscodeOutcome::VerifyFailed(outcome)) => {
                                            let _ = persist_app_lock_config(&self.app_lock_config);
                                            self.app_lock_ui.draft_current.clear();
                                            self.app_lock_ui.settings_error =
                                                Some(format_verify_error(outcome));
                                        }
                                        Err(err) => {
                                            self.app_lock_ui.settings_error =
                                                Some(format!("Không thể đổi mã khoá: {err}"));
                                        }
                                    }
                                }
                            }
                            if ui
                                .button("Huỷ")
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked()
                            {
                                self.app_lock_ui.reset_settings_drafts();
                            }
                        });
                    } else if self.app_lock_ui.settings_action == AppLockSettingsAction::Disabling
                    {
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("Nhập mã khoá hiện tại để tắt Khoá bảo mật:")
                                .color(pal.text_secondary)
                                .size(12.4),
                        );
                        ui.add_space(6.0);
                        let (_, enter_pressed) = render_passcode_field(
                            ui,
                            pal,
                            "app_lock_disable_current",
                            &mut self.app_lock_ui.draft_current,
                            self.app_lock_config.mode,
                            "Nhập mã khoá hiện tại",
                            false,
                        );
                        if let Some(ref err) = self.app_lock_ui.settings_error {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(err)
                                    .color(pal.danger_text)
                                    .size(12.2),
                            );
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let disable_btn = egui::Button::new(
                                RichText::new("Xác nhận tắt")
                                    .color(pal.primary_fg)
                                    .size(12.5)
                                    .strong(),
                            )
                            .fill(pal.danger)
                            .rounding(Rounding::same(6.0));
                            let clicked = ui
                                .add(disable_btn)
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked();
                            if clicked || enter_pressed {
                                let now = crate::login::unix_now();
                                let outcome = self
                                    .app_lock_config
                                    .verify_attempt(&self.app_lock_ui.draft_current, now);
                                self.app_lock_ui.draft_current.clear();
                                match outcome {
                                    VerifyOutcome::Unlocked => {
                                        if let Err(err) = AppLockConfig::remove_default() {
                                            crate::logger::log_error(
                                                "app_lock",
                                                &err.to_string(),
                                            );
                                            self.app_lock_ui.settings_error = Some(format!(
                                                "Không thể xoá app_lock.json: {err}"
                                            ));
                                        } else {
                                            self.app_lock_config = AppLockConfig::default();
                                            set_idle_lock_timeout_secs(0);
                                            self.app_lock_ui.corrupted_config = false;
                                            self.app_lock_ui.reset_settings_drafts();
                                            self.show_toast("Đã tắt khoá bảo mật");
                                        }
                                    }
                                    VerifyOutcome::Wrong { .. }
                                    | VerifyOutcome::LockedOut { .. } => {
                                        let _ = persist_app_lock_config(&self.app_lock_config);
                                        self.app_lock_ui.settings_error =
                                            Some(format_verify_error(outcome));
                                    }
                                }
                            }
                            if ui
                                .button("Huỷ")
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked()
                            {
                                self.app_lock_ui.reset_settings_drafts();
                            }
                        });
                    }

                    if self.app_lock_config.enabled {
                        ui.add_space(10.0);
                        ui.separator();
                        ui.add_space(8.0);
                        let mut prefs_changed = false;

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Tự khoá khi máy ngủ (sleep)")
                                    .color(pal.text_primary)
                                    .size(13.0),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if render_toggle_switch(
                                    ui,
                                    &mut self.app_lock_config.lock_on_sleep,
                                    pal,
                                )
                                .changed()
                                {
                                    prefs_changed = true;
                                }
                            });
                        });
                        ui.add_space(8.0);

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Tự khoá khi không thao tác")
                                    .color(pal.text_primary)
                                    .size(13.0),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let prev_idle = self.app_lock_config.idle_timeout_secs;
                                egui::ComboBox::from_id_salt("app_lock_idle_timeout_combo")
                                    .selected_text(idle_timeout_label(prev_idle))
                                    .width(130.0)
                                    .show_ui(ui, |ui| {
                                        for &preset in &IDLE_PRESETS_SECS {
                                            ui.selectable_value(
                                                &mut self.app_lock_config.idle_timeout_secs,
                                                preset,
                                                idle_timeout_label(preset),
                                            );
                                        }
                                    });
                                if self.app_lock_config.idle_timeout_secs != prev_idle {
                                    prefs_changed = true;
                                }
                            });
                        });
                        ui.add_space(8.0);

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Ẩn nội dung thông báo khi đang khoá")
                                    .color(pal.text_primary)
                                    .size(13.0),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if render_toggle_switch(
                                    ui,
                                    &mut self.app_lock_config.hide_notifications_when_locked,
                                    pal,
                                )
                                .changed()
                                {
                                    prefs_changed = true;
                                }
                            });
                        });

                        if prefs_changed {
                            let _ = persist_app_lock_config(&self.app_lock_config);
                            set_idle_lock_timeout_secs(self.app_lock_config.idle_timeout_secs);
                        }
                    }
                }
            });

        lock_now_requested
    }
}

#[cfg(test)]
mod tests {
    use super::{
        format_verify_error, idle_timeout_label, sanitize_passcode_draft, sanitize_pin4_input,
    };
    use crate::app_lock::{PasscodeMode, VerifyOutcome, IDLE_PRESETS_SECS};

    #[test]
    fn pin4_sanitizer_and_idle_preset_labels() {
        assert_eq!(sanitize_pin4_input("1a2b345"), "1234");
        assert_eq!(sanitize_pin4_input("١٢34"), "34");
        assert_eq!(sanitize_pin4_input(""), "");

        let labels: Vec<&str> = IDLE_PRESETS_SECS
            .iter()
            .copied()
            .map(idle_timeout_label)
            .collect();
        assert_eq!(labels, vec!["Tắt", "5 phút", "15 phút", "30 phút"]);
    }

    #[test]
    fn custom_passcode_sanitizer_caps_unicode_scalars_and_formats_errors() {
        let forty_accents = "á".repeat(40);
        let trimmed = sanitize_passcode_draft(PasscodeMode::Custom, &forty_accents);
        assert_eq!(trimmed.chars().count(), 32);

        assert!(format_verify_error(VerifyOutcome::Wrong {
            remaining_attempts: 3
        })
        .contains("3"));
        assert!(format_verify_error(VerifyOutcome::LockedOut { remaining_secs: 25 }).contains("25"));
    }
}
