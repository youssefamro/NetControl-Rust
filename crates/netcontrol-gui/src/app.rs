//! The NetControl application window (egui view over [`UiState`]).

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use egui::{Align, Color32, FontId, Layout, RichText, Sense, Stroke, Vec2};
use egui_extras::{Column, TableBuilder};

use crate::state::{DeviceRow, Mode, StatusLevel, UiState};
use crate::{strings, theme};

/// A deferred table action, applied after rendering to avoid borrow conflicts.
enum Action {
    SetLimit(Ipv4Addr, i32),
    ToggleRedirect(Ipv4Addr),
    ToggleBlock(Ipv4Addr),
}

pub struct NetControlApp {
    state: UiState,
    last_tick: Instant,
    tick_interval: Duration,
}

impl NetControlApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        NetControlApp {
            state: UiState::new(),
            last_tick: Instant::now(),
            tick_interval: Duration::from_millis(900),
        }
    }
}

impl eframe::App for NetControlApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme::APP_BACKGROUND.to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_tick.elapsed() >= self.tick_interval {
            self.state.demo_tick(self.last_tick.elapsed().as_secs_f64());
            self.state.poll_capture_health();
            self.last_tick = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(250));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(theme::APP_BACKGROUND)
                    .inner_margin(16.0),
            )
            .show(ctx, |ui| {
                self.banners(ui);
                self.toolbar(ui);
                ui.add_space(12.0);
                if self.state.mode() == Mode::Live {
                    self.live_panel(ui);
                    ui.add_space(10.0);
                }
                self.kpi_cards(ui);
                ui.add_space(10.0);
                self.throttle_bar(ui);
                ui.add_space(10.0);
                self.device_table(ui);
                ui.add_space(10.0);
                self.footer(ui);
            });
    }
}

impl NetControlApp {
    // ── Banners ────────────────────────────────────────────────────

    fn banners(&mut self, ui: &mut egui::Ui) {
        if self.state.mode() == Mode::Demonstration {
            banner(
                ui,
                theme::ACCENT_WARNING_BG,
                theme::ACCENT_WARNING,
                strings::DEMO_BANNER_TITLE,
                strings::DEMO_BANNER_BODY,
            );
            ui.add_space(8.0);
        }

        if self.state.elevation_warning() {
            banner(
                ui,
                theme::ACCENT_DANGER_BG,
                theme::ACCENT_DANGER,
                strings::ELEVATION_TITLE,
                self.state.elevation_guidance(),
            );
            ui.add_space(8.0);
        }

        if let Some(err) = self.state.last_error() {
            banner(
                ui,
                theme::ACCENT_DANGER_BG,
                theme::ACCENT_DANGER,
                "Error",
                err,
            );
            ui.add_space(8.0);
        }

        if self.state.disclaimer_visible() {
            theme::card()
                .fill(theme::CARD_ELEVATED)
                .rounding(8.0)
                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        if ui
                            .add_sized(
                                [22.0, 22.0],
                                egui::Button::new(RichText::new("✕").color(theme::TEXT_MUTED))
                                    .fill(Color32::TRANSPARENT)
                                    .stroke(Stroke::NONE),
                            )
                            .on_hover_text("Dismiss notice")
                            .clicked()
                        {
                            self.state.dismiss_disclaimer();
                        }
                        ui.label(
                            RichText::new(strings::DISCLAIMER_BODY)
                                .color(theme::TEXT_SECONDARY)
                                .size(11.5),
                        );
                    });
                });
            ui.add_space(8.0);
        }
    }

    // ── Toolbar ────────────────────────────────────────────────────

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(strings::APP_NAME)
                            .color(theme::TEXT_PRIMARY)
                            .strong()
                            .size(15.0),
                    );
                    ui.label(
                        RichText::new(strings::APP_SUBTITLE)
                            .color(theme::TEXT_MUTED)
                            .size(11.0),
                    );
                });

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // Start / Stop.
                    let running = self.state.capture_running();
                    let (label, fill) = if running {
                        (format!("■ {}", strings::STOP_BUTTON), theme::CARD_ELEVATED)
                    } else {
                        (
                            format!("▶ {}", strings::START_BUTTON),
                            theme::ACCENT_PRIMARY,
                        )
                    };
                    if ui
                        .add_sized(
                            [92.0, 34.0],
                            egui::Button::new(RichText::new(label).color(Color32::WHITE).strong())
                                .fill(fill)
                                .stroke(Stroke::new(1.0_f32, theme::BORDER_DEFAULT)),
                        )
                        .clicked()
                    {
                        if running {
                            self.state.stop_capture();
                        } else {
                            self.state.start_capture();
                        }
                    }

                    // Interface selector.
                    let sel = self.state.selected_interface();
                    let current = self
                        .state
                        .interfaces()
                        .get(sel)
                        .map(|i| i.display.clone())
                        .unwrap_or_else(|| "—".to_string());
                    let mut new_sel = sel;
                    egui::ComboBox::from_id_salt("iface")
                        .width(240.0)
                        .selected_text(RichText::new(current).color(theme::TEXT_PRIMARY).size(12.0))
                        .show_ui(ui, |ui| {
                            for (i, iface) in self.state.interfaces().iter().enumerate() {
                                ui.selectable_value(&mut new_sel, i, &iface.display);
                            }
                        });
                    if new_sel != sel {
                        self.state.select_interface(new_sel);
                    }
                    ui.label(
                        RichText::new(strings::INTERFACE_LABEL)
                            .color(theme::TEXT_SECONDARY)
                            .strong()
                            .size(12.5),
                    );

                    // Mode toggle.
                    for mode in [Mode::Demonstration, Mode::Live] {
                        let selected = self.state.mode() == mode;
                        let fill = if selected {
                            theme::ACCENT_PRIMARY
                        } else {
                            theme::CARD_ELEVATED
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(mode.label())
                                        .color(if selected {
                                            Color32::WHITE
                                        } else {
                                            theme::TEXT_SECONDARY
                                        })
                                        .size(12.0),
                                )
                                .fill(fill)
                                .stroke(Stroke::new(1.0_f32, theme::BORDER_DEFAULT)),
                            )
                            .clicked()
                        {
                            self.state.set_mode(mode);
                        }
                    }
                });
            });
        });
    }

    // ── KPI cards ──────────────────────────────────────────────────

    fn kpi_cards(&mut self, ui: &mut egui::Ui) {
        let (total, intercepted, blocked, gateway) = self.state.dashboard();
        let spacing = 6.0;
        let card_w = (ui.available_width() - spacing * 3.0) / 4.0;
        ui.horizontal(|ui| {
            kpi_card(
                ui,
                card_w,
                strings::KPI_TOTAL,
                &total.to_string(),
                theme::TEXT_PRIMARY,
            );
            kpi_card(
                ui,
                card_w,
                strings::KPI_SPOOF_FLAGGED,
                &intercepted.to_string(),
                theme::ACCENT_CYAN,
            );
            kpi_card(
                ui,
                card_w,
                strings::KPI_BLOCK_FLAGGED,
                &blocked.to_string(),
                theme::ACCENT_DANGER,
            );
            kpi_card(
                ui,
                card_w,
                strings::KPI_GATEWAY,
                &gateway,
                theme::ACCENT_WARNING,
            );
        });
    }

    // ── Throttle status bar ────────────────────────────────────────

    fn throttle_bar(&mut self, ui: &mut egui::Ui) {
        let summary = self.state.throttle_summary();
        theme::badge(theme::CARD_BACKGROUND, theme::BORDER_DEFAULT)
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(12.0, 7.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(strings::THROTTLE_LABEL)
                            .color(theme::TEXT_SECONDARY)
                            .strong()
                            .size(11.5),
                    );
                    ui.label(
                        RichText::new(&summary.kind)
                            .color(theme::TEXT_PRIMARY)
                            .size(11.5),
                    );
                    ui.label(RichText::new("·").color(theme::TEXT_MUTED));
                    ui.label(
                        RichText::new(&summary.status)
                            .color(theme::ACCENT_WARNING)
                            .strong()
                            .size(11.5),
                    );
                })
                .response
                .on_hover_text(&summary.explanation);
            });
    }

    // ── Live diagnostics panel ─────────────────────────────────────

    fn live_panel(&mut self, ui: &mut egui::Ui) {
        let d = self.state.live_diagnostics();
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new("LIVE MODE — PASSIVE LISTENING")
                    .color(theme::ACCENT_CYAN)
                    .strong()
                    .size(12.0),
            );
            ui.add_space(2.0);

            kv(ui, "Interface", &d.interface);
            kv_flag(
                ui,
                "Live capture built in",
                d.capture_supported,
                &d.support_note,
            );
            kv(ui, "Capture runtime", &d.runtime_note);
            kv_flag(ui, "Capture privileges", d.elevated, &d.permission_note);
            kv_flag(ui, "Passive listening running", d.capture_running, "");
            if let Some(dev) = &d.capture_device {
                kv(ui, "Capture device", dev);
            }
            if let Some(err) = &d.capture_error {
                ui.label(
                    RichText::new(format!("Last capture error: {err}"))
                        .color(theme::ACCENT_DANGER)
                        .size(11.0),
                );
            }
            kv(ui, "Devices discovered", &d.devices_discovered.to_string());

            ui.add_space(2.0);
            ui.label(
                RichText::new(&d.mode_note)
                    .color(theme::TEXT_SECONDARY)
                    .size(11.0),
            );
            if let Some(reason) = &d.no_devices_reason {
                ui.label(
                    RichText::new(format!("Why no devices: {reason}"))
                        .color(theme::ACCENT_WARNING)
                        .size(11.0),
                );
            }

            ui.add_space(4.0);
            ui.label(
                RichText::new("Not implemented / not operational:")
                    .color(theme::TEXT_MUTED)
                    .strong()
                    .size(10.5),
            );
            for feat in &d.unsupported_features {
                ui.label(
                    RichText::new(format!("  • {feat}"))
                        .color(theme::TEXT_MUTED)
                        .size(10.5),
                );
            }
        });
    }

    // ── Device table ───────────────────────────────────────────────

    fn device_table(&mut self, ui: &mut egui::Ui) {
        let rows = self.state.device_rows();
        let empty_body = if self.state.mode() == Mode::Live {
            strings::EMPTY_BODY_LIVE
        } else {
            strings::EMPTY_BODY_DEMO
        };
        let mut actions: Vec<Action> = Vec::new();

        egui::Frame::none()
            .fill(theme::CARD_BACKGROUND)
            .stroke(Stroke::new(1.0_f32, theme::BORDER_DEFAULT))
            .rounding(8.0)
            .show(ui, |ui| {
                ui.set_min_height(ui.available_height() - 60.0);

                if rows.is_empty() {
                    empty_state(ui, empty_body);
                    return;
                }

                let mono = FontId::monospace(12.0);
                TableBuilder::new(ui)
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .column(Column::initial(108.0).at_least(90.0))
                    .column(Column::initial(140.0).at_least(120.0))
                    .column(Column::remainder().at_least(180.0))
                    .column(Column::initial(96.0).at_least(80.0))
                    .column(Column::initial(96.0).at_least(80.0))
                    .column(Column::initial(90.0).at_least(78.0))
                    .column(Column::initial(52.0))
                    .column(Column::initial(52.0))
                    .header(34.0, |mut header| {
                        let cols: [(&str, Option<&str>); 8] = [
                            (strings::COL_IP, None),
                            (strings::COL_MAC, None),
                            (strings::COL_DEVICE, None),
                            (strings::COL_DOWNLOAD, None),
                            (strings::COL_UPLOAD, None),
                            (strings::COL_CAP, Some(strings::TIP_CAP)),
                            (strings::COL_SPOOF, Some(strings::TIP_SPOOF)),
                            (strings::COL_BLOCK, Some(strings::TIP_BLOCK)),
                        ];
                        for (title, tip) in cols {
                            header.col(|ui| {
                                let resp = ui.label(
                                    RichText::new(title)
                                        .color(theme::TEXT_SECONDARY)
                                        .strong()
                                        .size(11.5),
                                );
                                if let Some(tip) = tip {
                                    resp.on_hover_text(tip);
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(40.0, rows.len(), |mut row| {
                            let r = &rows[row.index()];
                            render_row(&mut row, r, &mono, &mut actions);
                        });
                    });
            });

        for action in actions {
            match action {
                Action::SetLimit(ip, v) => self.state.set_bandwidth_limit(ip, v),
                Action::ToggleRedirect(ip) => self.state.toggle_redirect(ip),
                Action::ToggleBlock(ip) => self.state.toggle_block(ip),
            }
        }
    }

    // ── Footer ─────────────────────────────────────────────────────

    fn footer(&mut self, ui: &mut egui::Ui) {
        let (text, level) = self.state.status();
        let dot = match level {
            StatusLevel::Success => theme::ACCENT_SUCCESS,
            StatusLevel::Info => theme::ACCENT_CYAN,
            StatusLevel::Warning => theme::ACCENT_WARNING,
            StatusLevel::Error => theme::ACCENT_DANGER,
        };
        let text = text.to_string();
        let local = self.state.local_ip();
        let subnet = self.state.subnet_mask().to_string();

        ui.horizontal(|ui| {
            theme::badge(theme::CARD_BACKGROUND, theme::BORDER_DEFAULT)
                .rounding(14.0)
                .inner_margin(egui::Margin::symmetric(12.0, 5.0))
                .show(ui, |ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                    ui.painter().circle_filled(rect.center(), 4.0, dot);
                    ui.label(RichText::new(text).color(theme::TEXT_SECONDARY).size(12.0));
                });

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let mono = FontId::monospace(11.5);
                ui.label(
                    RichText::new(format!("Subnet: {subnet}"))
                        .font(mono.clone())
                        .color(theme::TEXT_MUTED),
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!("Local: {local}"))
                        .font(mono)
                        .color(theme::TEXT_MUTED),
                );
            });
        });
    }
}

// ── Free helpers ───────────────────────────────────────────────────

fn render_row(
    row: &mut egui_extras::TableRow<'_, '_>,
    r: &DeviceRow,
    mono: &FontId,
    actions: &mut Vec<Action>,
) {
    row.col(|ui| {
        ui.label(
            RichText::new(&r.ip_display)
                .font(mono.clone())
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
    });
    row.col(|ui| {
        ui.label(
            RichText::new(&r.mac)
                .font(mono.clone())
                .color(theme::TEXT_SECONDARY),
        );
    });
    row.col(|ui| {
        if r.is_gateway {
            role_badge(
                ui,
                "GATEWAY",
                theme::ACCENT_WARNING,
                theme::ACCENT_WARNING_BG,
            );
        }
        if r.is_local {
            role_badge(ui, "YOU", theme::ACCENT_CYAN, theme::ACCENT_CYAN_BG);
        }
        ui.label(
            RichText::new(&r.label)
                .color(theme::TEXT_PRIMARY)
                .size(12.5),
        )
        .on_hover_text(&r.label);
    });
    row.col(|ui| {
        speed_cell(
            ui,
            "↓",
            &r.download,
            theme::parse_hex(&r.download_hex),
            mono,
        )
    });
    row.col(|ui| speed_cell(ui, "↑", &r.upload, theme::parse_hex(&r.upload_hex), mono));
    row.col(|ui| {
        let mut cap = r.bandwidth_limit_kb;
        let resp = ui
            .add_enabled(
                r.throttling_enabled,
                egui::DragValue::new(&mut cap)
                    .speed(16.0)
                    .range(0..=1_048_576),
            )
            .on_hover_text(strings::TIP_CAP);
        if resp.changed() {
            actions.push(Action::SetLimit(r.ip, cap));
        }
    });
    row.col(|ui| {
        let mut on = r.redirect;
        if ui
            .add_enabled(r.can_control, egui::Checkbox::without_text(&mut on))
            .on_hover_text(strings::TIP_SPOOF)
            .changed()
        {
            actions.push(Action::ToggleRedirect(r.ip));
        }
    });
    row.col(|ui| {
        let mut on = r.block;
        if ui
            .add_enabled(r.can_control, egui::Checkbox::without_text(&mut on))
            .on_hover_text(strings::TIP_BLOCK)
            .changed()
        {
            actions.push(Action::ToggleBlock(r.ip));
        }
    });
}

/// A label: value row for the live diagnostics panel.
fn kv(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{label}:"))
                .color(theme::TEXT_MUTED)
                .size(11.0),
        );
        ui.label(RichText::new(value).color(theme::TEXT_PRIMARY).size(11.0));
    });
}

/// A label with a yes/no flag (green/red) and an optional note.
fn kv_flag(ui: &mut egui::Ui, label: &str, yes: bool, note: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{label}:"))
                .color(theme::TEXT_MUTED)
                .size(11.0),
        );
        let (text, color) = if yes {
            ("yes", theme::ACCENT_SUCCESS)
        } else {
            ("no", theme::ACCENT_DANGER)
        };
        ui.label(RichText::new(text).color(color).strong().size(11.0));
        if !note.is_empty() {
            ui.label(
                RichText::new(format!("— {note}"))
                    .color(theme::TEXT_SECONDARY)
                    .size(10.5),
            );
        }
    });
}

fn banner(ui: &mut egui::Ui, bg: Color32, accent: Color32, title: &str, body: &str) {
    theme::badge(bg, accent)
        .rounding(8.0)
        .inner_margin(egui::Margin::symmetric(12.0, 9.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(|ui| {
                ui.label(RichText::new(title).color(accent).strong().size(12.5));
                ui.label(RichText::new(body).color(theme::TEXT_SECONDARY).size(11.5));
            });
        });
}

fn kpi_card(ui: &mut egui::Ui, width: f32, label: &str, value: &str, value_color: Color32) {
    theme::card().show(ui, |ui| {
        ui.set_width(width - 28.0);
        ui.set_height(40.0);
        ui.vertical(|ui| {
            ui.label(
                RichText::new(label)
                    .color(theme::TEXT_MUTED)
                    .strong()
                    .size(10.5),
            );
            ui.label(RichText::new(value).color(value_color).strong().size(19.0));
        });
    });
}

fn role_badge(ui: &mut egui::Ui, text: &str, color: Color32, bg: Color32) {
    theme::badge(bg, color).show(ui, |ui| {
        ui.label(RichText::new(text).color(color).strong().size(9.0));
    });
}

fn speed_cell(ui: &mut egui::Ui, arrow: &str, value: &str, color: Color32, mono: &FontId) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.label(RichText::new(arrow).color(color).size(11.0));
        ui.label(
            RichText::new(value)
                .font(mono.clone())
                .color(color)
                .size(11.5),
        );
    });
}

fn empty_state(ui: &mut egui::Ui, body: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(50.0);
        ui.label(RichText::new("◎").color(theme::ACCENT_PRIMARY).size(40.0));
        ui.label(
            RichText::new(strings::EMPTY_TITLE)
                .color(theme::TEXT_PRIMARY)
                .strong()
                .size(15.0),
        );
        ui.label(RichText::new(body).color(theme::TEXT_SECONDARY).size(12.0));
        ui.add_space(50.0);
    });
}
