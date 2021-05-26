use std::path::PathBuf;

use eframe::egui::CtxRef;
use eframe::epi::Frame;
use eframe::{egui, epi};
use native_dialog::FileDialog;

use linkage_cli;
use linkage_cli::cmd::connect::{cmd_connect, Configuration};

use crate::exception_gui;

pub struct LinkageGUI {
    label: String,
    file: PathBuf,
    requests: u32,
    config: PathBuf,
}

impl Default for LinkageGUI {
    fn default() -> Self {
        Self {
            label: "Linkage".to_owned(),
            file: PathBuf::new(),
            requests: 100,
            config: Default::default(),
        }
    }
}

impl epi::App for LinkageGUI {
    fn update(&mut self, ctx: &CtxRef, frame: &mut Frame<'_>) {
        let LinkageGUI {
            label,
            file,
            requests,
            config,
        } = self;

        egui::CentralPanel::default().show(ctx, |inner| {
            inner.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                // Get the file string if we have a given file
                let file_string: Option<String> = if !file.is_file() {
                    None
                } else {
                    // We can safely unwrap here since we checked if it is none
                    Some(file.to_str().unwrap().parse().unwrap())
                };
                // A button for selecting an OpenVPN file. Opens a file_dialog to choose the file
                if ui
                    .button(
                        // If we don't have a file, the user should choose a new file.
                        if file_string.is_none() {
                            "Choose OpenVPN file".to_string()
                        } else {
                            // We can safely unwrap here since we checked if it is none
                            format!("Selected: {}", file_string.unwrap())
                        },
                    )
                    .clicked()
                {
                    let file_dialog = FileDialog::new()
                        .set_location("~")
                        .add_filter("OpenVPN file(.ovpn, .conf)", &["ovpn", "conf"])
                        .show_open_single_file()
                        .unwrap();
                    if let Some(ovpnfile) = file_dialog {
                        *file = ovpnfile;
                    }
                }
                // DNS Request section
                ui.horizontal(|ui| {
                    ui.label("Dns Requests");
                    ui.add(egui::Slider::new(requests, 10..=500)).on_hover_text(
                        "The Amount of DNS Tests to perform (higher is better, but takes longer)",
                    );
                });
                ui.separator();
                // Button Section
                ui.horizontal(|ui| {
                    if ui.button("Manage Exceptions").clicked() {
                        let exceptions = exception_gui::Exceptions::default();
                        eframe::run_native(Box::new(exceptions), Default::default());
                    }
                    if ui.button("Connect").clicked() {
                        cmd_connect(Configuration {
                            dns_requests: *requests,
                            file: file.clone(),
                            config: config.clone(),
                        });
                    }
                });
            });
        });
    }

    fn name(&self) -> &str {
        "Linkage GUI"
    }
}
