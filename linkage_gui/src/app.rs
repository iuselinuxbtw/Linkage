use std::path::{Path, PathBuf};

use eframe::egui::CtxRef;
use eframe::epi::Frame;
use eframe::{egui, epi};
use native_dialog::{FileDialog, MessageDialog, MessageType};

use linkage_cli;
use linkage_cli::cmd::connect::cmd_connect;

pub struct LinkageGUI {
    label: String,
    file: PathBuf,
    arguments: Vec<String>,
    requests: u16,
}

impl Default for LinkageGUI {
    fn default() -> Self {
        Self {
            label: "Linkage".to_owned(),
            file: PathBuf::new(),
            arguments: vec![],
            requests: 100,
        }
    }
}

impl epi::App for LinkageGUI {
    fn update(&mut self, ctx: &CtxRef, frame: &mut Frame<'_>) {
        let LinkageGUI {
            label,
            file,
            arguments,
            requests,
        } = self;

        egui::CentralPanel::default().show(ctx, |inner| {
            inner.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                ui.heading("Select an OpenVPN file...");
                ui.separator();
                if ui.button("Choose an OpenVPN file...").clicked() {
                    let file_dialog = FileDialog::new()
                        .set_location("~")
                        .add_filter("OpenVPN file(.ovpn)", &[".ovpn"])
                        .show_open_single_file()
                        .unwrap();
                    if let Some(ovpnfile) = file_dialog {
                        *file = ovpnfile;
                    }
                }
                ui.add(doc_link_label(
                    "Dns Requests",
                    "The Amount of DNS Tests to perform(higher is better, but takes longer",
                ));
                ui.add(egui::Slider::new(requests, 10..=500));

                ui.separator();
                if ui.button("Connect").clicked() {
                    // TODO: Use the user-given values
                    cmd_connect(ArgMatches);
                    asdasd
                }
            });
        });
    }

    fn name(&self) -> &str {
        "Linkage GUI"
    }
}

fn doc_link_label<'a>(title: &'a str, search_term: &'a str) -> impl egui::Widget + 'a {
    let label = format!("{}:", title);
    let url = format!("https://docs.rs/egui?search={}", search_term);
    move |ui: &mut egui::Ui| {
        ui.hyperlink_to(label, url).on_hover_ui(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Search egui docs for");
                ui.code(search_term);
            });
        })
    }
}
