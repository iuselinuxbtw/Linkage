use eframe::egui::CtxRef;
use eframe::epi::Frame;
use eframe::{egui, epi};

use crate::error::ExceptionParseError;
use linkage_config::utils::get_config_dir;
use linkage_config::{open_config, Config, FirewallConfig};
use linkage_firewall::{FirewallException, FirewallExceptionProtocol};
use std::convert::TryInto;
use std::net::IpAddr;
use std::str::FromStr;

pub struct Exceptions {
    exception_list: Vec<GUIException>,
}

/// This struct is necessary because we need an intermediate struct between the
/// [`FirewallException`] and the frontend or we won't be able to edit anything in the UI.
#[derive(Debug, Clone)]
struct GUIException {
    ip_address: String,
    port: i32,
    protocol: String,
}

impl Default for GUIException {
    fn default() -> Self {
        GUIException {
            ip_address: "192.168.1.5".to_string(),
            port: 80,
            protocol: "TCP".to_string(),
        }
    }
}

impl From<FirewallException> for GUIException {
    fn from(fe: FirewallException) -> Self {
        GUIException {
            ip_address: fe.host.to_string(),
            port: fe.port as i32,
            protocol: fe.protocol.to_string(),
        }
    }
}

impl TryInto<FirewallException> for GUIException {
    type Error = ExceptionParseError;

    fn try_into(self) -> Result<FirewallException, Self::Error> {
        Ok(FirewallException {
            host: IpAddr::from_str(&self.ip_address)?,
            port: self.port as u16,
            protocol: match self.protocol.as_str() {
                "TCP" => FirewallExceptionProtocol::TCP,
                "UDP" => FirewallExceptionProtocol::UDP,
                //TODO: Return another Error here
                _ => return Err(ExceptionParseError::ProtocolParseError),
            },
        })
    }
}

impl Default for Exceptions {
    fn default() -> Self {
        // As a default, we need to load the default configuration
        let empty_config: Config = Config {
            firewall: FirewallConfig { exception: vec![] },
        };
        let config_file = open_config(get_config_dir().join("config")).unwrap_or(empty_config);
        let mut exception_list = vec![];
        for exception in config_file.firewall.exception {
            exception_list.push(GUIException::from(exception));
        }
        Exceptions { exception_list }
    }
}

impl From<Vec<FirewallException>> for Exceptions {
    fn from(_: Vec<FirewallException>) -> Self {
        todo!()
    }
}

impl epi::App for Exceptions {
    fn update(&mut self, ctx: &CtxRef, frame: &mut Frame<'_>) {
        let Exceptions { exception_list } = self;
        let mut c = 0;
        egui::CentralPanel::default().show(ctx, |ui| {
            // Button Section
            ui.horizontal(|ui| {
                // Add a new Exception
                if ui.button("Add").clicked() {
                    exception_list.push(GUIException::default());
                }
                // Save the changes
                if ui.button("Save").clicked() {
                    //TODO
                }
                // Revert Changes and close the window
                if ui.button("Cancel").clicked() {
                    //TODO
                }
            });
            ui.with_layout(egui::Layout::top_down(Default::default()), |ui| {
                for guiexc in exception_list {
                    c += 1;
                    // Make a new Dropdown Menu for every Exception with the title being for example "Exception 1"
                    ui.collapsing(format!("Exception {}", c), |exc_menu| {
                        exc_menu.horizontal(|ui| {
                            ui.label("IP Address:");
                            ui.text_edit_singleline(&mut guiexc.ip_address);
                        });
                        exc_menu.horizontal(|ui| {
                            ui.label("Port:");
                            ui.add(egui::Slider::new(&mut guiexc.port, 1..=65535))
                        });
                        exc_menu.horizontal(|ui| {
                            ui.label("Protocol:");
                            // Add a combobox
                            egui::ComboBox::from_label("")
                                // Display the current protocol
                                .selected_text(guiexc.protocol.to_string())
                                .show_ui(ui, |ui| {
                                    // Add every selectible Protocol
                                    ui.selectable_value(
                                        &mut guiexc.protocol,
                                        FirewallExceptionProtocol::TCP.to_string(),
                                        "TCP",
                                    );
                                    ui.selectable_value(
                                        &mut guiexc.protocol,
                                        FirewallExceptionProtocol::UDP.to_string(),
                                        "UDP",
                                    );
                                });

                            if ui.button("Delete").clicked() {
                                //TODO
                            }
                        });
                    });
                }
            });
        });
    }

    fn name(&self) -> &str {
        "Exception Management"
    }
}
