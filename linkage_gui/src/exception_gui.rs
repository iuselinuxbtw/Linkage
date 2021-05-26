use std::borrow::BorrowMut;
use std::net::IpAddr;
use std::str::FromStr;

use eframe::egui::output::WidgetType::CollapsingHeader;
use eframe::egui::CtxRef;
use eframe::epi::Frame;
use eframe::{egui, epi};

use linkage_config::utils::get_config_dir;
use linkage_config::{open_config, Config, FirewallConfig};
use linkage_firewall::{FirewallException, FirewallExceptionProtocol};

pub struct Exceptions {
    exception_list: Vec<FirewallException>,
}

impl Default for Exceptions {
    fn default() -> Self {
        // As a default, we need to load the default configuration
        let empty_config: Config = Config {
            firewall: FirewallConfig { exception: vec![] },
        };
        let config_file = open_config(get_config_dir().join("config")).unwrap_or(empty_config);
        Exceptions {
            exception_list: config_file.firewall.exception,
        }
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
        egui::CentralPanel::default().show(ctx, |ui| {
            for exc in exception_list {
                // Make a new Dropdown Menu for every Exception with the title being the IP
                ui.collapsing(exc.get_host().to_string(), |exc_menu| {
                    exc_menu.horizontal(|ui| {
                        ui.label("IP Adress:");
                        //TODO: This can't work. We probably need a custom Widget
                        ui.text_edit_singleline(&mut exc.host.to_string());
                    });
                    exc_menu.horizontal(|ui| {
                        ui.label("Port:");
                        // TODO: Also won't work
                        ui.add(egui::Slider::new(exc.port.borrow_mut(), 1..=65535))
                    });
                    exc_menu.horizontal(|ui| {
                        ui.label("Protocol:");
                        // Add a combobox
                        egui::ComboBox::from_label("Choose Protocol")
                            // Display the current protocol
                            .selected_text(format!("{}", exc.protocol))
                            .show_ui(ui, |ui| {
                                // Add every selectible Protocol
                                ui.selectable_value(
                                    &mut exc.protocol,
                                    FirewallExceptionProtocol::TCP,
                                    "TCP",
                                );
                                ui.selectable_value(
                                    &mut exc.protocol,
                                    FirewallExceptionProtocol::UDP,
                                    "UDP",
                                );
                            });
                    });
                });
            }
            // Button Section
            ui.horizontal(|ui| {
                // Save the changes
                if ui.button("Save").clicked() {}
                // Add a new Exception
                if ui.button("Add").clicked() {}
                // Revert Changes and close the window
            });
        });
    }

    fn name(&self) -> &str {
        "Exception Management"
    }
}
