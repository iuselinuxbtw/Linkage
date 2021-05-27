mod app;
mod error;
mod exception_gui;

fn main() {
    let app = app::LinkageGUI::default();
    eframe::run_native(Box::new(app), Default::default());
}
