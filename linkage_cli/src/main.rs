use linkage_cli::entry;
use std::process::exit;
use colored::Colorize;

fn main() {
    let r = entry();
    if let Some(e) = r.err() {
        eprintln!("{} {}", "Error:".red(), e);
        exit(e.get_exit_code());
    }
}
