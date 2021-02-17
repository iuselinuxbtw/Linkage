use linkage_cli::entry;
use std::process::exit;

fn main() {
    let r = entry();
    if let Some(e) = r.err() {
        eprintln!("Error: {}", e);
        exit(e.get_exit_code());
    }
}
