use clap::{Arg, App};
use ovpnfile::{self, ConfigDirective};

fn main() {
    let matches = App::new("Linkage")
        .version("0.0.1")
        .author("BitJerkers not incorporated")
        .about("A VPN Manager")
        // Creates the main Argument which should be the openvpn config file
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE"))
        .get_matches()
        ;
    // TODO: Error Handling
    let configfile = matches.value_of("config").unwrap();
    println!("The config file is: {}", configfile);
    let mut file = std::fs::File::open(configfile).unwrap();
    let parsed_file = ovpnfile::parse(file).unwrap();
    let mut remotes:Vec<String> = Vec::new();
    for d in parsed_file.directives() {
        match d {
            ConfigDirective::Remote {host: h, ..} => remotes.push(h),
            _ => (),
        }
    }
    println!("{:?}", remotes);


}
