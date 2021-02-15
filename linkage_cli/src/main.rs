use clap::{Arg, App};
use ovpnfile::{self, ConfigDirective};
use linkage_leaks;
use linkage_leaks::dns_test;
use libc;
use std::process::Command;


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
    let file = std::fs::File::open(configfile).unwrap();
    let parsed_file = ovpnfile::parse(file).unwrap();
    let mut remotes:Vec<String> = Vec::new();
    for d in parsed_file.directives() {
        match d {
            ConfigDirective::Remote {host: h, ..} => remotes.push(h),
            _ => (),
        }
    }

    rootcheck();


    println!("{:?}", remotes);
    let _ip = linkage_leaks::get_ip();
    let dns_servers = dns_test();
    println!("{:?}, {}",dns_servers, dns_servers.len());

}

/// Checks if the program is being run as root, else it panics and exits
fn rootcheck(){
    unsafe {
       let uid = libc::geteuid();
        if uid !=0 {
            panic!("Please run this program as root!")
        }
    }
}
