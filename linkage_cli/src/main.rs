use std::process::Command;

use clap::{App, Arg};
use libc;
use ovpnfile::{self, ConfigDirective};

use linkage_firewall::firewalls::{FirewallException, FirewallExceptionProtocol};
use linkage_leaks::{dns_test, get_infos};
use std::net::IpAddr;
use std::str::FromStr;
use std::ptr::null;
use std::alloc::alloc;

fn main() {
    let matches = App::new("Linkage")
        .version("0.0.1")
        .author("BitJerkers not incorporated")
        .about("A VPN Manager")
        // Creates the main Argument which should be the openvpn config file
        .arg(Arg::with_name("config")
            // You need to passs a config to execute this program, we may change this later on
            .required(true)
            .short("c")
            .long("config")
            .value_name("FILE"))
        .get_matches()
        ;


    // TODO: Error Handling
    // Try to open the config file
    let configfile = matches.value_of("config").unwrap_or_else(||{"Couldn't get the config file"});
    println!("The config file is: {}", configfile);
    let file = std::fs::File::open(configfile).unwrap();

    // Parse the config file using ovpnfile
    let parsed_file = ovpnfile::parse(file).unwrap();

    let mut remotes: Vec<String> = Vec::new();
    let mut protocol=FirewallExceptionProtocol::UDP;
    for d in parsed_file.directives() {
        match d {
            ConfigDirective::Proto{p:proto} => protocol = FirewallExceptionProtocol::from_str(&proto).unwrap_or_else(|_| { "Invalid Protocol" }.parse().unwrap()),
            _ => (),
        };
    }
    for d in parsed_file.directives() {
        match d {
            ConfigDirective::Remote { host: h, port: port,  proto: proto} => FirewallException::new(h.parse().unwrap(),port.unwrap().parse().unwrap(),
                                                                                                    {match proto{
                                                                                                        None => protocol,
                                                                                                        Some(f) =>f.parse().unwrap()}
            }),
            _ => linkage_firewall::firewalls::FirewallException::new("127.0.0.1".parse().unwrap(), 0, FirewallExceptionProtocol::TCP),
        };
    }


    /*
    // TODO: Check if Windows or Linux
    let output = Command::new("openvpn")
        .arg(configfile);
    */
    rootcheck();


    println!("{:?}", remotes);
    let infos = get_infos();
    println!("{:?}", infos);
    let dns_servers = dns_test();
    println!("{:?}, {}", dns_servers, dns_servers.len());
}

/// Checks if the program is being run as root, else it panics and exits
fn rootcheck() {
    unsafe {
        let uid = libc::geteuid();
        if uid != 0 {
            // TODO: Ask for root permission
            //panic!("Please run this program as root!")
        }
    }
}
