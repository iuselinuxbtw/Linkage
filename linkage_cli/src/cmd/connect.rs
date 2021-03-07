//! Contains the `connect` subcommand.

use crate::error::{CliError, CliResult};
use clap::ArgMatches;
#[cfg(windows)]
use is_elevated::is_elevated;
#[cfg(unix)]
use libc;
use linkage_config::utils::get_home_dir;
use linkage_config::{open_config, Config};
use linkage_firewall::get_backends;
use linkage_firewall::FirewallBackend;
use linkage_firewall::FirewallException;
use linkage_leaks::{dns_test, get_ip_information};
use ovpnfile::{self, ConfigDirective as OvpnConfigDirective};
use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn cmd_connect(matches: &ArgMatches) -> CliResult<()> {
    // Administrator privileges are required
    root_check()?;

    // Get the Ip Addresses and DNS Servers before the VPN connection
    let ip_address_before = get_ip_information()?;
    let dns_addresses_before =
        dns_test(matches.value_of("dns-requests").unwrap().parse().unwrap())?;

    // This should not be None
    let config_file_path = matches.value_of("file").unwrap();
    println!("Using configuration file {}", config_file_path);
    let config_file = File::open(config_file_path)?;

    // Get the exceptions from the configuration file
    let mut exceptions = parse_configuration_file(config_file)?;

    // Add the exceptions from the exception-file
    let exception_config_path: PathBuf = matches
        .value_of("config")
        .unwrap_or(
            get_home_dir()
                .join(".config/linkage/config")
                .to_str()
                .unwrap(),
        )
        .parse()
        .unwrap();
    if exception_config_path.exists() {
        let mut additional_exception: Config = open_config(exception_config_path).unwrap();
        exceptions.append(&mut additional_exception.firewall.exception);
    }

    // The first backend is currently iptables, will be made more modular in the next versions
    let firewall_backend = get_backends().first().unwrap();
    if !firewall_backend.is_available()? {
        return Err(CliError::FirewallBackendNotAvailable);
    }

    firewall_backend.on_pre_connect(&exceptions)?;

    let c: Child = Command::new("openvpn")
        .arg(config_file_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let process_id = c.id();
    let mut stdout = c.stdout.unwrap();
    let mut buffer = [0; 2048];

    let regex = Regex::new(r"net_iface_up: set (tun[0-9]+) up").unwrap();

    // TODO: Error handling
    // This loop should probably be limited to about 30 seconds
    let interface_name = loop {
        stdout.read(&mut buffer)?;
        let i = String::from_utf8_lossy(&buffer);
        let matches = regex.captures(&i);
        if let Some(matches) = matches {
            let m = matches
                .get(1)
                .expect("couldn't get the interface from openvpn");
            break m.as_str().to_string();
        }
    };

    // After connect
    firewall_backend.on_post_connect(&interface_name)?;

    // Get the ip addresses after the connection is established.
    let ip_address_after = get_ip_information()?;
    let dns_addresses_after = dns_test(matches.value_of("dns-requests").unwrap().parse().unwrap())?;
    let matching_dns_addresses: Vec<&IpAddr> = dns_addresses_after
        .iter()
        .filter(|&e| dns_addresses_before.contains(e))
        .collect();
    if matching_dns_addresses.len() > 0 {
        println!("Detected DNS-Leak, disconnecting...");
        return disconnect(firewall_backend, Some(process_id));
    }
    let matching_ip_addresses = ip_address_after.0.ip == ip_address_before.0.ip
        || ip_address_after.1.ip == ip_address_before.1.ip;
    if matching_ip_addresses {
        println!("Detected Ip-leak, disconnecting...");
        return disconnect(firewall_backend, Some(process_id));
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst)).unwrap();

    println!("Waiting...");
    while running.load(Ordering::SeqCst) {}
    disconnect(firewall_backend, Some(process_id))?;

    Ok(())
}

/// Checks if the program is running as root.
fn root_check() -> CliResult<()> {
    if cfg!(windows) {
        #[cfg(windows)]
        // TODO: Ask for root permission. Windows support will be introduced in a later release though, so not high priority
        if !is_elevated() {
            panic!("The Program is not running as an administrator, please run it as admin");
        }
    }
    // We're assuming all other Platforms are Unix-based
    else {
        #[cfg(unix)]
        unsafe {
            let uid = libc::getuid();
            if uid != 0 {
                // TODO: Ask for root permission
                return Err(CliError::RootRequired);
            }
        }
    }

    Ok(())
}

fn disconnect(
    firewall_backend: &Box<dyn FirewallBackend + Sync>,
    process_id: Option<u32>,
) -> CliResult<()> {
    println!("Exiting...");
    // When disconnecting
    firewall_backend.on_disconnect()?;

    if let Some(id) = process_id {
        kill_process(id);
    }

    Ok(())
}

/// Kills a process with the given process id
fn kill_process(process_id: u32) {
    // Maybe do this with Child.kill()
    unsafe {
        libc::kill(process_id as i32, libc::SIGTERM);
    }
}

/// Parses the supplied configuration file using ovpnfile.
fn parse_configuration_file(f: File) -> CliResult<Vec<FirewallException>> {
    // TODO: Make this more modular to support other VPN applications, not only OpenVPN.
    let parsed_file = ovpnfile::parse(f).map_err(|_| CliError::OvpnFile)?;

    // Get the default settings
    let mut default_protocol: Option<String> = None;
    for d in parsed_file.directives() {
        match d {
            OvpnConfigDirective::Proto { p } => {
                default_protocol = Some(p);
            }
            _ => (),
        }
    }

    // Create the firewall exceptions
    let mut exceptions: Vec<FirewallException> = Vec::new();
    for d in parsed_file.directives() {
        match d {
            OvpnConfigDirective::Remote { host, port, proto } => {
                // TODO: Handle the unwrap() calls here
                let default_protocol_clone = default_protocol.clone();
                exceptions.push(FirewallException::new(
                    host.parse()?,
                    port.unwrap().parse()?,
                    proto
                        .unwrap_or_else(|| default_protocol_clone.unwrap())
                        .parse()?,
                ));
            }
            _ => (),
        }
    }

    Ok(exceptions)
}
