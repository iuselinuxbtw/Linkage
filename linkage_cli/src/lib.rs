pub mod error;
pub(crate) mod consts;

use clap::{App as ClapApp, Arg as ClapArg, ArgMatches as ClapArgMatches};
use crate::error::{CliResult, CliError};
use std::fs::File;
use linkage_firewall::FirewallException;
use ovpnfile::{self, ConfigDirective as OvpnConfigDirective};
#[cfg(unix)]
use libc;
#[cfg(windows)]
use is_elevated::is_elevated;

/// The entry point of the cli application.
pub fn entry() -> CliResult<()> {
    // Administrator privileges are required
    root_check()?;

    let matches = get_config_matches();

    // This should not be None
    let config_file_path = matches.value_of("config").unwrap();
    println!("Using configuration file {}", config_file_path);
    let config_file = File::open(config_file_path)?;

    // Get the exceptions from the configuration file
    let exceptions = parse_configuration_file(config_file)?;

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
                return Err(CliError::RootRequired)
            }
        }
    }

    Ok(())
}

/// Parses the supplied configuration file using ovpnfile.
fn parse_configuration_file(f: File) -> CliResult<Vec<FirewallException>> {
    // TODO: Make this more modular to support other VPN applications, not only OpenVPN.
    let parsed_file = ovpnfile::parse(f).map_err(|_| {
        error::CliError::OvpnFile
    })?;

    // Get the default settings
    let mut default_protocol: Option<String> = None;
    for d in parsed_file.directives() {
        match d {
            OvpnConfigDirective::Proto {
                p,
            } => {
                default_protocol = Some(p);
            },
            _ => (),
        }
    }

    // Create the firewall exceptions
    let mut exceptions: Vec<FirewallException> = Vec::new();
    for d in parsed_file.directives() {
        match d {
            OvpnConfigDirective::Remote {
                host,
                port,
                proto,
            } => {
                // TODO: Handle the unwrap() calls here
                let default_protocol_clone = default_protocol.clone();
                exceptions.push(FirewallException::new(
                    host.parse()?, port.unwrap().parse()?,
                    proto.unwrap_or_else(|| default_protocol_clone.unwrap()).parse()?
                ));
            },
            _ => (),
        }
    }

    Ok(exceptions)
}

/// Returns the options that were supplied to the application.
fn get_config_matches<'a>() -> ClapArgMatches<'a> {
    ClapApp::new(consts::APP_NAME)
        .version(consts::APP_VERSION)
        .author(consts::APP_AUTHOR)
        .about(consts::APP_ABOUT)
        .arg(
            ClapArg::with_name("config")
                .required(true)
                .short("c")
                .long("config")
                .value_name("FILE")
        )
        .get_matches()
}