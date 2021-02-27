mod cmd;
pub(crate) mod consts;
pub mod error;

use crate::error::{CliError, CliResult};
use clap::{App as ClapApp, Arg as ClapArg, ArgMatches as ClapArgMatches};

/// The entry point of the cli application.
pub fn entry() -> CliResult<()> {
    let matches = get_config_matches();

    if let Some(matches) = matches.subcommand_matches("connect") {
        cmd::connect::cmd_connect(matches)?;
        Ok(())
    } else if let Some(matches) = matches.subcommand_matches("ipinfo") {
        cmd::ipinfo::cmd_ipinfo(matches)?;
        Ok(())
    } else {
        Err(CliError::SubcommandRequired)
    }
}

/// Returns the options that were supplied to the application.
fn get_config_matches<'a>() -> ClapArgMatches<'a> {
    ClapApp::new(consts::APP_NAME)
        .version(consts::APP_VERSION)
        .author(consts::APP_AUTHOR)
        .about(consts::APP_ABOUT)
        .subcommand(
            ClapApp::new("connect")
                .about("connects using the supplied config and does leak checking and prevention")
                .arg(
                    ClapArg::with_name("config")
                        .required(true)
                        .short("c")
                        .long("config")
                        .value_name("FILE"),
                )
                .arg(
                    ClapArg::with_name("dns-requests")
                        .help("Amount of requests to check for dns leaks")
                        .long_help("Sets the amount of DNS requests for leak-testing. More are more reliable but may take longer to check.")
                        .required(false)
                        .short("d")
                        .long("dns-requests")
                        .default_value("100")
                        .validator(|s| -> Result<(), String> {
                            match s.parse::<u32>() {
                                Ok(_) => Ok(()),
                                Err(_) => {
                                    Err("DNS requests must be a positive integer".to_string())
                                }
                            }
                        }),
                ),
        )
        .subcommand(
            ClapApp::new("ipinfo")
                .about("outputs ip information and does dns tests")
                .arg(
                    ClapArg::with_name("no-ip")
                        .help("Do not check ip address")
                        .long("no-ip")
                        .takes_value(false),
                )
                .arg(
                    ClapArg::with_name("no-ip4")
                        .help("Do not output ipv4 address information")
                        .long("no-ip4")
                        .takes_value(false),
                )
                .arg(
                    ClapArg::with_name("no-ip6")
                        .help("Do not output ipv6 address information")
                        .long("no-ip6")
                        .takes_value(false),
                )
                .arg(
                    ClapArg::with_name("no-dns")
                        .help("Do not run dns tests")
                        .long("no-dns")
                        .takes_value(false),
                ),
        )
        .get_matches()
}
