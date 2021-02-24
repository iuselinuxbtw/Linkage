pub(crate) mod consts;
pub mod error;
mod cmd;

use crate::error::CliResult;
use clap::{App as ClapApp, Arg as ClapArg, ArgMatches as ClapArgMatches};

/// The entry point of the cli application.
pub fn entry() -> CliResult<()> {
    let matches = get_config_matches();

    if let Some(matches) = matches.subcommand_matches("connect") {
        cmd::connect::cmd_connect(matches)?;
        Ok(())
    } else {
        Ok(())
    }
}

/// Returns the options that were supplied to the application.
fn get_config_matches<'a>() -> ClapArgMatches<'a> {
    ClapApp::new(consts::APP_NAME)
        .version(consts::APP_VERSION)
        .author(consts::APP_AUTHOR)
        .about(consts::APP_ABOUT)

        .subcommand(ClapApp::new("connect")
            .about("connects using the supplied config and does leak checking and prevention")
            .arg(ClapArg::with_name("config")
                .required(true)
                .short("c")
                .long("config")
                .value_name("FILE")))

        .subcommand(ClapApp::new("ipinfo")
            .about("outputs ip information for IPv4 and IPv6")
            .arg(ClapArg::with_name("no-ipv4")
                .help("Do not test IPv4")
                .long("no-ipv4")
                .takes_value(false))
            .arg(ClapArg::with_name("no-ipv6")
                .help("Do not test IPv6")
                .long("no-ipv6")
                .takes_value(false)))

        .get_matches()
}
