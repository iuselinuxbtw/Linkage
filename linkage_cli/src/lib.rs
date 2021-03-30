pub(crate) mod consts;
pub mod error;
mod cmd;

use crate::error::{CliResult, CliError};
use clap::{App as ClapApp, ArgMatches as ClapArgMatches};
use cmd::Command;
use lazy_static::lazy_static;

/// Contains a list of commands.
type CommandList = Vec<Box<dyn Command + Sync>>;

lazy_static! {
    /// Contains a list of all command the app can handle.
    static ref COMMANDS: CommandList = {
        let mut commands: CommandList = Vec::new();
        commands.push(Box::new(cmd::connect::CommandConnect));
        commands.push(Box::new(cmd::ipinfo::CommandIpInfo));
        commands
    };
}

/// The entry point of the cli application.
pub fn entry() -> CliResult<()> {
    let matches = get_config_matches(&COMMANDS);

    // Check if a command matches the arguments, if yes: run it
    for command in COMMANDS.iter() {
        if let Some(matches) = matches.subcommand_matches(command.get_subcommand()) {
            command.run(matches)?;
            return Ok(());
        }
    }
    // If no command ran, then an invalid or no subcommand at all was supplied so an error should be
    // thrown
    Err(CliError::SubcommandRequired)
}

/// Returns the options that were supplied to the application.
fn get_config_matches(commands: &CommandList) -> ClapArgMatches {
    let mut app = ClapApp::new(consts::APP_NAME)
        .version(consts::APP_VERSION)
        .author(consts::APP_AUTHOR)
        .about(consts::APP_ABOUT);

    // Add the subcommands to the ClapApp
    for command in commands.iter() {
        app = app.subcommand(command.get_clap_app());
    }

    app.get_matches()
}
