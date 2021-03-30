//! Contains the different commands the application has to offer.

use clap::{App as ClapApp, ArgMatches};
use crate::error::CliResult;

pub mod connect;
pub mod ipinfo;

/// A command can be executed from the cli.
pub trait Command {
    /// Runs the command.
    fn run(&self, matches: &ArgMatches) -> CliResult<()>;
    /// The subcommand as a string.
    fn get_subcommand(&self) -> &str;
    /// Returns the [`ClapApp`] for command line options.
    fn get_clap_app(&self) -> ClapApp;
}