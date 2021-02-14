use super::Executor;
use std::process::Command;
use crate::error::FirewallError;

/// Responsible for executing `iptables` using std::process::Command.
pub struct IptablesCommandExecutor;

impl Executor for IptablesCommandExecutor {
    /// Executes the `iptables` command with the given arguments.
    fn execute(&self, args: Vec<String>) -> Result<(), FirewallError> {
        // TODO: How to test this?
        let exit_status = Command::new("iptables")
            .args(args)
            .spawn()?
            .wait()?;
        if exit_status.success() {
            Ok(())
        } else {
            Err(FirewallError::IptablesError(exit_status.code()))
        }
    }
}