#[cfg(test)]
use mockall::automock;
use crate::error::FirewallResult;

pub mod iptables;

/// An executor is responsible for executing the commands necessary to configure the firewalls.
#[cfg_attr(test, automock)]
pub trait Executor {
    /// Executes the firewall command with the supplied arguments.
    fn execute(&self, args: Vec<String>) -> FirewallResult<()>;
}