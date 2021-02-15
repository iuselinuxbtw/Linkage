use crate::error::FirewallResult;
use std::fmt::Debug;
#[cfg(test)]
use std::fmt::{Result as FmtResult, Formatter};

pub mod iptables;

/// An executor is responsible for executing the commands necessary to configure the firewalls.
pub trait Executor: Debug {
    /// Executes the firewall command with the supplied arguments.
    fn execute(&self, args: Vec<String>) -> FirewallResult<()>;
}

#[cfg(test)]
mockall::mock!{
    pub Executor {}
    impl Executor for MockExecutor {
        fn execute(&self, args: Vec<String>) -> FirewallResult<()>;
    }
}

#[cfg(test)]
impl Debug for MockExecutor {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("MockExecutor")
            .finish()
    }
}

#[cfg(test)]
impl PartialEq for MockExecutor {
    /// When their respective pointer location matches, they are equal. This needs to be done since
    /// we do not have any fields to compare.
    fn eq(&self, other: &Self) -> bool {
        self as *const _ == other as *const _
    }
}