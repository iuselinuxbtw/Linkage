//! Responsible for handling everything related to the firewall. This e.g. includes its leak-safe
//! setup and exceptions so the VPN client can connect to the VPN server.

pub use error::FirewallError;
pub use firewalls::{
    FirewallBackend, FirewallException, FirewallExceptionProtocol, FirewallExceptionProtocolError,
};

mod error;
mod executor;
pub(crate) mod firewalls;
#[macro_use]
mod utils;
#[cfg(test)]
#[macro_use]
mod test_utils;

use executor::iptables::{IptablesBaseCommand, IptablesCommandExecutor};
use lazy_static::lazy_static;

/// A list that contains firewall backends.
type FirewallBackendList = Vec<Box<dyn firewalls::FirewallBackend + Sync>>;

lazy_static! {
    /// The command executor for `iptables` actions.
    static ref IPTABLES_COMMAND_EXECUTOR: IptablesCommandExecutor = IptablesCommandExecutor::new(IptablesBaseCommand::Iptables);
    /// The command executor for `ip6tables` actions.
    static ref IP6TABLES_COMMAND_EXECUTOR: IptablesCommandExecutor = IptablesCommandExecutor::new(IptablesBaseCommand::Ip6tables);

    /// A list of all implemented firewall backends.
    static ref ALL_BACKENDS: FirewallBackendList = {
        let mut v: FirewallBackendList = Vec::new();
        v.push(
            Box::new(
                firewalls::iptables::IpTablesFirewall::new(
                    // Deref is necessary so that we get a value that implements the Executor trait
                    &*IPTABLES_COMMAND_EXECUTOR,
                    &*IP6TABLES_COMMAND_EXECUTOR,
                )
            )
        );
        v
    };
}

/// Returns all available firewall backends. Currently, this are:
/// - `iptables`
pub fn get_backends() -> &'static FirewallBackendList {
    &ALL_BACKENDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_backends() {
        let backends = get_backends();
        assert_eq!(backends.len(), 1);

        assert_eq!(backends.get(0).unwrap().get_identifier(), "iptables");
        assert!(backends.get(1).is_none());
    }
}
