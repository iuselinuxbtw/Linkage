//! Definition and implementation of different firewall backends.

pub mod iptables;

use crate::error::FirewallResult;
use std::net::IpAddr;
use crate::executor::Executor;

/// A protocol for firewall exceptions.
#[derive(Debug, PartialEq)]
pub enum FirewallExceptionProtocol {
    TCP,
    UDP,
}

/// When activating a firewall, the connections to these exceptions will be allowed.
#[derive(Debug, PartialEq)]
pub struct FirewallException {
    host: IpAddr,
    port: u16, // log2(65536)=16
    protocol: FirewallExceptionProtocol,
}

impl FirewallException {
    /// Returns a new configured instance of FirewallException.
    pub fn new(host: IpAddr, port: u16, protocol: FirewallExceptionProtocol) -> FirewallException {
        return FirewallException {
            host,
            port,
            protocol
        }
    }
}

/// Holds a identifier for a firewall backend that is unique to the specific backend. Used for
/// identification purposes.
#[derive(Debug, PartialEq)]
pub struct FirewallIdentifier {
    identifier: &'static str,
}

/// Exposes methods to return the specific executors for firewall management.
pub trait FirewallExecutors<T: Executor, U: Executor> {
    /// Returns the executor for v4 operations.
    fn get_executor_v4(&self) -> &T;
    /// Returns the executor for v6 operations.
    fn get_executor_v6(&self) -> &U;
}

/// Exposes methods that can be called when managing different firewalls.
pub trait FirewallBackend<T: Executor, U: Executor>: FirewallExecutors<T, U> {
    /// Returns an unique identifier for the firewall backend. Used for identification purposes in
    /// the application
    fn get_identifier(&self) -> FirewallIdentifier;
    /// Returns whether the firewall backend is available. Can depend on various factors, e.g. the
    /// operating system or different installed packages.
    fn is_available(&self) -> FirewallResult<bool>;
    /// Called before connecting to the VPN server. Blocks all traffic into the internet while still
    /// allowing connections to the supplied exceptions. These include the vpn server.
    fn on_pre_connect(&self, exceptions: &[FirewallException]) -> FirewallResult<()>;
    /// Called after connecting to the VPN server. Allows all traffic from and to the supplied
    /// interface identifier.
    fn on_post_connect(&self, interface_identifier: &str) -> FirewallResult<()>;
    /// Called when the connection to the VPN server was closed. Resets the firewall.
    fn on_disconnect(&self) -> FirewallResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_firewall_exception_new() {
        assert_eq!(FirewallException{
            host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 1337,
            protocol: FirewallExceptionProtocol::TCP,
        }, FirewallException::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1337, FirewallExceptionProtocol::TCP));
    }
}