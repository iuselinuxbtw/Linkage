//! Definition and implementation of different firewall backends.

pub mod iptables;

use crate::error::FirewallError;
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

/// Exposes methods that can be called when managing different firewalls.
pub trait FirewallBackend {
    /// Called before connecting to the VPN server. Blocks all traffic into the internet while still
    /// allowing connections to the supplied exceptions. These include the vpn server.
    fn on_pre_connect<T: Executor>(executor: &T, exceptions: &[FirewallException]) -> Result<(), FirewallError>;
    /// Called after connecting to the VPN server. Allows all traffic from and to the supplied
    /// interface identifier.
    fn on_post_connect<T: Executor>(executor: &T, interface_identifier: &str) -> Result<(), FirewallError>;
    /// Called when the connection to the VPN server was closed. Resets the firewall.
    fn on_disconnect<T: Executor>(executor: &T) -> Result<(), FirewallError>;
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