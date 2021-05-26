//! Definition and implementation of different firewall backends.

use std::error;
use std::fmt;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::FirewallResult;
use crate::executor::Executor;

pub mod iptables;

/// A protocol for firewall exceptions.
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum FirewallExceptionProtocol {
    TCP,
    UDP,
}

impl fmt::Display for FirewallExceptionProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FirewallExceptionProtocol::TCP => "TCP",
                FirewallExceptionProtocol::UDP => "UDP",
            }
        )
    }
}

/// Occurs when the supplied protocol cannot be parsed using FromStr in FirewallExceptionProtocol.
#[derive(Debug, PartialEq)]
pub struct FirewallExceptionProtocolError;

impl fmt::Display for FirewallExceptionProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The protocol is invalid")
    }
}

impl error::Error for FirewallExceptionProtocolError {}

impl FromStr for FirewallExceptionProtocol {
    type Err = FirewallExceptionProtocolError;

    /// Converts the supplied string into FirewallExceptionProtocol.
    /// # Values
    /// Below is a list of values that can be converted. If they can't be converted, they return a
    /// FirewallExceptionProtocolError.
    /// - UDP: `udp` | `UDP`
    /// - TCP: `tcp` | `TCP`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" | "UDP" => Ok(Self::UDP),
            "tcp" | "TCP" => Ok(Self::TCP),
            _ => Err(FirewallExceptionProtocolError),
        }
    }
}

/// When activating a firewall, the connections to these exceptions will be allowed.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FirewallException {
    pub host: IpAddr,
    pub port: u16,
    // log2(65536)=16
    pub protocol: FirewallExceptionProtocol,
}

impl FirewallException {
    /// Returns a new configured instance of FirewallException.
    pub fn new(host: IpAddr, port: u16, protocol: FirewallExceptionProtocol) -> FirewallException {
        FirewallException {
            host,
            port,
            protocol,
        }
    }

    pub fn get_host(&self) -> IpAddr {
        self.host
    }
    pub fn get_port(&self) -> u16 {
        self.port
    }
    pub fn get_protocol(&self) -> FirewallExceptionProtocol {
        self.protocol
    }
}

/// Holds a identifier for a firewall backend that is unique to the specific backend. Used for
/// identification purposes.
#[derive(Debug, PartialEq)]
pub struct FirewallIdentifier {
    identifier: &'static str,
}

impl PartialEq<&str> for FirewallIdentifier {
    /// Returns whether the identifier of the firewall backend is equal to a supplied string.
    fn eq(&self, other: &&str) -> bool {
        self.identifier == *other
    }
}

impl PartialEq<FirewallIdentifier> for &str {
    /// Returns whether the string is equal to the identifier of a firewall backend.
    fn eq(&self, other: &FirewallIdentifier) -> bool {
        *other == *self
    }
}

/// Exposes methods to return the specific executors for firewall management.
pub trait FirewallExecutors<T: Executor, U: Executor> {
    /// Returns the executor for v4 operations.
    fn get_executor_v4(&self) -> &T;
    /// Returns the executor for v6 operations.
    fn get_executor_v6(&self) -> &U;
}

/// Exposes methods that can be called when managing different firewalls.
pub trait FirewallBackend {
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
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_firewall_identifier_partialeq_pointer_str() {
        assert!(
            FirewallIdentifier {
                identifier: "imagine"
            } == "imagine"
        );
        assert_eq!(
            FirewallIdentifier {
                identifier: "imagine"
            },
            "imagine"
        );

        assert!(FirewallIdentifier { identifier: "lol" } != "imagine");
        assert_ne!(FirewallIdentifier { identifier: "lol" }, "imagine");
    }

    #[test]
    fn test_pointer_str_partialeq_firewall_identifier() {
        assert_eq!(
            "imagine",
            FirewallIdentifier {
                identifier: "imagine"
            }
        );
        assert_eq!(
            "imagine",
            FirewallIdentifier {
                identifier: "imagine"
            }
        );

        assert_ne!("imagine", FirewallIdentifier { identifier: "lol" });
    }

    #[test]
    fn test_firewall_exception_new() {
        assert_eq!(
            FirewallException {
                host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 1337,
                protocol: FirewallExceptionProtocol::TCP,
            },
            FirewallException::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                1337,
                FirewallExceptionProtocol::TCP
            )
        );
    }

    #[test]
    fn test_firewall_exception_protocol_error_format() {
        assert_eq!(
            "The protocol is invalid",
            format!("{}", FirewallExceptionProtocolError)
        )
    }

    #[test]
    fn test_firewall_exception_protocol_error_from_str() {
        assert_eq!(
            FirewallExceptionProtocol::UDP,
            FirewallExceptionProtocol::from_str("udp").unwrap()
        );
        assert_eq!(
            FirewallExceptionProtocol::UDP,
            FirewallExceptionProtocol::from_str("UDP").unwrap()
        );
        assert_eq!(
            FirewallExceptionProtocol::TCP,
            FirewallExceptionProtocol::from_str("tcp").unwrap()
        );
        assert_eq!(
            FirewallExceptionProtocol::TCP,
            FirewallExceptionProtocol::from_str("TCP").unwrap()
        );

        assert_eq!(
            FirewallExceptionProtocolError,
            FirewallExceptionProtocol::from_str("Udp").err().unwrap()
        );
        assert_eq!(
            FirewallExceptionProtocolError,
            FirewallExceptionProtocol::from_str("uDp").err().unwrap()
        );
        assert_eq!(
            FirewallExceptionProtocolError,
            FirewallExceptionProtocol::from_str("udP").err().unwrap()
        );

        assert_eq!(
            FirewallExceptionProtocolError,
            FirewallExceptionProtocol::from_str("Tcp").err().unwrap()
        );
        assert_eq!(
            FirewallExceptionProtocolError,
            FirewallExceptionProtocol::from_str("tCp").err().unwrap()
        );
        assert_eq!(
            FirewallExceptionProtocolError,
            FirewallExceptionProtocol::from_str("tcP").err().unwrap()
        );
    }
}
