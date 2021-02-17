//! Implementation of the iptables firewall backend

use super::{FirewallBackend, FirewallException};
use crate::error::FirewallResult;
use crate::executor::Executor;
use crate::firewalls::{FirewallExceptionProtocol, FirewallExecutors, FirewallIdentifier};
use crate::{executor_execute_for, to_string_vec};
use std::net::IpAddr;

/// Identifies the iptables backend uniquely.
const IPTABLES_BACKEND_IDENTIFIER: &str = "iptables";

/// Uses `iptables` as a backend for the firewall configuration.
pub struct IpTablesFirewall<T: Executor, U: Executor> {
    executor_v4: T,
    executor_v6: U,
}

/// The name for the chain that handles `ACCEPT` for the `INPUT` chain.
const IN_ACCEPT_CHAIN_NAME: &str = "in_accept";
/// The name for the chain that handles `ACCEPT` for the `OUTPUT` chain.
const OUT_ACCEPT_CHAIN_NAME: &str = "out_accept";

impl<T: Executor, U: Executor> IpTablesFirewall<T, U> {
    /// Returns a new instance of IpTablesInstance with the supplied executors.
    pub fn new(executor_v4: T, executor_v6: U) -> IpTablesFirewall<T, U> {
        return IpTablesFirewall {
            executor_v4,
            executor_v6,
        };
    }
}

impl<T: Executor, U: Executor> FirewallExecutors<T, U> for IpTablesFirewall<T, U> {
    fn get_executor_v4(&self) -> &T {
        &self.executor_v4
    }

    fn get_executor_v6(&self) -> &U {
        &self.executor_v6
    }
}

impl<T: Executor, U: Executor> FirewallBackend for IpTablesFirewall<T, U> {
    fn get_identifier(&self) -> FirewallIdentifier {
        return FirewallIdentifier {
            identifier: IPTABLES_BACKEND_IDENTIFIER,
        };
    }

    /// The IpTablesFirewall backend is available if the operating system is Linux and an executable
    /// with the name `iptables` is found.
    fn is_available(&self) -> FirewallResult<bool> {
        // TODO: Implement
        return Ok(true);
    }

    /// Applies the following rules:
    /// - Sets the default policy to `DROP` for the chains `INPUT`, `OUTPUT` and `FORWARD`
    /// - For both the `INPUT` and `OUTPUT` chain, it will:
    ///     - Accept related/established traffic
    ///     - Drop invalid packets
    ///     - Allow traffic on the loopback device
    /// - Create a chain that will be used for new and untracked connections in the `INPUT` chain
    /// - Create a chain that will be used for new and untracked connections in the `OUTPUT` chain
    /// - Add exceptions for the supplied FirewallExceptions. They can be used for e.g. whitelisting
    /// VPN servers
    fn on_pre_connect(&self, exceptions: &[FirewallException]) -> FirewallResult<()> {
        let executor_v4 = self.get_executor_v4();
        let executor_v6 = self.get_executor_v6();

        // Default policies
        executor_execute_for!(
            to_string_vec!("-P", "INPUT", "DROP"),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!("-P", "OUTPUT", "DROP"),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!("-P", "FORWARD", "DROP"),
            executor_v4,
            executor_v6
        );

        for chain in ["INPUT", "OUTPUT"].iter() {
            // Related/established traffic should be allowed
            executor_execute_for!(
                to_string_vec!(
                    "-A",
                    *chain,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT"
                ),
                executor_v4,
                executor_v6
            );

            // Drop invalid packets
            executor_execute_for!(
                to_string_vec!("-A", *chain, "-m", "state", "--state", "INVALID", "-j", "DROP"),
                executor_v4,
                executor_v6
            );
        }

        // Allow traffic on loopback device
        executor_execute_for!(
            to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT"),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"),
            executor_v4,
            executor_v6
        );

        // Create new chain for incoming allow and hook it up
        executor_execute_for!(
            to_string_vec!("-N", IN_ACCEPT_CHAIN_NAME),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!(
                "-A",
                "INPUT",
                "-m",
                "state",
                "--state",
                "NEW,UNTRACKED",
                "-j",
                IN_ACCEPT_CHAIN_NAME
            ),
            executor_v4,
            executor_v6
        );

        // Create new chain for outgoing allow and hook it up
        executor_execute_for!(
            to_string_vec!("-N", OUT_ACCEPT_CHAIN_NAME),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!(
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "NEW,UNTRACKED",
                "-j",
                OUT_ACCEPT_CHAIN_NAME
            ),
            executor_v4,
            executor_v6
        );

        // Add exceptions
        for e in exceptions.iter() {
            let protocol = match e.protocol {
                FirewallExceptionProtocol::TCP => "tcp",
                FirewallExceptionProtocol::UDP => "udp",
            };
            match e.host {
                IpAddr::V4(ip) => {
                    executor_v4.execute(to_string_vec!(
                        "-A",
                        OUT_ACCEPT_CHAIN_NAME,
                        "-d",
                        format!("{}/32", ip.to_string()),
                        "-p",
                        protocol,
                        "-m",
                        protocol,
                        "--dport",
                        format!("{}", e.port),
                        "-j",
                        "ACCEPT"
                    ))?;
                }
                IpAddr::V6(ip) => {
                    executor_v6.execute(to_string_vec!(
                        "-A",
                        OUT_ACCEPT_CHAIN_NAME,
                        "-d",
                        format!("{}/128", ip.to_string()),
                        "-p",
                        protocol,
                        "-m",
                        protocol,
                        "--dport",
                        format!("{}", e.port),
                        "-j",
                        "ACCEPT"
                    ))?;
                }
            }
        }

        Ok(())
    }

    /// Applies the following rules:
    /// - Allows outgoing connections from the supplied interface identifier
    fn on_post_connect(&self, interface_identifier: &str) -> FirewallResult<()> {
        let executor_v4 = self.get_executor_v4();
        let executor_v6 = self.get_executor_v6();

        // TODO: Do we need to accept incoming connections on the supplied interface identifier?
        executor_execute_for!(
            to_string_vec!(
                "-A",
                OUT_ACCEPT_CHAIN_NAME,
                "-o",
                interface_identifier,
                "-j",
                "ACCEPT"
            ),
            executor_v4,
            executor_v6
        );

        Ok(())
    }

    /// Applies the following rules:
    /// - Sets the default policy of the `INPUT`, `OUTPUT` and `FORWARD` chains to `ACCEPT`
    /// - Flushes all chains
    /// - Deletes the chains that are responsible for `ACCEPT` in the `INPUT` and `OUTPUT` chain
    fn on_disconnect(&self) -> FirewallResult<()> {
        let executor_v4 = self.get_executor_v4();
        let executor_v6 = self.get_executor_v6();

        // TODO: Reload firewall state from before creation
        // Default policies
        executor_execute_for!(
            to_string_vec!("-P", "INPUT", "ACCEPT"),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!("-P", "OUTPUT", "ACCEPT"),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!("-P", "FORWARD", "ACCEPT"),
            executor_v4,
            executor_v6
        );

        // Flush rules
        executor_execute_for!(to_string_vec!("-F"), executor_v4, executor_v6);

        // Delete the created chains
        executor_execute_for!(
            to_string_vec!("-X", IN_ACCEPT_CHAIN_NAME),
            executor_v4,
            executor_v6
        );
        executor_execute_for!(
            to_string_vec!("-X", OUT_ACCEPT_CHAIN_NAME),
            executor_v4,
            executor_v6
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockExecutor;
    use crate::expect_execute;
    use mockall::predicate::*;

    #[test]
    fn test_get_identifier() {
        let executor_v4_mock = MockExecutor::new();
        let executor_v6_mock = MockExecutor::new();
        let f = IpTablesFirewall {
            executor_v4: executor_v4_mock,
            executor_v6: executor_v6_mock,
        };

        assert_eq!(
            FirewallIdentifier {
                identifier: "iptables"
            },
            f.get_identifier()
        );
    }

    #[test]
    fn test_is_available() -> FirewallResult<()> {
        let executor_v4_mock = MockExecutor::new();
        let executor_v6_mock = MockExecutor::new();
        let f = IpTablesFirewall {
            executor_v4: executor_v4_mock,
            executor_v6: executor_v6_mock,
        };

        assert!(f.is_available()?);

        Ok(())
    }

    #[test]
    fn test_on_pre_connect() {
        let mut executor_v4_mock = MockExecutor::new();
        let mut executor_v6_mock = MockExecutor::new();

        // Default policies
        expect_execute!(executor_v4_mock, to_string_vec!("-P", "INPUT", "DROP"));
        expect_execute!(executor_v6_mock, to_string_vec!("-P", "INPUT", "DROP"));
        expect_execute!(executor_v4_mock, to_string_vec!("-P", "OUTPUT", "DROP"));
        expect_execute!(executor_v6_mock, to_string_vec!("-P", "OUTPUT", "DROP"));
        expect_execute!(executor_v4_mock, to_string_vec!("-P", "FORWARD", "DROP"));
        expect_execute!(executor_v6_mock, to_string_vec!("-P", "FORWARD", "DROP"));

        // Related/established traffic should be allowed for INPUT
        expect_execute!(
            executor_v4_mock,
            to_string_vec!(
                "-A",
                "INPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT"
            )
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!(
                "-A",
                "INPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT"
            )
        );

        // Drop invalid packets for INPUT
        expect_execute!(
            executor_v4_mock,
            to_string_vec!("-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!("-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
        );

        // Related/established traffic should be allowed for OUTPUT
        expect_execute!(
            executor_v4_mock,
            to_string_vec!(
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT"
            )
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!(
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT"
            )
        );

        // Drop invalid packets for OUTPUT
        expect_execute!(
            executor_v4_mock,
            to_string_vec!("-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!("-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
        );

        // Allow traffic on loopback device for INPUT
        expect_execute!(
            executor_v4_mock,
            to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
        );

        // Allow traffic on loopback device for OUTPUT
        expect_execute!(
            executor_v4_mock,
            to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
        );

        // New chain for incoming allow and hook of it into INPUT chain
        expect_execute!(executor_v4_mock, to_string_vec!("-N", "in_accept"));
        expect_execute!(executor_v6_mock, to_string_vec!("-N", "in_accept"));
        expect_execute!(
            executor_v4_mock,
            to_string_vec!(
                "-A",
                "INPUT",
                "-m",
                "state",
                "--state",
                "NEW,UNTRACKED",
                "-j",
                "in_accept"
            )
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!(
                "-A",
                "INPUT",
                "-m",
                "state",
                "--state",
                "NEW,UNTRACKED",
                "-j",
                "in_accept"
            )
        );

        // New chain for outgoing allow and hook of it into OUTPUT chain
        expect_execute!(executor_v4_mock, to_string_vec!("-N", "out_accept"));
        expect_execute!(executor_v6_mock, to_string_vec!("-N", "out_accept"));
        expect_execute!(
            executor_v4_mock,
            to_string_vec!(
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "NEW,UNTRACKED",
                "-j",
                "out_accept"
            )
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!(
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "NEW,UNTRACKED",
                "-j",
                "out_accept"
            )
        );

        // Firewall exceptions should get added
        expect_execute!(
            executor_v4_mock,
            to_string_vec!(
                "-A",
                "out_accept",
                "-d",
                "1.1.1.1/32",
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                "1337",
                "-j",
                "ACCEPT"
            )
        );
        expect_execute!(
            executor_v4_mock,
            to_string_vec!(
                "-A",
                "out_accept",
                "-d",
                "127.0.0.1/32",
                "-p",
                "udp",
                "-m",
                "udp",
                "--dport",
                "4200",
                "-j",
                "ACCEPT"
            )
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!(
                "-A",
                "out_accept",
                "-d",
                "2001:db8:85a3::8a2e:370:7334/128",
                "-p",
                "udp",
                "-m",
                "udp",
                "--dport",
                "2020",
                "-j",
                "ACCEPT"
            )
        );

        let f = IpTablesFirewall {
            executor_v4: executor_v4_mock,
            executor_v6: executor_v6_mock,
        };
        f.on_pre_connect(&[
            FirewallException::new(
                "1.1.1.1".parse().unwrap(),
                1337,
                FirewallExceptionProtocol::TCP,
            ),
            FirewallException::new(
                "127.0.0.1".parse().unwrap(),
                4200,
                FirewallExceptionProtocol::UDP,
            ),
            FirewallException::new(
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap(),
                2020,
                FirewallExceptionProtocol::UDP,
            ),
        ])
        .unwrap();
    }

    #[test]
    fn test_on_post_connect() {
        let mut executor_v4_mock = MockExecutor::new();
        let mut executor_v6_mock = MockExecutor::new();

        // Allow outgoing connections on the supplied interfaces
        expect_execute!(
            executor_v4_mock,
            to_string_vec!("-A", "out_accept", "-o", "tun1", "-j", "ACCEPT")
        );
        expect_execute!(
            executor_v6_mock,
            to_string_vec!("-A", "out_accept", "-o", "tun1", "-j", "ACCEPT")
        );

        let f = IpTablesFirewall {
            executor_v4: executor_v4_mock,
            executor_v6: executor_v6_mock,
        };
        f.on_post_connect("tun1").unwrap();
    }

    #[test]
    fn test_on_disconnect() {
        let mut executor_v4_mock = MockExecutor::new();
        let mut executor_v6_mock = MockExecutor::new();

        // Default policies
        expect_execute!(executor_v4_mock, to_string_vec!("-P", "INPUT", "ACCEPT"));
        expect_execute!(executor_v6_mock, to_string_vec!("-P", "INPUT", "ACCEPT"));
        expect_execute!(executor_v4_mock, to_string_vec!("-P", "OUTPUT", "ACCEPT"));
        expect_execute!(executor_v6_mock, to_string_vec!("-P", "OUTPUT", "ACCEPT"));
        expect_execute!(executor_v4_mock, to_string_vec!("-P", "FORWARD", "ACCEPT"));
        expect_execute!(executor_v6_mock, to_string_vec!("-P", "FORWARD", "ACCEPT"));

        // Flushes rules
        expect_execute!(executor_v4_mock, to_string_vec!("-F"));
        expect_execute!(executor_v6_mock, to_string_vec!("-F"));

        // Deletes the created chains
        expect_execute!(executor_v4_mock, to_string_vec!("-X", "in_accept"));
        expect_execute!(executor_v6_mock, to_string_vec!("-X", "in_accept"));
        expect_execute!(executor_v4_mock, to_string_vec!("-X", "out_accept"));
        expect_execute!(executor_v6_mock, to_string_vec!("-X", "out_accept"));

        let f = IpTablesFirewall {
            executor_v4: executor_v4_mock,
            executor_v6: executor_v6_mock,
        };
        f.on_disconnect().unwrap();
    }
}
