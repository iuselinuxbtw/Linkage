//! Implementation of the iptables firewall backend

use super::{FirewallBackend, FirewallException};
use crate::error::FirewallError;
use crate::executor::Executor;
use crate::{to_string_vec, executor_execute_for};
use crate::firewalls::FirewallExceptionProtocol;
use std::net::IpAddr;

/// Uses `iptables` as a backend for the firewall configuration.
pub struct IpTablesFirewall {}

/// The name for the chain that handles `ACCEPT` for the `INPUT` chain.
const IN_ACCEPT_CHAIN_NAME: &str = "in_accept";
/// The name for the chain that handles `ACCEPT` for the `OUTPUT` chain.
const OUT_ACCEPT_CHAIN_NAME: &str = "out_accept";

impl FirewallBackend for IpTablesFirewall {
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
    fn on_pre_connect<T: Executor, U: Executor>(executor_v4: &T, executor_v6: &U, exceptions: &[FirewallException]) -> Result<(), FirewallError> {
        // Default policies
        executor_execute_for!(to_string_vec!("-P", "INPUT", "DROP"), executor_v4, executor_v6);
        executor_execute_for!(to_string_vec!("-P", "OUTPUT", "DROP"), executor_v4, executor_v6);
        executor_execute_for!(to_string_vec!("-P", "FORWARD", "DROP"), executor_v4, executor_v6);

        for chain in ["INPUT", "OUTPUT"].iter() {
            // Related/established traffic should be allowed
            executor_execute_for!(to_string_vec!(
                "-A", *chain, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ), executor_v4, executor_v6);

            // Drop invalid packets
            executor_execute_for!(to_string_vec!(
                "-A", *chain, "-m", "state", "--state", "INVALID", "-j", "DROP"
            ), executor_v4, executor_v6);
        }

        // Allow traffic on loopback device
        executor_execute_for!(
            to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT"),
            executor_v4, executor_v6
        );
        executor_execute_for!(
            to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"),
            executor_v4, executor_v6
        );

        // Create new chain for incoming allow and hook it up
        executor_execute_for!(to_string_vec!("-N", IN_ACCEPT_CHAIN_NAME), executor_v4, executor_v6);
        executor_execute_for!(
            to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", IN_ACCEPT_CHAIN_NAME
            ),
            executor_v4, executor_v6
        );

        // Create new chain for outgoing allow and hook it up
        executor_execute_for!(to_string_vec!("-N", OUT_ACCEPT_CHAIN_NAME), executor_v4, executor_v6);
        executor_execute_for!(
            to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", OUT_ACCEPT_CHAIN_NAME
            ),
            executor_v4, executor_v6
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
                        "-A", OUT_ACCEPT_CHAIN_NAME, "-d", format!("{}/32", ip.to_string()),
                        "-p", protocol, "-m", protocol, "--dport", format!("{}", e.port), "-j",
                        "ACCEPT"
                    ))?;
                },
                IpAddr::V6(ip) => {
                    executor_v6.execute(to_string_vec!(
                        "-A", OUT_ACCEPT_CHAIN_NAME, "-d", format!("{}/128", ip.to_string()),
                        "-p", protocol, "-m", protocol, "--dport", format!("{}", e.port), "-j",
                        "ACCEPT"
                    ))?;
                },
            }
        }

        Ok(())
    }

    /// Applies the following rules:
    /// - Allows outgoing connections from the supplied interface identifier
    fn on_post_connect<T: Executor, U: Executor>(executor_v4: &T, executor_v6: &U, interface_identifier: &str) -> Result<(), FirewallError> {
        // TODO: Do we need to accept incoming connections on the supplied interface identifier?
        executor_execute_for!(
            to_string_vec!("-A", OUT_ACCEPT_CHAIN_NAME, "-o", interface_identifier, "-j", "ACCEPT"),
            executor_v4, executor_v6
        );

        Ok(())
    }

    /// Applies the following rules:
    /// - Sets the default policy of the `INPUT`, `OUTPUT` and `FORWARD` chains to `ACCEPT`
    /// - Flushes all chains
    /// - Deletes the chains that are responsible for `ACCEPT` in the `INPUT` and `OUTPUT` chain
    fn on_disconnect<T: Executor, U: Executor>(executor_v4: &T, executor_v6: &U) -> Result<(), FirewallError> {
        // TODO: Reload firewall state from before creation
        // Default policies
        executor_execute_for!(to_string_vec!("-P", "INPUT", "ACCEPT"), executor_v4, executor_v6);
        executor_execute_for!(to_string_vec!("-P", "OUTPUT", "ACCEPT"), executor_v4, executor_v6);
        executor_execute_for!(to_string_vec!("-P", "FORWARD", "ACCEPT"), executor_v4, executor_v6);

        // Flush rules
        executor_execute_for!(to_string_vec!("-F"), executor_v4, executor_v6);

        // Delete the created chains
        executor_execute_for!(to_string_vec!("-X", IN_ACCEPT_CHAIN_NAME), executor_v4, executor_v6);
        executor_execute_for!(to_string_vec!("-X", OUT_ACCEPT_CHAIN_NAME), executor_v4, executor_v6);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::MockExecutor;
    use mockall::predicate::*;

    #[test]
    fn test_on_pre_connect() {
        let mut executor_v4_mock = MockExecutor::new();
        let mut executor_v6_mock = MockExecutor::new();

        // TODO: Make a macro for the execute method call to remove duplicate code

        // Default policies
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "INPUT", "DROP")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "INPUT", "DROP")))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "OUTPUT", "DROP")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "OUTPUT", "DROP")))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "FORWARD", "DROP")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "FORWARD", "DROP")))
            .returning(|_| Ok(()));

        // Related/established traffic should be allowed for INPUT
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));

        // Drop invalid packets for INPUT
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"
            )))
            .returning(|_| Ok(()));

        // Related/established traffic should be allowed for OUTPUT
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));

        // Drop invalid packets for OUTPUT
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"
            )))
            .returning(|_| Ok(()));

        // Allow traffic on loopback device for INPUT
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT")))
            .returning(|_| Ok(()));

        // Allow traffic on loopback device for OUTPUT
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")))
            .returning(|_| Ok(()));

        // New chain for incoming allow and hook of it into INPUT chain
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-N", "in_accept"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-N", "in_accept"
            )))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", "in_accept"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", "in_accept"
            )))
            .returning(|_| Ok(()));


        // New chain for outgoing allow and hook of it into OUTPUT chain
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-N", "out_accept"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-N", "out_accept"
            )))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", "out_accept"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", "out_accept"
            )))
            .returning(|_| Ok(()));

        // Firewall exceptions should get added
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "out_accept", "-d", "1.1.1.1/32", "-p", "tcp", "-m", "tcp", "--dport", "1337",
                "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "out_accept", "-d", "127.0.0.1/32", "-p", "udp", "-m", "udp", "--dport",
                "4200", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!(
                "-A", "out_accept", "-d", "2001:db8:85a3::8a2e:370:7334/128", "-p",
                "udp", "-m", "udp", "--dport", "2020", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));

        IpTablesFirewall::on_pre_connect(&executor_v4_mock, &executor_v6_mock, &[
            FirewallException::new("1.1.1.1".parse().unwrap(), 1337, FirewallExceptionProtocol::TCP),
            FirewallException::new("127.0.0.1".parse().unwrap(), 4200, FirewallExceptionProtocol::UDP),
            FirewallException::new("2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap(), 2020, FirewallExceptionProtocol::UDP),
        ]).unwrap();
    }

    #[test]
    fn test_on_post_connect() {
        let mut executor_v4_mock = MockExecutor::new();
        let mut executor_v6_mock = MockExecutor::new();

        // Allow outgoing connections on the supplied interfaces
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-A", "out_accept", "-o", "tun1", "-j", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-A", "out_accept", "-o", "tun1", "-j", "ACCEPT")))
            .returning(|_| Ok(()));

        IpTablesFirewall::on_post_connect(&executor_v4_mock, &executor_v6_mock, "tun1").unwrap();
    }

    #[test]
    fn test_on_disconnect() {
        let mut executor_v4_mock = MockExecutor::new();
        let mut executor_v6_mock = MockExecutor::new();

        // Default policies
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "INPUT", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "INPUT", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "OUTPUT", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "OUTPUT", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "FORWARD", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-P", "FORWARD", "ACCEPT")))
            .returning(|_| Ok(()));

        // Flushes rules
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-F")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-F")))
            .returning(|_| Ok(()));

        // Deletes the created chains
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-X", "in_accept")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-X", "in_accept")))
            .returning(|_| Ok(()));
        executor_v4_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-X", "out_accept")))
            .returning(|_| Ok(()));
        executor_v6_mock.expect_execute()
            .times(1)
            .with(eq(to_string_vec!("-X", "out_accept")))
            .returning(|_| Ok(()));

        IpTablesFirewall::on_disconnect(&executor_v4_mock, &executor_v6_mock).unwrap();
    }
}