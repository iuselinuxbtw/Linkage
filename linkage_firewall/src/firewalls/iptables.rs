//! Implementation of the iptables firewall backend

use super::{FirewallBackend, FirewallException};
use crate::error::FirewallError;
use crate::executor::Executor;
use crate::to_string_vec;
use crate::firewalls::FirewallExceptionProtocol;

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
    fn on_pre_connect<T: Executor>(executor: &T, exceptions: &[FirewallException]) -> Result<(), FirewallError> {
        // TODO: IPv6
        // Default policies
        executor.execute(to_string_vec!("-P", "INPUT", "DROP"))?;
        executor.execute(to_string_vec!("-P", "OUTPUT", "DROP"))?;
        executor.execute(to_string_vec!("-P", "FORWARD", "DROP"))?;

        for chain in ["INPUT", "OUTPUT"].iter() {
            // Related/established traffic should be allowed
            executor.execute(to_string_vec!(
                "-A", *chain, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ))?;

            // Drop invalid packets
            executor.execute(to_string_vec!(
                "-A", *chain, "-m", "state", "--state", "INVALID", "-j", "DROP"
            ))?;
        }

        // Allow traffic on loopback device
        executor.execute(to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT"))?;
        executor.execute(to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"))?;

        // Create new chain for incoming allow and hook it up
        executor.execute(to_string_vec!("-N", IN_ACCEPT_CHAIN_NAME))?;
        executor.execute(to_string_vec!(
            "-A", "INPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", IN_ACCEPT_CHAIN_NAME
        ))?;

        // Create new chain for outgoing allow and hook it up
        executor.execute(to_string_vec!("-N", OUT_ACCEPT_CHAIN_NAME))?;
        executor.execute(to_string_vec!(
            "-A", "OUTPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", OUT_ACCEPT_CHAIN_NAME
        ))?;

        // Add exceptions
        for e in exceptions.iter() {
            // Only add the host if it is IPv4
            // TODO: IPv6 support
            if e.host.is_ipv4() {
                let protocol = match e.protocol {
                    FirewallExceptionProtocol::TCP => "tcp",
                    FirewallExceptionProtocol::UDP => "udp",
                };
                executor.execute(to_string_vec!(
                    "-A", OUT_ACCEPT_CHAIN_NAME, "-d", format!("{}/32", e.host.to_string()), "-p",
                    protocol, "-m", protocol, "--dport", format!("{}", e.port), "-j", "ACCEPT"
                ))?;
            }
        }

        Ok(())
    }

    fn on_post_connect<T: Executor>(executor: &T, interface_identifier: &str) -> Result<(), FirewallError> {
        unimplemented!()
    }

    /// Applies the following rules:
    /// - Sets the default policy of the `INPUT`, `OUTPUT` and `FORWARD` chains to `ACCEPT`
    /// - Flushes all chains
    /// - Deletes the chains that are responsible for `ACCEPT` in the `INPUT` and `OUTPUT` chain
    fn on_disconnect<T: Executor>(executor: &T) -> Result<(), FirewallError> {
        // TODO: IPv6 and reload firewall state from before creation
        // Default policies
        executor.execute(to_string_vec!("-P", "INPUT", "ACCEPT"))?;
        executor.execute(to_string_vec!("-P", "OUTPUT", "ACCEPT"))?;
        executor.execute(to_string_vec!("-P", "FORWARD", "ACCEPT"))?;

        // Flush rules
        executor.execute(to_string_vec!("-F"))?;

        // Delete the created chains
        executor.execute(to_string_vec!("-X", IN_ACCEPT_CHAIN_NAME))?;
        executor.execute(to_string_vec!("-X", OUT_ACCEPT_CHAIN_NAME))?;

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
        let mut executor_mock = MockExecutor::new();

        // Default policies
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-P", "INPUT", "DROP")))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-P", "OUTPUT", "DROP")))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-P", "FORWARD", "DROP")))
            .returning(|_| Ok(()));

        // Related/established traffic should be allowed for INPUT
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));

        // Drop invalid packets for INPUT
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"
            )))
            .returning(|_| Ok(()));

        // Related/established traffic should be allowed for OUTPUT
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));

        // Drop invalid packets for OUTPUT
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"
            )))
            .returning(|_| Ok(()));

        // Allow traffic on loopback device for INPUT
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-A", "INPUT", "-i", "lo", "-j", "ACCEPT")))
            .returning(|_| Ok(()));

        // Allow traffic on loopback device for OUTPUT
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")))
            .returning(|_| Ok(()));

        // New chain for incoming allow and hook of it into INPUT chain
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-N", "in_accept"
            )))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "INPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", "in_accept"
            )))
            .returning(|_| Ok(()));


        // New chain for outgoing allow and hook of it into OUTPUT chain
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-N", "out_accept"
            )))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "OUTPUT", "-m", "state", "--state", "NEW,UNTRACKED", "-j", "out_accept"
            )))
            .returning(|_| Ok(()));

        // Firewall exceptions should get added
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "out_accept", "-d", "1.1.1.1/32", "-p", "tcp", "-m", "tcp", "--dport", "1337",
                "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-A", "out_accept", "-d", "127.0.0.1/32", "-p", "udp", "-m", "udp", "--dport",
                "4200", "-j", "ACCEPT"
            )))
            .returning(|_| Ok(()));
        // The IPv6 should not be executed

        IpTablesFirewall::on_pre_connect(&executor_mock, &[
            FirewallException::new("1.1.1.1".parse().unwrap(), 1337, FirewallExceptionProtocol::TCP),
            FirewallException::new("127.0.0.1".parse().unwrap(), 4200, FirewallExceptionProtocol::UDP),
            FirewallException::new("2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap(), 2020, FirewallExceptionProtocol::UDP),
        ]).unwrap();
    }

    #[test]
    fn test_on_disconnect() {
        let mut executor_mock = MockExecutor::new();

        // Default policies
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-P", "INPUT", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-P", "OUTPUT", "ACCEPT")))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-P", "FORWARD", "ACCEPT")))
            .returning(|_| Ok(()));

        // Flushes rules
        executor_mock.expect_execute()
            .with(eq(to_string_vec!(
                "-F"
            )))
            .returning(|_| Ok(()));

        // Deletes the created chains
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-X", "in_accept")))
            .returning(|_| Ok(()));
        executor_mock.expect_execute()
            .with(eq(to_string_vec!("-X", "out_accept")))
            .returning(|_| Ok(()));

        IpTablesFirewall::on_disconnect(&executor_mock).unwrap();
    }
}