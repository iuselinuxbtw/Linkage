use thiserror;
use std::io::Error as IoError;
use which::Error as WhichError;

/// An error that occurred while doing firewall-related stuff.
#[derive(thiserror::Error, Debug)]
pub enum FirewallError {
    #[error("io error: {0}")]
    IoError(#[from] IoError),

    /// The `iptables` command was executed successfully, but it resulted in an error. Holds the
    /// exit status code, if there's any.
    #[error("iptables exited with non-zero status code {0:?}")]
    IptablesError(Option<i32>),

    /// An error occurred while using the which crate. Most likely happens when checking for the
    /// existence of a binary like `iptables`.
    #[error("cannot looking up binary path: {0}")]
    WhichError(#[from] WhichError),
}

/// A result that contains T for Ok and FirewallError for Err.
pub(crate) type FirewallResult<T> = Result<T, FirewallError>;