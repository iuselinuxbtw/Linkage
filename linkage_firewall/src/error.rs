use std::io::Error as IoError;

/// An error that occurred while doing firewall-related stuff.
#[derive(Debug)]
pub enum FirewallError {
    IoError(IoError),
    /// The `iptables` command was executed successfully, but it resulted in an error. Holds the
    /// exit status code, if there's any.
    IptablesError(Option<i32>),
}

impl From<IoError> for FirewallError {
    fn from(error: IoError) -> Self {
        // TODO: Tests
        FirewallError::IoError(error)
    }
}

/// A result that contains T for Ok and FirewallError for Err.
pub(crate) type FirewallResult<T> = Result<T, FirewallError>;
