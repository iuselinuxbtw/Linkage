use std::net::AddrParseError;

#[derive(thiserror::Error, Debug)]
pub enum ExceptionParseError {
    #[error("IP address Parse error")]
    AddrParseError(#[from] AddrParseError),

    #[error("Protocol invalid")]
    ProtocolParseError,
}
