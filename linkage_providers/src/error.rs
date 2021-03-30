use thiserror::Error;
use serde_json::Error as SerdeJsonError;

#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("authentication method not implemented")]
    AuthenticationMethodNotImplemented,

    #[error("json error: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
}

pub(crate) type ProviderResult<T> = Result<T, ProviderError>;