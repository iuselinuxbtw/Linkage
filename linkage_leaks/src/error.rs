use reqwest::Error as RequestError;
use serde_json::Error as SerdeJsonError;
use std::any::Any;
use std::io::Error as IoError;
use std::net::AddrParseError;
use std::sync::mpsc::RecvError;
use thiserror::Error;

pub(crate) type LeakResult<T> = Result<T, LeakError>;

#[derive(Error, Debug)]
pub enum LeakError {
    #[error("request error: {0}")]
    RequestError(#[from] RequestError),
    #[error("io error: {0}")]
    IoError(#[from] IoError),
    #[error("cannot parse json: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("error while joining threads")]
    JoiningThreadsError(Box<dyn Any + Send>),
    #[error("recv error occurred: {0}")]
    RecvError(#[from] RecvError),
    #[error("cannot parse address: {0}")]
    AddrParseError(#[from] AddrParseError),
}
