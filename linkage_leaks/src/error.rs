use thiserror::Error;
use reqwest::Error as ReqwestError;
use std::io::Error as IoError;
use serde_json::Error as SerdeJsonError;
use std::any::Any;
use std::sync::mpsc::RecvError;
use std::net::AddrParseError;

pub(crate) type LeakResult<T> = Result<T, LeakError>;

#[derive(Error, Debug)]
pub enum LeakError {
    #[error("request error: {0}")]
    RequestError(#[from] ReqwestError),
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
