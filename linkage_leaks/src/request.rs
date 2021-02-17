use crate::error::HttpError;
#[cfg(test)]
use mockall::automock;
use std::io::Read;

pub enum RequestError {}

pub(crate) type RequestResult<T> = Result<T, RequestError>;

#[cfg_attr(test, automock)]
pub trait Requester {
    /// Returns the body of a given Internet address
    fn get(&self, address: &str) -> RequestResult<String>;
}

pub struct InternetRequester {}
/*
TODO: Implement this with tokio
impl Requester for InternetRequester {
    fn get(&self, address: &str) -> RequestResult<String> {
        let mut response = reqwest::blocking::get(address).map_err(|_|HttpError::ResponseError).unwrap();
        let mut body = String::new();
        response.read_to_string(&mut body).unwrap();
        Ok(body)
    }
}

 */
