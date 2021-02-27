//! Can check the current DNS servers as well as the outgoing ip address of the system.

mod dns;
mod error;
mod ip;

use error::LeakResult;
use std::io::Read;

pub use dns::dns_test;
pub use error::LeakError;
pub use ip::{get_ip_information, IpInformation};

/// Returns the response body of a given url.
fn get_body(url: &str) -> LeakResult<String> {
    let mut response = reqwest::blocking::get(url)?;
    let mut body = String::new();
    response.read_to_string(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_get_body() {
        let body = get_body("https://am.i.mullvad.net/ip");
        IpAddr::from_str(body.unwrap().trim()).unwrap();
    }
}
