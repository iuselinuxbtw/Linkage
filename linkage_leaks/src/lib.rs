use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use random_string::{Charset, Charsets, GenerationResult, RandomString};
use reqwest::header as RequestHeaders;
use reqwest::blocking::Client as HttpClient;
use reqwest::header::USER_AGENT;
use error::HttpError;

mod error;

// Vars for the DNSTest

// Tor User Agent, you can also use any User Agent you like but for anonymity this is probably the best one
static USERAGENT: &str = "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0";
static REFERER: &str = "http://ipleak.net";
// If you want to use another site for DNSTesting, you should replace this
static SITE: &str = "ipleak.net/dnsdetect/";



/// Requests the IP from Mullvad
// TODO: Implement it for ipv4 and ipv6
pub fn get_ip() -> IpAddr {
    let mut resp = reqwest::blocking::get("https://am.i.mullvad.net/ip").unwrap();
    let mut body = String::new();
    resp.read_to_string(&mut body).unwrap();
    body.trim().parse().unwrap()
}


/// Gets all DNS Servers
// TODO: Make this more efficient
pub fn dns_test() -> Vec<IpAddr> {
    let data = Arc::new(Mutex::new(Vec::new()));
    let handles = (0..100)
        .into_iter()
        .map(|_| {
            let data = Arc::clone(&data);
            thread::spawn(move || {
                let mut ip = data.lock().unwrap();
                ip.push(get_dns().unwrap());
            })
        })
        .collect::<Vec<thread::JoinHandle<_>>>();
    for thread in handles {
        thread.join().unwrap();
    };
    let mut ips = data.lock().unwrap().to_owned();
    ips.sort();
    ips.dedup();
    ips
}

/// Gets the DNS server from ipleak.net
fn get_dns() -> Result<IpAddr, HttpError> {
    let letters = Charset::from_charsets(Charsets::Letters);
    let mut prefix: GenerationResult = RandomString::generate(40, &letters);
    let prefix = format!("{}.", prefix.to_string());
    let client = HttpClient::new();
    let mut resp = client
        .get(
            &format!("https://{}{}", prefix, SITE))
        .header(RequestHeaders::ORIGIN, REFERER)
        .header(RequestHeaders::USER_AGENT, USERAGENT)
        .header(RequestHeaders::REFERER, REFERER)
        .send()
        .map_err(|_| HttpError::ResponseError)
        .unwrap();
    let mut body = String::new();
    resp.read_to_string(&mut body).map_err(|_| HttpError::ParseError).unwrap();
    Ok(body.trim().parse().unwrap())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
