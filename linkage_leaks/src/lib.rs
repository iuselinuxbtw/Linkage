use std::io::Read;
use std::net::{IpAddr, };
use std::sync::{Arc, Mutex};
use std::thread;

use random_string::{Charset, Charsets, GenerationResult, RandomString};
use reqwest::blocking::Client as HttpClient;
use reqwest::header as RequestHeaders;
use serde::Deserialize;
use serde_json;

use error::HttpError;
mod error;

// Vars for the DNSTest

// Tor User Agent, you can also use any User Agent you like but for anonymity this is probably the best one
const USERAGENT: &str = "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0";
const REFERER: &str = "http://ipleak.net";
// If you want to use another site for DNSTesting, you should replace this
const DNS_SITE: &str = "ipleak.net/dnsdetect/";
const IPV4_SITE: &str = "https://ipv4.ipleak.net/json/";
const IPV6_SITE: &str = "https://ipv6.ipleak.net/json/";

#[derive(Deserialize, Debug)]
struct Infos {
    country_code:String,
    region_code:String,
    continent_code:String,
    city_name:String,
    ipv4:String,
    ipv6:String
}

/// Requests the IP from ipleak.net
// TODO: merge this and ipv6 into one function and save the data into Infos
pub fn get_ipv4() -> IpAddr {
    let mut resp = reqwest::blocking::get(IPV4_SITE)
        .map_err(|_| HttpError::ResponseError)
        .unwrap();
    let mut body = String::new();
    resp.read_to_string(&mut body).map_err(|_| HttpError::ParseError).unwrap();
    let response: Infos = serde_json::from_str(&body).unwrap();
    let mut ipstring= response.ip;
    body.trim().parse().unwrap()
}

pub fn get_ipv6() -> IpAddr {
    let mut resp = reqwest::blocking::get(IPV6_SITE)
        .map_err(|_| HttpError::ResponseError)
        .unwrap();
    let mut body = String::new();
    resp.read_to_string(&mut body).map_err(|_| HttpError::ParseError).unwrap();
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
            &format!("https://{}{}", prefix, DNS_SITE))
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
