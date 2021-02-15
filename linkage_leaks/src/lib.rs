use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::channel;
use std::thread;
use std::sync::{Arc,Mutex};
use reqwest::blocking::Client as HttpClient;
use reqwest::{header as RequestHeaders, RequestBuilder, Url};
use random_string::{RandomString, Charsets, Charset};
use std::str::FromStr;
//TODO: Error Handling

/// Requests the IP from Mullvad
// TODO: Implement it for ipv4 and ipv6
pub fn get_ip() -> IpAddr{
    let mut resp = reqwest::blocking::get("https://am.i.mullvad.net/ip").unwrap();
    let mut body=String::new();
    resp.read_to_string(&mut body).unwrap();
    body.trim().parse().unwrap()
}

pub fn dns_test() -> Vec<IpAddr> {
    let data = Arc::new(Mutex::new(Vec::new()));
    let handles = (0..100)
        .into_iter()
        .map(|_|{
            let data = Arc::clone(&data);
            thread::spawn(move || {
                let mut ip = data.lock().unwrap();
                ip.push(get_dns());
            })
        })
        .collect::<Vec<thread::JoinHandle<_>>>();
    for thread in handles{
        thread.join().unwrap();
    };
    let mut ips = data.lock().unwrap().to_owned();
    ips.sort();
    ips.dedup();
    ips
}
 fn get_dns() -> IpAddr {
     let letters = Charset::from_charsets(Charsets::Letters);
     let prefix = RandomString::generate(40, &letters);
     let mut client = HttpClient::new();
     let mut resp = client
        .get(
        &format!("https://{}.ipleak.net/dnsdetect/", prefix.to_string()))
        .header(RequestHeaders::ORIGIN, "http://ipleak.net")
        .header(RequestHeaders::USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0")
        .header(RequestHeaders::REFERER, "http://ipleak.net/")
        .send()
        .unwrap();
     let mut body = String::new();
     resp.read_to_string(&mut body).unwrap();
     body.trim().parse().unwrap()
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
