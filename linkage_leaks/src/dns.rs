//! Contains the utilities for detecting the DNS servers in use.

use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use lazy_static::lazy_static;
use random_string::{Charset, GenerationResult, RandomString};

use crate::error::LeakResult;
use crate::LeakError;

/// The site used for DNS leak checking. Contains a formatting parameter for a prefix.
const LEAK_DETECT_DNS_SITE: &str = "https://{}.ipleak.net/dnsdetect/";
/// A set of chars that can be used for generating prefixes for the DNS leak check.
const LEAK_DETECT_DNS_PREFIX_CHARSET: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
/// The length of the prefix for DNS leak detection.
const LEAK_DETECT_DNS_PREFIX_LENGTH: i32 = 40;
/// How many requests per thread will be executed to check for DNS leaks.
const LEAK_DETECT_REQUESTS_PER_THREAD: u32 = 5;

/// Options related to the execution of the dns leak test.
#[derive(Debug, PartialEq)]
struct DnsTestConfig {
    total: u32,
    requests_per_thread: u32,
    amount_of_threads: u32,
}

/// Returns the configuration that should be used to execute the dns leak test. This mainly consists
/// of data related to the amount of threads and the requests that should be executed in each
/// thread.
fn get_dns_leak_test_config(mut amount_of_requests: u32) -> DnsTestConfig {
    // Not mutable because it should be equal to the constant
    let requests_per_thread: u32 = LEAK_DETECT_REQUESTS_PER_THREAD;

    // If the amount of requests that should be executed is a multiple of requests_per_thread we can
    // safely use the provided value
    if amount_of_requests % requests_per_thread != 0 {
        // If the amount is not a multiple of the value, we have to get the next number of the
        // amount that's dividable by the requests per thread so we can have a clean amount of
        // threads and as a result of that, we won't get any strange behaviour when using weird
        // numbers as amount
        amount_of_requests = {
            let mut t: u32 = 0;
            while t < amount_of_requests {
                t += requests_per_thread;
            }
            t
        };
    }
    let amount_of_threads: u32 = amount_of_requests / requests_per_thread;

    return DnsTestConfig {
        total: amount_of_requests,
        requests_per_thread,
        amount_of_threads,
    };
}

/// Returns a list of all detected DNS servers. The supplied argument amount_of_requests determines
/// how often the test will be run.
pub fn dns_test(amount_of_requests: u32) -> LeakResult<Vec<IpAddr>> {
    let config = get_dns_leak_test_config(amount_of_requests);

    // Make a channel to receive the ip addresses
    let (tx, rx): (Sender<_>, Receiver<_>) = mpsc::channel::<String>();
    let mut children = Vec::new();

    for _ in 0..config.amount_of_threads {
        let thread_tx = tx.clone();
        let per_thread = config.requests_per_thread.clone();

        // Spawn the threads and save their handles into a Vec
        let child = thread::spawn(move || {
            // Each thread should do a specific amount of requests per thread
            for _ in 0..per_thread {
                // TODO: Improve the error handling for this calls
                let dns = get_dns().expect("cannot get dns server for dns leak detection");
                // We use .except here since this will probably not happen because we calculate this
                thread_tx
                    .send(dns)
                    .expect("cannot transmit data through created channel for dns leak detection");
            }
        });
        children.push(child);
    }

    // Save the collected ip addresses into a vec
    let mut ips: Vec<IpAddr> = Vec::new();
    for _ in 0..config.total {
        ips.push(rx.recv()?.parse()?);
    }

    // Wait for the threads to finish
    for child in children {
        child
            .join()
            .map_err(|e| LeakError::JoiningThreadsError(e))?;
    }

    // Sort and deduplicate the ip addresses
    ips.sort();
    ips.dedup();

    Ok(ips)
}

/// Gets the DNS server from the site used for DNS leak detection.
fn get_dns() -> LeakResult<String> {
    // Replaces {} in the string for the dns site for a random string. Necessary for some websites.
    let request_url = str::replace(LEAK_DETECT_DNS_SITE, "{}", &*generate_dns_leak_prefix());

    let resp = reqwest::blocking::get(&request_url)?;
    let body = resp.text()?;

    Ok(body.trim().to_owned())
}

/// Returns a prefix that can be used for DNS leak detection.
fn generate_dns_leak_prefix() -> String {
    lazy_static! {
        static ref LETTERS: Vec<char> = Charset::from_str(LEAK_DETECT_DNS_PREFIX_CHARSET);
    }
    let prefix: GenerationResult = RandomString::generate(LEAK_DETECT_DNS_PREFIX_LENGTH, &*LETTERS);
    prefix.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dns_leak_prefix() {
        // Running this test often ensures that we generate all available characters, but it will
        // take longer to run this test, though it is still nearly instantly.
        for _ in 0..1000 {
            let s = generate_dns_leak_prefix();
            assert_eq!(40, s.len());
            assert!(s
                .chars()
                .all(|x| x.is_ascii_digit() || x.is_ascii_lowercase()));
        }
    }

    #[test]
    fn test_get_dns() {
        let result = get_dns();
        let body: String = result.unwrap();
        let ip: IpAddr = body.parse().unwrap();
        println!("{}", ip);
    }

    #[test]
    fn test_get_dns_leak_test_config() {
        assert_eq!(
            DnsTestConfig {
                total: 25,
                requests_per_thread: 5,
                amount_of_threads: 5,
            },
            get_dns_leak_test_config(25)
        );

        assert_eq!(
            DnsTestConfig {
                total: 100,
                requests_per_thread: 5,
                amount_of_threads: 20,
            },
            get_dns_leak_test_config(100)
        );

        assert_eq!(
            DnsTestConfig {
                total: 75,
                requests_per_thread: 5,
                amount_of_threads: 15,
            },
            get_dns_leak_test_config(74)
        );
        assert_eq!(
            DnsTestConfig {
                total: 80,
                requests_per_thread: 5,
                amount_of_threads: 16,
            },
            get_dns_leak_test_config(76)
        );
        assert_eq!(
            DnsTestConfig {
                total: 80,
                requests_per_thread: 5,
                amount_of_threads: 16,
            },
            get_dns_leak_test_config(79)
        );

        assert_eq!(
            DnsTestConfig {
                total: 0,
                requests_per_thread: 5,
                amount_of_threads: 0,
            },
            get_dns_leak_test_config(0)
        );

        assert_eq!(
            DnsTestConfig {
                total: 5,
                requests_per_thread: 5,
                amount_of_threads: 1,
            },
            get_dns_leak_test_config(1)
        );
    }
}
