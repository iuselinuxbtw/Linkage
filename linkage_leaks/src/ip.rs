//! Contains utilities to get information about an ip address.

use crate::get_body;
use crate::error::LeakResult;
use serde::Deserialize;
use serde_json;

/// The site used for IPv4 leak checking.
const LEAK_DETECT_IPV4_SITE: &str = "https://ipv4.ipleak.net/json/";
/// The site used for IPv6 leak checking.
const LEAK_DETECT_IPV6_SITE: &str = "https://ipv6.ipleak.net/json/";

/// Contains information about an ip address.
#[derive(Deserialize, Debug)]
pub struct IpInformation {
    pub country_code: String,
    pub country_name: String,

    pub region_code: String,
    pub region_name: String,

    pub continent_code: String,
    pub continent_name: String,

    pub city_name: String,
    pub postal_code: Option<String>,
    pub postal_confidence: Option<String>,

    pub latitude: f32,
    pub longitude: f32,
    pub accuracy_radius: i32,

    pub time_zone: String,
    pub metro_code: Option<String>,

    pub ip: String,
}

/// Contains the information for an IPv4. This is an alias for `IpInformation`.
type Ip4Information = IpInformation;
/// Contains the information for an IPv6. This is an alias for `IpInformation`.
type Ip6Information = IpInformation;

/// Requests infos from a site that returns them in json format, parses them afterwards and then
/// turns them into an instance of IpInformation. Returns a tuple with the information for IPv4 at
/// index `0` and IPv6 at `1`
pub fn get_ip_information() -> LeakResult<(Ip4Information, Ip6Information)> {
    let ipv4_response = get_body(LEAK_DETECT_IPV4_SITE)?;
    let ipv6_response = get_body(LEAK_DETECT_IPV6_SITE)?;

    let ipv4_infos = serde_json::from_str(&ipv4_response)?;
    let ipv6_infos = serde_json::from_str(&ipv6_response)?;

    Ok((ipv4_infos, ipv6_infos))
}
