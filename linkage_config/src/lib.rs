mod error;
mod utils;

use linkage_firewall::FirewallException;
use serde::{Deserialize, Serialize};
use toml::Value;

#[derive(Serialize, Deserialize)]
pub struct FirewallConfig {
    pub exception: Vec<FirewallException>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub firewall: FirewallConfig,
}

#[cfg(test)]
mod tests {
    use toml::Value;

    #[test]
    fn toml_parsing() {
        let string = "linkage='cool'";
        let value = string.parse::<Value>().unwrap();
        assert_eq!(value["linkage"].as_str(), Some("cool"));
    }
}
