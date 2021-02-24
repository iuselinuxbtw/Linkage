mod error;
mod utils;

use crate::error::ConfigError::{
    CreateDirError, DeserializeError, FileReadingError, SaveError, SerializeError,
};
use linkage_firewall::FirewallException;
use serde::{Deserialize, Serialize};
use std::fs::create_dir;
use std::path::PathBuf;
use std::string::ParseError;
use utils::get_home_dir;

#[derive(Serialize, Deserialize)]
pub struct FirewallConfig {
    pub exception: Vec<FirewallException>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub firewall: FirewallConfig,
}

pub fn save_config<T: Serialize>(data: &T, name: &str) {
    let serialized = toml::to_string(&data).map_err(|_| SerializeError).unwrap();
    let home_dir = get_home_dir();
    let config_dir = home_dir.join(".config/linkage/");
    if !config_dir.exists() {
        create_config_dir(&config_dir)
    }
    std::fs::write(config_dir.join(name), serialized)
        .map_err(|_| SaveError)
        .unwrap();
}
pub fn create_config_dir(path: &PathBuf) {
    if path.exists() {
        return;
    }
    create_dir(path).map_err(|_| CreateDirError).unwrap();
}
pub fn open_config(path: PathBuf) -> Config {
    let file = std::fs::read_to_string(path)
        .map_err(|_| FileReadingError)
        .unwrap();
    toml::from_str(&file).map_err(|_| DeserializeError).unwrap()
}
#[cfg(test)]
mod tests {
    use crate::save_config;
    use linkage_firewall::{FirewallException, FirewallExceptionProtocol};
    use std::net::IpAddr;
    use toml::Value;

    #[test]
    fn toml_parsing() {
        let string = "linkage='cool'";
        let value = string.parse::<Value>().unwrap();
        assert_eq!(value["linkage"].as_str(), Some("cool"));
    }
    #[test]
    fn config_parsing() {}
    #[test]
    fn test_save_config() {
        let exception1 = FirewallException::new(
            IpAddr::from("192.168.1.112"),
            31,
            FirewallExceptionProtocol::TCP,
        );
        let exception2 = FirewallException::new(
            IpAddr::from("2607:f0d0:1002:0051:0000:0000:0000:0004"),
            187,
            FirewallExceptionProtocol::UDP,
        );

        save_config(&exception, "testconfig");
    }
}
