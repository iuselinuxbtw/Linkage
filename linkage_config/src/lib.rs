mod error;
mod utils;

use crate::error::ConfigError::{
    CreateDirError, DeserializeError, FileReadingError, SaveError, SerializeError,
};
use linkage_firewall::FirewallException;
use serde::{Deserialize, Serialize};
use std::fs::create_dir;
use std::path::PathBuf;
use utils::get_home_dir;

#[derive(Serialize, Deserialize)]
pub struct FirewallConfig {
    pub exception: Vec<FirewallException>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub firewall: FirewallConfig,
}

/// Saves serializeable data to a config file in .config/linkage/[name]
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

/// Creates a directory if it doesn't exist yet
pub fn create_config_dir(path: &PathBuf) {
    if path.exists() {
        return;
    }
    create_dir(path).map_err(|_| CreateDirError).unwrap();
}

/// Opens the config file with the given Path and returns a Config
pub fn open_config(path: PathBuf) -> Config {
    let file = std::fs::read_to_string(path)
        .map_err(|_| FileReadingError)
        .unwrap();
    toml::from_str(&file).map_err(|_| DeserializeError).unwrap()
}
#[cfg(test)]
mod tests {
    use crate::error::ConfigError::{FileDeletionError, FileReadingError};
    use crate::utils::get_home_dir;
    use crate::{save_config, Config, FirewallConfig};
    use linkage_firewall::{FirewallException, FirewallExceptionProtocol};
    use std::fs;
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
    /// Creates two artificial exceptions and saves them to a config file. Then it compares the
    /// written file to a predefined string and deletes the test file after.
    fn test_save_config() {
        // Create two artificial exceptions
        let exception1 = FirewallException::new(
            "192.168.1.112".parse().unwrap(),
            31,
            FirewallExceptionProtocol::TCP,
        );
        let exception2 = FirewallException::new(
            "2607:f0d0:1002:0051:0000:0000:0000:0004".parse().unwrap(),
            187,
            FirewallExceptionProtocol::UDP,
        );
        let mut exceptions: Vec<FirewallException> = Vec::new();
        exceptions.push(exception1);
        exceptions.push(exception2);
        let firewall_conf: FirewallConfig = FirewallConfig {
            exception: exceptions,
        };
        let config = Config {
            firewall: firewall_conf,
        };
        save_config(&config, "tsconfig");
        let filepath = get_home_dir().join(".config/linkage/tsconfig");
        let contents = fs::read_to_string(&filepath)
            .map_err(|_| FileReadingError)
            .unwrap();
        // This string formatting could be nicer but for now it works fine.
        let expected = r#"[[firewall.exception]]
host = "192.168.1.112"
port = 31
protocol = "TCP"

[[firewall.exception]]
host = "2607:f0d0:1002:51::4"
port = 187
protocol = "UDP"
"#;
        assert_eq!(contents, expected);
        fs::remove_file(filepath)
            .map_err(|_| FileDeletionError)
            .unwrap();
    }
}
