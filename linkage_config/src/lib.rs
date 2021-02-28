//! Contains the configuration part of Linkage.

mod error;
pub mod utils;

use crate::error::{ConfigError, ConfigResult};
use crate::utils::get_config_dir;
use linkage_firewall::FirewallException;
use serde::{Deserialize, Serialize};
use std::fs::create_dir;
use std::path::PathBuf;
use utils::get_home_dir;

/// Contains the configuration of the firewall.
#[derive(Serialize, Deserialize, Debug)]
pub struct FirewallConfig {
    pub exception: Vec<FirewallException>,
}

/// The general application configuration. Holds all configuration values.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub firewall: FirewallConfig,
}

/// Saves serializable data to a config file in `.config/linkage/[name]`.
pub fn save_config<T: Serialize>(data: &T, name: &str) -> Result<(), ConfigError> {
    // First we need to serialize the data
    let serialized = toml::to_string(&data)?;

    // Get the config directory
    let config_dir = get_config_dir();
    // If the config directory doesn't exist we're going to create it
    create_config_dir(&config_dir)?;

    // Write the serialized data to the config file
    std::fs::write(config_dir.join(name), serialized)?;
    Ok(())
}

/// Creates a directory if it doesn't exist yet. Return true if it was created, false if it existed.
pub fn create_config_dir(path: &PathBuf) -> Result<bool, ConfigError> {
    // Checks if the directory already exists
    if path.exists() {
        return Ok(false);
    }
    create_dir(path)?;
    Ok(true)
}

/// Opens the config file with the given Path and returns a Config
pub fn open_config(path: PathBuf) -> ConfigResult<Config> {
    // Reads the config file to a string
    let file = std::fs::read_to_string(path)?;
    // Serialize the string and return the Config
    let c: Config = toml::from_str(&file)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use crate::utils::{get_config_dir, get_home_dir};
    use crate::{open_config, save_config, Config, FirewallConfig};
    use linkage_firewall::{FirewallException, FirewallExceptionProtocol};
    use std::fs;
    use std::io::Write;
    use toml::Value;

    #[test]
    fn toml_parsing() {
        let string = "linkage='cool'";
        let value = string.parse::<Value>().unwrap();
        assert_eq!(value["linkage"].as_str(), Some("cool"));
    }

    /// Creates two artificial exceptions and saves them to a config file. Then it compares the
    /// written file to a predefined string and deletes the test file after.
    #[test]
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
        let config: Config = Config {
            firewall: firewall_conf,
        };
        save_config(&config, "tsconfig").unwrap();
        let filepath = get_config_dir();
        let contents = fs::read_to_string(&filepath).unwrap();
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
        fs::remove_file(filepath).unwrap();
    }

    /// Creates a tsconfig file and saves two exceptions to a file and then compares them to the
    /// expected result.
    #[test]
    fn test_open_config() {
        let filepath = get_config_dir();
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
        let expected: Config = Config {
            firewall: firewall_conf,
        };
        let to_write = r#"[[firewall.exception]]
host = "192.168.1.112"
port = 31
protocol = "TCP"

[[firewall.exception]]
host = "2607:f0d0:1002:51::4"
port = 187
protocol = "UDP"
"#;
        let mut file = std::fs::File::create(&filepath).unwrap();
        file.write_all(to_write.as_ref()).unwrap();
        let result = open_config(filepath.clone()).unwrap();
        assert_eq!(result.firewall.exception, expected.firewall.exception);
        fs::remove_file(filepath).unwrap();
    }
}
