use std::io::Error as IOError;
use thiserror::Error;
use toml::de::Error as TomlDeserializeError;
use toml::ser::Error as TomlSerializeError;

#[derive(Error, Debug)]
pub enum ConfigError {
    // TODO: Use #[from] for these errors, similar to linkage_cli
    #[error("Couldn't get home directory")]
    PathError,
    #[error("Couldn't write config file")]
    SaveError(#[from] IOError),
    #[error("Couldn't serialize the data to save")]
    SerializeError(#[from] TomlSerializeError),
    #[error("Couldn't deserialize the config file")]
    DeserializeError(#[from] TomlDeserializeError),
}

pub type ConfigResult<T> = Result<T, ConfigError>;
