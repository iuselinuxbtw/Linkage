use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    // TODO: Use #[from] for these errors, similar to linkage_cli
    #[error("Couldn't get home directory")]
    PathError,
    #[error("Couldn't write config file")]
    SaveError,
    #[error("Couldn't serialize the data to save")]
    SerializeError,
    #[error("Couldn't create the config directory")]
    CreateDirError,
    #[error("Couldn't read the config file")]
    FileReadingError,
    #[error("Couldn't deserialize the config file")]
    DeserializeError,
    #[error("Couldn't delete the config file")]
    FileDeletionError,
}
impl ConfigError {}
