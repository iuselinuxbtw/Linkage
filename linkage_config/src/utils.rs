use std::path;

use home::home_dir;

use crate::error::ConfigError::PathError;

/// Gets the home directory under Linux as well as Windows.
/// # Panics
/// When the home directory cannot be found, this function will panic, though this should be fine
/// because it (theoretically) should not happen.
pub fn get_home_dir() -> path::PathBuf {
    match home_dir() {
        Some(path) => path,
        None => panic!("{}", PathError),
    }
}

/// Returns the configuration directory for Linkage.
pub fn get_config_dir() -> path::PathBuf {
    // TODO: This is Linux-only
    get_home_dir().join(".config/linkage/")
}
