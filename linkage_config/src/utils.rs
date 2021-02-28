use crate::error::ConfigError::PathError;
use home::home_dir;
use std::path;

/// Gets the home directory under Linux as well as Linux.
pub fn get_home_dir() -> path::PathBuf {
    match home_dir() {
        Some(path) => path,
        None => panic!(PathError),
    }
}
