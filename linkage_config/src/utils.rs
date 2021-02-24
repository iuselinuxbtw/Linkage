use crate::error::ConfigError::PathError;
use home::home_dir;
use std::path;

pub fn get_home_dir() -> path::PathBuf {
    match home_dir() {
        Some(path) => path,
        None => panic!(PathError),
    }
}
