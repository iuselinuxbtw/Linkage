use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Couldn't get home directory")]
    PathError,
}
impl ConfigError {
    pub fn get_exit_code(&self) -> i32 {
        match self {
            _ => 1,
        }
    }
}
