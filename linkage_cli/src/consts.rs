//! Contains various constants that are used throughout the whole application.

/// The name of the application.
pub const APP_NAME: &str = "Linkage";
/// The version of the app. Uses the version from `Cargo.toml`.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The author of the application.
pub const APP_AUTHOR: &str = "BitJerkers not incorporated";
/// Short description of the application.
pub const APP_ABOUT: &str = "An open-source VPN manager.";