//! Configuration loading, parsing, and validation for the DHCP server.

mod types;
pub(crate) mod validation;

pub use types::*;

use std::path::Path;
use thiserror::Error;

/// Errors that can occur when loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the configuration file from disk.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse the TOML configuration content.
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    /// Configuration values failed semantic validation.
    #[error("validation error: {0}")]
    Validation(String),
}

impl Config {
    /// Load configuration from a TOML file, parsing and validating all values.
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(Path::new(path))?;
        let config: Config = toml::from_str(&contents)?;
        validation::validate(&config)?;
        Ok(config)
    }
}
