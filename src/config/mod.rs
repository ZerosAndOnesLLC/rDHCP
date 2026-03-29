mod types;
pub(crate) mod validation;

pub use types::*;

use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("validation error: {0}")]
    Validation(String),
}

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(Path::new(path))?;
        let config: Config = toml::from_str(&contents)?;
        validation::validate(&config)?;
        Ok(config)
    }
}
