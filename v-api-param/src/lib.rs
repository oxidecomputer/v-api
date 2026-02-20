// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Parameter string utilities for configuration.
//!
//! This crate provides a [`StringParam`] type that can be deserialized from either
//! an inline value or a file path, allowing parameters to be stored outside of
//! configuration files.
//!
//! # TOML Usage
//!
//! Inline value:
//! ```toml
//! key = "my-parameter-value"
//! ```
//!
//! Path-based value (reads parameter from file at runtime):
//! ```toml
//! key = { path = "/run/parameters/my-key" }
//! ```

use secrecy::SecretString;
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParamResolutionError {
    #[error("Failed to read param from path '{path}'")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// A param string that can be specified either inline or as a path to a file.
///
/// When deserialized from TOML/JSON, accepts either:
/// - A plain string: `"my-param"`
/// - An object with path: `{ path = "/path/to/param" }`
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StringParam {
    /// Param value specified directly inline
    Inline(SecretString),
    /// Path to a file containing the param
    FromPath { path: PathBuf },
}

impl StringParam {
    /// Resolves the param value, reading from file if necessary.
    ///
    /// For inline values, returns the value directly.
    /// For path-based values, reads the file contents and trims trailing whitespace.
    pub fn resolve(&self) -> Result<SecretString, ParamResolutionError> {
        match self {
            StringParam::Inline(value) => Ok(value.clone()),
            StringParam::FromPath { path } => {
                let content = std::fs::read_to_string(path).map_err(|source| {
                    ParamResolutionError::FileRead {
                        path: path.display().to_string(),
                        source,
                    }
                })?;
                // Trim trailing whitespace/newlines that are common in param files
                Ok(content.trim_end().to_string().into())
            }
        }
    }
}

impl Default for StringParam {
    fn default() -> Self {
        StringParam::Inline(SecretString::default())
    }
}

impl From<String> for StringParam {
    fn from(value: String) -> Self {
        StringParam::Inline(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_inline_value() {
        let param = StringParam::Inline("my-param".to_string().into());
        assert_eq!(param.resolve().unwrap().expose_secret(), "my-param");
    }

    #[test]
    fn test_from_path() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "file-param").unwrap();

        let param = StringParam::FromPath {
            path: file.path().to_path_buf(),
        };
        assert_eq!(param.resolve().unwrap().expose_secret(), "file-param");
    }

    #[test]
    fn test_from_path_trims_trailing_whitespace() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "file-param").unwrap();
        writeln!(file).unwrap();

        let param = StringParam::FromPath {
            path: file.path().to_path_buf(),
        };
        assert_eq!(param.resolve().unwrap().expose_secret(), "file-param");
    }

    #[test]
    fn test_from_path_file_not_found() {
        let param = StringParam::FromPath {
            path: PathBuf::from("/nonexistent/path"),
        };
        let result = param.resolve();
        assert!(matches!(result, Err(ParamResolutionError::FileRead { .. })));
    }

    #[test]
    fn test_deserialize_inline() {
        let toml = r#"key = "inline-value""#;

        #[derive(Deserialize)]
        struct Config {
            key: StringParam,
        }

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            config.key.resolve().unwrap().expose_secret(),
            "inline-value"
        );
    }

    #[test]
    fn test_deserialize_from_path() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "path-value").unwrap();

        let toml = format!(r#"key = {{ path = "{}" }}"#, file.path().display());

        #[derive(Deserialize)]
        struct Config {
            key: StringParam,
        }

        let config: Config = toml::from_str(&toml).unwrap();
        assert_eq!(config.key.resolve().unwrap().expose_secret(), "path-value");
    }
}
