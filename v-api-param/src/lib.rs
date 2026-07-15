// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Parameter utilities for configuration.
//!
//! This crate provides parameter types that can be deserialized from either an
//! inline value or a file path, allowing parameters to be stored outside of
//! configuration files.
//!
//! - [`StringParam`] resolves to a [`SecretString`], reading the raw file
//!   contents when a path is given.
//! - [`SerializedParam`] resolves to an arbitrary `T`, deserializing the file
//!   contents using a [`ParamFormat`] marker (for example [`Json`] or
//!   [`Toml`]). This is useful when the file contents are themselves a
//!   structured document whose shape and size are only known at runtime.
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

use serde::{Deserialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub use secrecy::SecretString;

#[derive(Debug, Error)]
pub enum ParamResolutionError {
    #[error("Failed to read param from path '{path}'")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to deserialize param from path '{path}'")]
    Deserialize {
        path: String,
        #[source]
        source: FormatError,
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
    pub fn resolve(&self, base: Option<&Path>) -> Result<SecretString, ParamResolutionError> {
        match self {
            StringParam::Inline(value) => Ok(value.clone()),
            StringParam::FromPath { path } => {
                let path = resolve_path(base, path);
                let content = read_to_string(&path)?;
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

/// A param that can be specified either inline or as a path to a file whose
/// contents are deserialized into `T` using the format `F`. A common use is
/// configuration whose *shape* is fixed but whose *contents* are only known
/// at runtime:
///
/// ```toml
/// # a config file that is identical across environments
/// silos = { path = "/run/parameters/silos.json" }
/// ```
///
/// ```rust
/// # use std::collections::HashMap;
/// # use v_api_param::{SerializedParam, Json};
/// // The file at the path above is deserialized as JSON into `T`.
/// type Silos = SerializedParam<HashMap<String, String>, Json>;
/// ```
///
/// Like [`StringParam`], path-relative resolution against an optional base
/// directory is supported. The path variant is tried first when deserializing,
/// so `{ path = "..." }` is unambiguous even when `T` is itself a map or
/// struct.
pub struct SerializedParam<T, F> {
    source: Source<T>,
    _format: PhantomData<fn() -> F>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Source<T> {
    /// Path to a file whose contents are deserialized at resolve time.
    FromPath { path: PathBuf },
    /// Value specified directly inline in the configuration.
    Inline(T),
}

impl<T: Clone> Clone for Source<T> {
    fn clone(&self) -> Self {
        match self {
            Source::FromPath { path } => Source::FromPath { path: path.clone() },
            Source::Inline(value) => Source::Inline(value.clone()),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Source<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::FromPath { path } => f.debug_struct("FromPath").field("path", path).finish(),
            Source::Inline(value) => f.debug_tuple("Inline").field(value).finish(),
        }
    }
}

impl<T, F> SerializedParam<T, F> {
    /// Construct a param that holds an inline value.
    pub fn inline(value: T) -> Self {
        Self {
            source: Source::Inline(value),
            _format: PhantomData,
        }
    }

    /// Construct a param that reads its value from the given path.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self {
            source: Source::FromPath { path: path.into() },
            _format: PhantomData,
        }
    }
}

impl<T, F> SerializedParam<T, F>
where
    T: DeserializeOwned + Clone,
    F: ParamFormat,
{
    /// Resolves the param value, reading and deserializing the file if necessary.
    ///
    /// For inline values, returns a clone of the value directly. For path-based
    /// values, reads the file contents and deserializes them using `F`. When
    /// `base` is provided, relative paths are resolved against it.
    pub fn resolve(&self, base: Option<&Path>) -> Result<T, ParamResolutionError> {
        match &self.source {
            Source::Inline(value) => Ok(value.clone()),
            Source::FromPath { path } => {
                let path = resolve_path(base, path);
                let content = read_to_string(&path)?;
                F::deserialize_str(&content).map_err(|source| ParamResolutionError::Deserialize {
                    path: path.display().to_string(),
                    source,
                })
            }
        }
    }
}

impl<'de, T, F> Deserialize<'de> for SerializedParam<T, F>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self {
            source: Source::deserialize(deserializer)?,
            _format: PhantomData,
        })
    }
}

impl<T: Clone, F> Clone for SerializedParam<T, F> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            _format: PhantomData,
        }
    }
}

impl<T: std::fmt::Debug, F> std::fmt::Debug for SerializedParam<T, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerializedParam")
            .field("source", &self.source)
            .finish()
    }
}

/// A serialization format a [`SerializedParam`] file can be deserialized from.
///
/// Implemented by the marker types [`Json`] and [`Toml`] (each gated behind the
/// feature of the same name), but downstream crates may implement it for other
/// formats as well.
pub trait ParamFormat {
    /// Deserialize a value of type `T` from the textual `content`.
    fn deserialize_str<T: DeserializeOwned>(content: &str) -> Result<T, FormatError>;
}

/// Errors produced while deserializing a [`SerializedParam`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FormatError {
    #[cfg(feature = "json")]
    #[error("Failed to deserialize as JSON")]
    Json(#[from] serde_json::Error),
    #[cfg(feature = "toml")]
    #[error("Failed to deserialize as TOML")]
    Toml(#[from] toml::de::Error),
}

/// Marker type selecting JSON deserialization for a [`SerializedParam`].
#[cfg(feature = "json")]
#[derive(Debug, Clone, Copy)]
pub struct Json;

#[cfg(feature = "json")]
impl ParamFormat for Json {
    fn deserialize_str<T: DeserializeOwned>(content: &str) -> Result<T, FormatError> {
        Ok(serde_json::from_str(content)?)
    }
}

/// A [`SerializedParam`] that deserializes its file contents as JSON.
#[cfg(feature = "json")]
pub type JsonParam<T> = SerializedParam<T, Json>;

/// Marker type selecting TOML deserialization for a [`SerializedParam`].
#[cfg(feature = "toml")]
#[derive(Debug, Clone, Copy)]
pub struct Toml;

#[cfg(feature = "toml")]
impl ParamFormat for Toml {
    fn deserialize_str<T: DeserializeOwned>(content: &str) -> Result<T, FormatError> {
        Ok(toml::from_str(content)?)
    }
}

/// A [`SerializedParam`] that deserializes its file contents as TOML.
#[cfg(feature = "toml")]
pub type TomlParam<T> = SerializedParam<T, Toml>;

fn resolve_path(base: Option<&Path>, path: &Path) -> PathBuf {
    match base {
        Some(base) => base.join(path),
        None => path.to_path_buf(),
    }
}

fn read_to_string(path: &Path) -> Result<String, ParamResolutionError> {
    std::fs::read_to_string(path).map_err(|source| ParamResolutionError::FileRead {
        path: path.display().to_string(),
        source,
    })
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
        assert_eq!(param.resolve(None).unwrap().expose_secret(), "my-param");
    }

    #[test]
    fn test_from_path() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "file-param").unwrap();

        let param = StringParam::FromPath {
            path: file.path().to_path_buf(),
        };
        assert_eq!(param.resolve(None).unwrap().expose_secret(), "file-param");
    }

    #[test]
    fn test_from_path_with_base() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "file-param").unwrap();

        let param = StringParam::FromPath {
            path: PathBuf::from(file.path().file_name().unwrap()),
        };
        let base_path = std::env::temp_dir();

        assert_eq!(
            param.resolve(Some(&base_path)).unwrap().expose_secret(),
            "file-param"
        );
    }

    #[test]
    fn test_from_path_trims_trailing_whitespace() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "file-param").unwrap();
        writeln!(file).unwrap();

        let param = StringParam::FromPath {
            path: file.path().to_path_buf(),
        };
        assert_eq!(param.resolve(None).unwrap().expose_secret(), "file-param");
    }

    #[test]
    fn test_from_path_file_not_found() {
        let param = StringParam::FromPath {
            path: PathBuf::from("/nonexistent/path"),
        };
        let result = param.resolve(None);
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
            config.key.resolve(None).unwrap().expose_secret(),
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
        assert_eq!(
            config.key.resolve(None).unwrap().expose_secret(),
            "path-value"
        );
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_serialized_json_from_path() {
        use std::collections::HashMap;

        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{ "a": "1", "b": "2" }}"#).unwrap();

        let param: JsonParam<HashMap<String, String>> =
            SerializedParam::from_path(file.path());
        let resolved = param.resolve(None).unwrap();

        assert_eq!(resolved.get("a").map(String::as_str), Some("1"));
        assert_eq!(resolved.get("b").map(String::as_str), Some("2"));
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_serialized_json_from_path_with_base() {
        use std::collections::HashMap;

        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{ "a": "1" }}"#).unwrap();

        let param: JsonParam<HashMap<String, String>> =
            SerializedParam::from_path(file.path().file_name().unwrap());
        let base = std::env::temp_dir();

        let resolved = param.resolve(Some(&base)).unwrap();
        assert_eq!(resolved.get("a").map(String::as_str), Some("1"));
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_serialized_json_deserialize_path_variant() {
        // A `{ path = ... }` entry must resolve to the path variant even though
        // `T` is a map that could otherwise absorb the `path` key.
        use std::collections::HashMap;

        let mut file = NamedTempFile::new().unwrap();
        write!(file, r#"{{ "hello": "world" }}"#).unwrap();

        let toml = format!(r#"key = {{ path = "{}" }}"#, file.path().display());

        #[derive(Deserialize)]
        struct Config {
            key: JsonParam<HashMap<String, String>>,
        }

        let config: Config = toml::from_str(&toml).unwrap();
        let resolved = config.key.resolve(None).unwrap();
        assert_eq!(resolved.get("hello").map(String::as_str), Some("world"));
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_serialized_inline_value() {
        use std::collections::HashMap;

        let mut expected = HashMap::new();
        expected.insert("a".to_string(), "1".to_string());

        let param: JsonParam<HashMap<String, String>> = SerializedParam::inline(expected.clone());
        assert_eq!(param.resolve(None).unwrap(), expected);
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_serialized_deserialize_error() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "not valid json").unwrap();

        let param: JsonParam<std::collections::HashMap<String, String>> =
            SerializedParam::from_path(file.path());
        assert!(matches!(
            param.resolve(None),
            Err(ParamResolutionError::Deserialize { .. })
        ));
    }

    #[cfg(feature = "toml")]
    #[test]
    fn test_serialized_toml_from_path() {
        use std::collections::HashMap;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "a = \"1\"").unwrap();
        writeln!(file, "b = \"2\"").unwrap();

        let param: TomlParam<HashMap<String, String>> = SerializedParam::from_path(file.path());
        let resolved = param.resolve(None).unwrap();

        assert_eq!(resolved.get("a").map(String::as_str), Some("1"));
        assert_eq!(resolved.get("b").map(String::as_str), Some("2"));
    }
}
