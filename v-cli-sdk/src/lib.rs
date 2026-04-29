use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::cmd::{auth::login::{CliMagicLinkAdapter, CliOAuthAdapter}, config::CliConfig};

pub mod cmd;
pub mod err;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerbosityLevel {
    None,
    All,
}

#[derive(Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Clone, Serialize, Deserialize)]
pub enum FormatStyle {
    #[value(name = "json")]
    Json,
    #[value(name = "tab")]
    Tab,
}

impl Display for FormatStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Tab => write!(f, "tab"),
        }
    }
}

pub trait CliContext<C, P> {
    type Attempt;
    type Token;
    type Error;

    fn config(&self) -> &impl CliConfig;
    fn config_mut(&mut self) -> &mut impl CliConfig;
    fn client(&self) -> Option<&C>;
    fn printer(&self) -> Option<&P>;
    fn verbosity(&self) -> VerbosityLevel;

    fn oauth_adapter(&self) -> impl CliOAuthAdapter<Token = Self::Token, Error = Self::Error>;
    fn mlink_adapter(&self) -> impl CliMagicLinkAdapter<Token = Self::Token, Error = Self::Error>;
}

pub trait ApiErrorMessage {
    fn message(&self) -> Option<&str>;
    fn error_code(&self) -> Option<&str>;
    fn request_id(&self) -> Option<&str>;
}
