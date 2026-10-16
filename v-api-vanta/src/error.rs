// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;
use v_api_param::ParamResolutionError;

#[derive(Debug, Error)]
pub enum VantaError {
    #[error("Failed to resolve the Vanta client secret")]
    Secret(#[from] ParamResolutionError),
    #[error("Failed to reach Vanta")]
    Request(#[from] reqwest::Error),
    #[error("Vanta returned {status} for {path}: {body}")]
    Response {
        status: reqwest::StatusCode,
        path: String,
        body: String,
    },
    /// A full state sync of nothing tells Vanta that every account it holds for this service has
    /// gone away, which is far more likely to be a failure to read the database than a service
    /// with no users at all.
    #[error("Refusing to sync an empty set of user accounts, which would deprecate every account")]
    NoUserAccounts,
}
