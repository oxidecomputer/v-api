// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::instrument;

use crate::{
    VantaConfig, VantaError,
    resource::{CustomResource, SyncRequest, UserAccount},
};

/// The only scope a private integration needs to report resources.
const WRITE_RESOURCE_SCOPE: &str = "connectors.self:write-resource";

/// How long before expiry a cached token is replaced. Vanta issues hour long tokens, and this
/// leaves room for a long sync to finish on the token it started with.
const EXPIRY_MARGIN: Duration = Duration::from_secs(120);

#[derive(Debug, Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    scope: &'a str,
    grant_type: &'a str,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

struct CachedToken {
    value: String,
    /// When the token stops being usable, already reduced by [`EXPIRY_MARGIN`]
    usable_until: Instant,
}

/// Reports resources to one service's Vanta private integration.
pub struct VantaClient {
    http: reqwest::Client,
    base_url: String,
    client_id: String,
    client_secret: SecretString,
    user_account_resource_id: String,
    group_resource_id: Option<String>,
    api_key_resource_id: Option<String>,
    token: Mutex<Option<CachedToken>>,
}

impl VantaClient {
    /// Resolve the configured secret and build a client.
    ///
    /// `base` is the directory that a file backed client secret is resolved relative to, matching
    /// how the rest of a service's params are loaded.
    pub fn new(config: &VantaConfig, base: Option<&Path>) -> Result<Self, VantaError> {
        Ok(Self {
            http: reqwest::Client::new(),
            base_url: config.base_url.trim_end_matches('/').to_string(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.resolve(base)?,
            user_account_resource_id: config.user_account_resource_id.clone(),
            group_resource_id: config.group_resource_id.clone(),
            api_key_resource_id: config.api_key_resource_id.clone(),
            token: Mutex::new(None),
        })
    }

    pub fn group_resource_id(&self) -> Option<&str> {
        self.group_resource_id.as_deref()
    }

    pub fn api_key_resource_id(&self) -> Option<&str> {
        self.api_key_resource_id.as_deref()
    }

    /// A token that is valid now, reusing the cached one when it has life left.
    ///
    /// Vanta keeps a single active token per application and revokes the previous one whenever a
    /// new one is issued, so the lock is held across the request. Two callers racing here would
    /// otherwise each mint a token and invalidate the other's.
    async fn access_token(&self) -> Result<String, VantaError> {
        let mut cached = self.token.lock().await;

        if let Some(token) = cached.as_ref()
            && Instant::now() < token.usable_until
        {
            return Ok(token.value.clone());
        }

        let path = "/oauth/token";
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(&TokenRequest {
                client_id: &self.client_id,
                client_secret: self.client_secret.expose_secret(),
                scope: WRITE_RESOURCE_SCOPE,
                grant_type: "client_credentials",
            })
            .send()
            .await?;

        let response = error_for_status(response, path).await?;
        let token = response.json::<TokenResponse>().await?;

        let usable_until =
            Instant::now() + Duration::from_secs(token.expires_in).saturating_sub(EXPIRY_MARGIN);
        let value = token.access_token.clone();
        *cached = Some(CachedToken {
            value: token.access_token,
            usable_until,
        });

        Ok(value)
    }

    /// Report the complete set of user accounts.
    #[instrument(skip(self, accounts), fields(accounts = accounts.len()))]
    pub async fn sync_user_accounts(&self, accounts: Vec<UserAccount>) -> Result<(), VantaError> {
        if accounts.is_empty() {
            return Err(VantaError::NoUserAccounts);
        }

        self.put(
            "/v1/resources/user_account",
            &SyncRequest {
                resource_id: self.user_account_resource_id.clone(),
                resources: accounts,
            },
        )
        .await
    }

    /// Report the complete set of one custom resource.
    ///
    /// An empty set is allowed here, unlike user accounts: a service really can have no groups or
    /// no API keys, and Vanta needs to be told when the last one goes away.
    #[instrument(skip(self, resources), fields(resources = resources.len()))]
    pub async fn sync_custom_resources<P>(
        &self,
        resource_id: &str,
        resources: Vec<CustomResource<P>>,
    ) -> Result<(), VantaError>
    where
        P: Serialize,
    {
        self.put(
            "/v1/resources/custom_resource",
            &SyncRequest {
                resource_id: resource_id.to_string(),
                resources,
            },
        )
        .await
    }

    async fn put<B>(&self, path: &str, body: &B) -> Result<(), VantaError>
    where
        B: Serialize,
    {
        let token = self.access_token().await?;

        let response = self
            .http
            .put(format!("{}{path}", self.base_url))
            .bearer_auth(token)
            .json(body)
            .send()
            .await?;

        error_for_status(response, path).await?;

        Ok(())
    }
}

/// Carry the response body into the error. Vanta reports schema and resource id problems in the
/// body, and without it a failed sync only says that something was rejected.
async fn error_for_status(
    response: reqwest::Response,
    path: &str,
) -> Result<reqwest::Response, VantaError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().await.unwrap_or_default();

    Err(VantaError::Response {
        status,
        path: path.to_string(),
        body,
    })
}
