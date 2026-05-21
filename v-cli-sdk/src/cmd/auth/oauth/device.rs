// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::CliOAuthProviderInfo;

/// Default polling interval in seconds per RFC 8628 §3.2.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Response from the v-api device authorization endpoint.
#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    interval: Option<u64>,
}

/// Request body sent to the v-api device authorization endpoint.
#[derive(Serialize)]
struct DeviceAuthorizationRequest {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// Request body sent to the v-api device token exchange endpoint.
#[derive(Serialize)]
struct DeviceTokenExchangeRequest {
    client_id: String,
    device_code: String,
    grant_type: String,
}

/// Successful token response from the v-api device token exchange endpoint.
#[derive(Debug, Deserialize)]
pub struct DeviceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

/// Error response from the v-api device token exchange endpoint.
#[derive(Debug, Deserialize)]
struct DeviceTokenError {
    error: String,
    #[allow(dead_code)]
    error_description: Option<String>,
}

/// Initiate a device authorization flow through the v-api proxy and poll until
/// the user completes authorization or the device code expires.
pub async fn login(provider: &impl CliOAuthProviderInfo) -> Result<DeviceTokenResponse> {
    let authz_endpoint = provider
        .device_authorization_endpoint()
        .ok_or_else(|| anyhow::anyhow!("Provider does not support device authorization"))?;
    let token_endpoint = provider
        .device_token_endpoint()
        .ok_or_else(|| anyhow::anyhow!("Provider does not support device token exchange"))?;

    let http = reqwest::Client::new();

    // Step 1: Initiate device authorization
    let scope = {
        let s = provider.scopes();
        if s.is_empty() {
            None
        } else {
            Some(s.join(" "))
        }
    };

    let resp = http
        .post(authz_endpoint)
        .json(&DeviceAuthorizationRequest {
            client_id: provider.client_id().to_string(),
            scope,
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Device authorization failed ({}): {}", status, body);
    }

    let details: DeviceAuthorizationResponse = resp.json().await?;

    // Step 2: Display instructions to the user
    print_user_instructions(&details);

    // Step 3: Poll for the token
    poll_for_token(&http, token_endpoint, provider, &details).await
}

fn print_user_instructions(details: &DeviceAuthorizationResponse) {
    if let Some(complete_uri) = &details.verification_uri_complete {
        println!(
            "To complete login visit:\n\n  {}\n\nOr go to {} and enter code: {}\n",
            complete_uri, details.verification_uri, details.user_code,
        );
    } else {
        println!(
            "To complete login visit: {} and enter code: {}\n",
            details.verification_uri, details.user_code,
        );
    }
}

async fn poll_for_token(
    http: &reqwest::Client,
    token_endpoint: &str,
    provider: &impl CliOAuthProviderInfo,
    details: &DeviceAuthorizationResponse,
) -> Result<DeviceTokenResponse> {
    let interval = Duration::from_secs(details.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS));

    loop {
        tokio::time::sleep(interval).await;

        let resp = http
            .post(token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                serde_urlencoded::to_string(&DeviceTokenExchangeRequest {
                    client_id: provider.client_id().to_string(),
                    device_code: details.device_code.clone(),
                    grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                })
                .unwrap(),
            )
            .send()
            .await?;

        if resp.status().is_success() {
            let token: DeviceTokenResponse = resp.json().await?;
            return Ok(token);
        }

        // Parse the error to decide whether to keep polling or bail
        let body = resp.bytes().await?;
        let error: DeviceTokenError = serde_json::from_slice(&body).map_err(|_| {
            anyhow::anyhow!(
                "Device token exchange failed: {}",
                String::from_utf8_lossy(&body)
            )
        })?;

        match error.error.as_str() {
            "authorization_pending" | "slow_down" => continue,
            _ => anyhow::bail!(
                "Device authorization failed: {}",
                error.error_description.as_deref().unwrap_or(&error.error)
            ),
        }
    }
}
