// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use anyhow::Result;
use uuid::Uuid;

use crate::cmd::auth::login::LoginProvider;

use super::{
    CliOAuthAdapter, DeviceAccessTokenResponse, DeviceAuthorizationRequest,
    DeviceAuthorizationResponse, DeviceTokenExchange,
};

/// Default polling interval in seconds per RFC 8628 §3.2.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Initiate a device authorization flow through the v-api proxy and poll until
/// the user completes authorization or the device code expires.
pub async fn login<T>(
    adapter: &T,
    provider: LoginProvider,
    client_id: Uuid,
    scope: Option<String>,
) -> Result<T::ShortToken>
where
    T: CliOAuthAdapter,
{
    let details = adapter
        .initiate_device_authorization(DeviceAuthorizationRequest {
            provider,
            client_id,
            scope,
        })
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    print_user_instructions(&details);

    poll_for_token(adapter, provider, client_id, &details).await
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

async fn poll_for_token<T>(
    adapter: &T,
    provider: LoginProvider,
    client_id: Uuid,
    details: &DeviceAuthorizationResponse,
) -> Result<T::ShortToken>
where
    T: CliOAuthAdapter,
{
    let interval = Duration::from_secs(details.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS));
    let grant_type = "urn:ietf:params:oauth:grant-type:device_code".to_string();

    loop {
        tokio::time::sleep(interval).await;

        let result = adapter
            .exchange_device_token(DeviceTokenExchange {
                provider,
                client_id,
                device_code: details.device_code.clone(),
                grant_type: grant_type.clone(),
            })
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        match result {
            DeviceAccessTokenResponse::Pending => continue,
            DeviceAccessTokenResponse::Token(token) => return Ok(token),
        }
    }
}
