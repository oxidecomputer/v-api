// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::{
    AuthType, AuthUrl, ClientId, DeviceAuthorizationUrl, EmptyExtraTokenFields, EndpointNotSet,
    EndpointSet, Scope, StandardTokenResponse, TokenUrl,
};
use oauth2::StandardDeviceAuthorizationResponse;

type DeviceClient = BasicClient<
    // HasAuthUrl
    EndpointSet,
    // HasDeviceAuthUrl
    EndpointSet,
    // HasIntrospectionUrl
    EndpointNotSet,
    // HasRevocationUrl
    EndpointNotSet,
    // HasTokenUrl
    EndpointSet,
>;

pub struct DeviceOAuth {
    client: DeviceClient,
    http: oauth2_reqwest::ReqwestClient,
    scopes: Vec<String>,
}

impl DeviceOAuth {
    pub fn new<T>(provider: T) -> Result<Self> where T: CliOAuthProviderInfo {
        if let Some(device_endpoint) = provider.device_code_endpoint() {
            let device_auth_url = DeviceAuthorizationUrl::new(device_endpoint.to_string())?;

            let client = BasicClient::new(ClientId::new(provider.client_id().to_string()))
                .set_auth_uri(AuthUrl::new(provider.auth_url_endpoint().to_string())?)
                .set_auth_type(AuthType::RequestBody)
                .set_token_uri(TokenUrl::new(provider.token_endpoint().to_string())?)
                .set_device_authorization_url(device_auth_url);

            Ok(Self {
                client,
                http: oauth2_reqwest::ReqwestClient::from(
                    reqwest::ClientBuilder::new()
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .unwrap(),
                ),
                scopes: provider.scopes().into_iter().map(|s| s.to_string()).collect(),
            })
        } else {
            anyhow::bail!("Device authorization is not supported by this provider")
        }
    }

    pub async fn login(
        &self,
        details: &StandardDeviceAuthorizationResponse,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
        let token = self
            .client
            .exchange_device_access_token(details)
            .set_max_backoff_interval(details.interval())
            .request_async(&self.http, tokio::time::sleep, Some(details.expires_in()))
            .await;

        Ok(token?)
    }

    pub async fn get_device_authorization(&self) -> Result<StandardDeviceAuthorizationResponse> {
        let mut req = self.client.exchange_device_code();

        for scope in &self.scopes {
            req = req.add_scope(Scope::new(scope.to_string()));
        }

        let res = req.request_async(&self.http).await;

        Ok(res?)
    }
}

pub trait CliOAuthProviderInfo {
    fn device_code_endpoint(&self) -> Option<&str>;
    fn auth_url_endpoint(&self) -> &str;
    fn token_endpoint(&self) -> &str;
    fn client_id(&self) -> &str;
    fn scopes(&self) -> &[String];
}
