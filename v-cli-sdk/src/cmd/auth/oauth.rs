// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::StandardDeviceAuthorizationResponse;
use oauth2::{
    AuthType, AuthUrl, ClientId, CsrfToken, DeviceAuthorizationUrl, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, RedirectUrl, Scope, StandardTokenResponse, TokenUrl,
};
use reqwest::Url;
use tokio::sync::oneshot;

use crate::cmd::auth::login::CliAdapterToken;

use super::proxy::run_proxy_server;

pub trait CliOAuthAdapter {
    type Token: CliAdapterToken;
    type Error: StdError + Send + Sync + 'static;

    fn provider(
        &self,
        provider: &super::login::LoginProvider,
    ) -> Pin<Box<dyn Future<Output = Result<impl CliOAuthProviderInfo, Self::Error>> + Send>>;
    fn exchange_authorization_code(
        &self,
        request: Request<Incoming>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, Self::Error>> + Send>>;
    fn get_long_lived_token(
        &self,
        access_token: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Token, Self::Error>> + Send>>;
}

pub trait CliOAuthProviderInfo {
    fn device_code_endpoint(&self) -> Option<&str>;
    fn code_redirect_proxy_endpoint(&self) -> Option<&str>;
    fn auth_url_endpoint(&self) -> &str;
    fn token_endpoint(&self) -> &str;
    fn client_id(&self) -> &str;
    fn scopes(&self) -> &[String];
}

type CodeClient = BasicClient<
    // HasAuthUrl
    EndpointSet,
    // HasDeviceAuthUrl
    EndpointNotSet,
    // HasIntrospectionUrl
    EndpointNotSet,
    // HasRevocationUrl
    EndpointNotSet,
    // HasTokenUrl
    EndpointSet,
>;

pub struct CodeOAuth {
    client: CodeClient,
    scopes: Vec<String>,
    port: u16,
}

impl CodeOAuth {
    pub fn new<T>(provider: T) -> Result<Self>
    where
        T: CliOAuthProviderInfo,
    {
        let redirect_url = provider
            .code_redirect_proxy_endpoint()
            .ok_or_else(|| anyhow::anyhow!("Provider does not support code redirect proxy flow"))?;

        let parsed_url = Url::parse(redirect_url)?;

        let port = parsed_url.port().ok_or_else(|| {
            anyhow::anyhow!("Provider proxy url does not have a defined port to listen on")
        })?;

        if parsed_url.scheme() != "http" {
            anyhow::bail!("Provider proxy url scheme must be http");
        }

        if parsed_url
            .host_str()
            .map(|h| h != "localhost" && h != "127.0.0.1")
            .unwrap_or(true)
        {
            anyhow::bail!("Provider proxy url host must be localhost");
        }

        let client = BasicClient::new(ClientId::new(provider.client_id().to_string()))
            .set_auth_uri(AuthUrl::new(provider.auth_url_endpoint().to_string())?)
            .set_auth_type(AuthType::RequestBody)
            .set_token_uri(TokenUrl::new(provider.token_endpoint().to_string())?)
            .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

        Ok(Self {
            client,
            scopes: provider.scopes().iter().map(|s| s.to_string()).collect(),
            port,
        })
    }

    /// Build the authorization URL that the user should visit in a browser.
    /// Returns the full URL and the CSRF state token used for verification.
    pub fn authorize_url(&self) -> (oauth2::url::Url, CsrfToken) {
        let mut req = self.client.authorize_url(CsrfToken::new_random);

        for scope in &self.scopes {
            req = req.add_scope(Scope::new(scope.to_string()));
        }

        req.url()
    }

    /// Run the full authorization code login flow:
    ///
    /// 1. Generate the authorization URL and print it for the user.
    /// 2. Spin up a local HTTP proxy server to capture the IdP redirect.
    /// 3. Forward the redirect request to the API server via the adapter.
    /// 4. Extract the token from the server's response.
    /// 5. Return a success page to the browser and shut down the proxy.
    pub async fn login<T>(&self, adapter: Arc<T>) -> Result<String>
    where
        T: CliOAuthAdapter + Send + Sync + 'static,
    {
        let (auth_url, _csrf_state) = self.authorize_url();

        println!(
            "Open the following URL in your browser to authenticate:\n\n  {}\n",
            auth_url
        );

        // Channel to receive the token extracted from the server response.
        let (token_tx, token_rx) = oneshot::channel::<Result<String>>();
        let token_tx: Arc<Mutex<Option<oneshot::Sender<Result<String>>>>> =
            Arc::new(Mutex::new(Some(token_tx)));

        // Channel to shut down the proxy server once we have the token.
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let port = self.port;

        // Spawn the local proxy server in a background task.
        tokio::spawn({
            let callback_token_tx = Arc::clone(&token_tx);
            let error_token_tx = Arc::clone(&token_tx);

            async move {
                let callback = Arc::new(move |request: Request<Incoming>| {
                    let adapter = Arc::clone(&adapter);
                    let token_tx = Arc::clone(&callback_token_tx);

                    Box::pin(async move {
                        // Forward the redirect request to the API server.
                        let response = adapter
                            .exchange_authorization_code(request)
                            .await
                            .map_err(|e| anyhow::anyhow!(e))?;

                        // The server responds with the access token in the body.
                        let (_parts, body) = response.into_parts();
                        let body_bytes = body
                            .collect()
                            .await
                            .expect("Full<Bytes> collection cannot fail")
                            .to_bytes();
                        let token = String::from_utf8(body_bytes.to_vec())?;

                        // Send the token back to the main task.
                        if let Ok(mut guard) = token_tx.lock() {
                            if let Some(tx) = guard.take() {
                                let _ = tx.send(Ok(token));
                            }
                        }

                        // Return a friendly page to the browser so the user
                        // knows they can close the tab.
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Full::new(Bytes::from(concat!(
                                "<html><body>",
                                "<h1>Authentication successful!</h1>",
                                "<p>You can close this tab and return to the CLI.</p>",
                                "</body></html>"
                            ))))?)
                    })
                        as Pin<
                            Box<dyn Future<Output = anyhow::Result<Response<Full<Bytes>>>> + Send>,
                        >
                });

                if let Err(e) = run_proxy_server(port, callback, shutdown_rx).await {
                    eprintln!("Proxy server error: {e}");

                    // If the proxy died before we got a token, unblock the
                    // receiver so the caller isn't stuck forever.
                    if let Ok(mut guard) = error_token_tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(Err(anyhow::anyhow!(
                                "Proxy server exited unexpectedly: {e}"
                            )));
                        }
                    }
                }
            }
        });

        // Wait for the proxy callback to extract the token.
        let token = token_rx.await.map_err(|_| {
            anyhow::anyhow!(
                "Authentication callback was never received — proxy server may have exited early"
            )
        })??;

        // Tell the proxy server to stop.
        let _ = shutdown_tx.send(());

        Ok(token)
    }
}

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
    pub fn new<T>(provider: T) -> Result<Self>
    where
        T: CliOAuthProviderInfo,
    {
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
                scopes: provider.scopes().iter().map(|s| s.to_string()).collect(),
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
