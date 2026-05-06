use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};

use oauth2::{
    basic::BasicClient, AuthType, AuthUrl, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, RedirectUrl, Scope, TokenUrl,
};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::cmd::auth::{
    oauth::{CliOAuthAdapter, CliOAuthProviderInfo},
    proxy::run_proxy_server,
};

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
    client_id: Uuid,
    redirect_uri: String,
    scopes: Vec<String>,
    port: u16,
}

impl CodeOAuth {
    pub fn new<T>(provider: T) -> Result<Self>
    where
        T: CliOAuthProviderInfo,
    {
        let client = BasicClient::new(ClientId::new(provider.client_id().to_string()))
            .set_auth_uri(AuthUrl::new(
                provider
                    .auth_url_endpoint()
                    .ok_or_else(|| {
                        anyhow::anyhow!("OAuth code flow provider must define an authorization url")
                    })?
                    .to_string(),
            )?)
            .set_auth_type(AuthType::RequestBody)
            .set_token_uri(TokenUrl::new(provider.token_endpoint().to_string())?)
            .set_redirect_uri(RedirectUrl::new(
                provider
                    .redirect_endpoint()
                    .ok_or_else(|| {
                        anyhow::anyhow!("OAuth code flow provider must define a redirect url")
                    })?
                    .to_string(),
            )?);

        Ok(Self {
            client,
            client_id: provider.client_id(),
            redirect_uri: provider.redirect_endpoint().unwrap_or_default().to_string(),
            scopes: provider.scopes().iter().map(|s| s.to_string()).collect(),
            port: provider.public_pkce_port().ok_or_else(|| {
                anyhow::anyhow!("OAuth code flow provider must define a public proxy port")
            })?,
        })
    }

    /// Build the authorization URL that the user should visit in a browser.
    /// Returns the full URL and the CSRF state token used for verification.
    pub fn authorize_url(
        &self,
        pkce_challenge: PkceCodeChallenge,
    ) -> (oauth2::url::Url, CsrfToken) {
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);

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
    pub async fn login<T>(&self, adapter: Arc<T>, request_idp_token: bool) -> Result<T::ShortToken>
    where
        T: CliOAuthAdapter + Send + Sync + 'static,
    {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, _csrf_state) = self.authorize_url(pkce_challenge);

        println!(
            "Open the following URL in your browser to authenticate:\n\n  {}\n",
            auth_url
        );

        // Channel to receive the token extracted from the server response.
        let (token_tx, token_rx) = oneshot::channel::<Result<T::ShortToken>>();
        #[allow(clippy::type_complexity)]
        let token_tx: Arc<Mutex<Option<oneshot::Sender<Result<T::ShortToken>>>>> =
            Arc::new(Mutex::new(Some(token_tx)));

        // Channel to shut down the proxy server once we have the token.
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let port = self.port;

        // Spawn the local proxy server in a background task.
        tokio::spawn({
            let callback_token_tx = Arc::clone(&token_tx);
            let error_token_tx = Arc::clone(&token_tx);
            let client_id = self.client_id;
            let redirect_uri = self.redirect_uri.clone();

            async move {
                let callback: crate::cmd::auth::proxy::Callback = Arc::new(Mutex::new(Some(
                    Box::new(move |request: Request<Incoming>| {
                        let adapter = Arc::clone(&adapter);
                        let token_tx = Arc::clone(&callback_token_tx);

                        Box::pin(async move {
                            let code = request
                                .uri()
                                .query()
                                .and_then(|q: &str| {
                                    q.split('&')
                                        .filter_map(|pair: &str| pair.split_once('='))
                                        .find(|(key, _): &(&str, &str)| *key == "code")
                                        .map(|(_, value): (&str, &str)| value.to_string())
                                })
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "Missing 'code' query parameter in callback request"
                                    )
                                })?;

                            // Forward the redirect request to the API server.
                            let token = adapter
                                .exchange_authorization_code(
                                    super::AuthorizationCodeExchange {
                                        provider: crate::cmd::auth::login::LoginProvider::Zendesk,
                                        client_id,
                                        redirect_uri: redirect_uri.clone(),
                                        grant_type: "authorization_code".to_string(),
                                        code,
                                        pkce_verifier,
                                        request_idp_token,
                                    },
                                )
                                .await
                                .map_err(|e| anyhow::anyhow!(e))?;

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
                                "<script>window.close();</script>",
                                "<p>Authentication successful. This window should close automatically.</p>",
                                "</body></html>"
                            ))))?)
                        })
                            as Pin<
                                Box<
                                    dyn Future<Output = anyhow::Result<Response<Full<Bytes>>>>
                                        + Send,
                                >,
                            >
                    }),
                )));

                if let Err(e) = run_proxy_server(port, callback, shutdown_rx).await {
                    eprintln!("Proxy server error: {e}");

                    // If the proxy died before we got a token, unblock the
                    // receiver so the caller is not stuck forever.
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
