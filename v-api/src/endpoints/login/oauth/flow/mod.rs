// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpCodedResponse, HttpError, HttpResponseHeaders, HttpResponseOk};
use http::{
    HeaderMap, HeaderValue,
    header::{CACHE_CONTROL, PRAGMA},
};
use oauth2::{
    ClientId, ClientSecret, EndpointNotSet, EndpointSet, RevocationUrl, StandardRevocableToken,
    basic::BasicClient,
};
use secrecy::{ExposeSecret, SecretString};
use v_model::{LoginAttempt, permissions::PermissionStorage};

use super::OAuthProvider;
use crate::{
    context::VContext,
    endpoints::login::UserInfo,
    permissions::{VAppPermission, VPermission},
};
use error::{OAuthErrorCode, OAuthErrorResponse};

pub mod client_credentials;
pub mod code;
pub mod device_token;
pub mod error;

pub use code::OAuthAuthzCodeExchangeResponse;

/// The grant type recorded on login attempts that run through the device flow (RFC 8628 §3.4)
pub(crate) const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The scope a client requested, once it has been checked to parse. An absent or empty scope
/// means no permissions, and the special scope "full" asks for every permission the principal
/// holds.
pub(crate) fn requested_scope<T>(scope: Option<&str>) -> Result<String, OAuthErrorResponse>
where
    T: VAppPermission,
{
    let scope = scope.unwrap_or_default();
    match T::from_scope_arg(scope) {
        Ok(_) => Ok(scope.to_string()),
        Err(err) => {
            tracing::warn!(?err, ?scope, "Client requested an invalid scope");
            Err(OAuthErrorResponse::new(
                OAuthErrorCode::InvalidScope,
                Some(format!("Invalid scope: {scope}").as_str()),
            ))
        }
    }
}

/// Marks a response that carries an access token as one that must never be cached. Required by
/// RFC 6749 §5.1
pub(crate) fn mark_uncacheable(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

/// Wraps a token response body in the headers RFC 6749 §5.1 requires of it
pub(crate) fn token_response<T>(body: T) -> HttpResponseHeaders<T>
where
    T: HttpCodedResponse,
{
    let mut response = HttpResponseHeaders::new_unnamed(body);
    mark_uncacheable(response.headers_mut());
    response
}

/// Tokens issued by the upstream identity provider during a code exchange.
#[derive(Default)]
pub(crate) struct UpstreamTokens {
    pub access_token: Option<SecretString>,
    pub refresh_token: Option<SecretString>,
}

pub(crate) async fn complete_exchange<T>(
    ctx: &VContext<T>,
    mut info: UserInfo,
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
    request_idp_token: bool,
    upstream: UpstreamTokens,
) -> Result<HttpResponseOk<OAuthAuthzCodeExchangeResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let idp_token = info.idp_token.take();

    // Register this user as an API user if needed
    let (api_user_info, api_user_provider) = ctx
        .register_api_user(&ctx.builtin_registration_user(), info)
        .await?;

    // Only return the IdP token if the caller requested it AND the user has permission.
    // We must resolve the full caller (including group permissions) rather than checking
    // only the directly assigned user permissions.
    let provide_idp_token =
        should_provide_idp_token(ctx, request_idp_token, &api_user_info).await?;

    // Revoke the upstream tokens whenever they will NOT be returned to the caller.
    // This covers the cases where the tokens were never requested, where the user lacks
    // the RetrieveRemoteAccessToken permission, and where the provider did not return
    // a token at all. Refresh tokens are long lived, so it is important that we do not
    // simply drop one that we requested but are not handing back.
    if !provide_idp_token {
        revoke_upstream_tokens(provider, attempt, &upstream).await;
    }

    tracing::info!(api_user_id = ?api_user_info.user.id, "Retrieved api user to generate access token for");

    let scope = attempt
        .scope
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let token = ctx
        .generate_access_token(
            &ctx.builtin_registration_user(),
            &api_user_info.user.id,
            &api_user_provider.id,
            attempt.client_id.to_string(),
            scope,
        )
        .await?;

    Ok(HttpResponseOk(OAuthAuthzCodeExchangeResponse {
        token_type: "Bearer".to_string(),
        access_token: token.signed_token,
        expires_in: token.expires_in,
        scope: attempt.scope.clone(),
        idp_token: if provide_idp_token {
            idp_token.map(|s| s.expose_secret().to_string())
        } else {
            None
        },
        idp_refresh_token: if provide_idp_token {
            upstream
                .refresh_token
                .as_ref()
                .map(|s| s.expose_secret().to_string())
        } else {
            None
        },
    }))
}

/// Determine if a user is allowed to retrieve the IdP token based on whether it was
/// requested and whether the user has the `RetrieveRemoteAccessToken` permission
pub(crate) async fn should_provide_idp_token<T>(
    ctx: &VContext<T>,
    requested: bool,
    api_user_info: &v_model::ApiUserInfo<T>,
) -> Result<bool, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    if requested {
        // Resolve the caller so that group-inherited permissions are included in the
        // permission check, not just directly-assigned user permissions.
        let caller = ctx
            .user
            .resolve_caller(api_user_info, crate::context::BasePermissions::Full)
            .await
            .map_err(|err| {
                HttpError::for_internal_error(format!(
                    "Failed to resolve caller permissions for IdP token check: {}",
                    err
                ))
            })?;

        if caller
            .permissions
            .can(&VPermission::RetrieveRemoteAccessToken.into())
        {
            Ok(true)
        } else {
            tracing::info!(
                "User requested IdP token but lacks RetrieveRemoteAccessToken permission"
            );
            Ok(false)
        }
    } else {
        Ok(false)
    }
}

/// An upstream client that can only revoke tokens
type RevocationClient =
    BasicClient<EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet, EndpointNotSet>;

/// Builds the client that revocations for a login attempt are sent as.
fn revocation_client(
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
) -> Option<RevocationClient> {
    let (client_id, client_secret, endpoint) = if attempt.grant_type == DEVICE_CODE_GRANT_TYPE {
        let remote = &provider.device_code_flow_info()?.remote;
        (
            &remote.client_id,
            &remote.client_secret,
            remote.revocation_endpoint.as_ref()?,
        )
    } else {
        let remote = &provider.authz_code_flow_info()?.remote;
        (
            &remote.client_id,
            &remote.client_secret,
            remote.revocation_endpoint.as_ref()?,
        )
    };

    let revocation_url = RevocationUrl::new(endpoint.clone())
        .inspect_err(|err| tracing::warn!(?err, "Provider revocation endpoint is not a valid URL"))
        .ok()?;

    Some(
        BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(
                client_secret.0.expose_secret().to_string(),
            ))
            .set_revocation_url(revocation_url),
    )
}

/// Revoke every upstream IdP token that will not be handed back to the caller.
///
/// Per RFC 7009 §2.1, revoking a refresh token invalidates the access tokens
/// issued under the same grant. We revoke the access tokens as well in the
/// event the provider fails to cascade.
pub(crate) async fn revoke_upstream_tokens(
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
    upstream: &UpstreamTokens,
) {
    let client = match revocation_client(provider, attempt) {
        Some(client) => client,
        None => {
            tracing::debug!("Provider does not support token revocation");
            return;
        }
    };

    if let Some(refresh_token) = &upstream.refresh_token {
        revoke_upstream_token(
            provider,
            &client,
            oauth2::RefreshToken::new(refresh_token.expose_secret().to_string()).into(),
        )
        .await;
    }

    if let Some(access_token) = &upstream.access_token {
        revoke_upstream_token(
            provider,
            &client,
            oauth2::AccessToken::new(access_token.expose_secret().to_string()).into(),
        )
        .await;
    }
}

/// Revoke a single upstream IdP token. Failures are logged but do not propagate, since the
/// overall exchange should not fail just because revocation was unsuccessful.
async fn revoke_upstream_token(
    provider: &dyn OAuthProvider,
    client: &RevocationClient,
    token: StandardRevocableToken,
) {
    let oauth_client: oauth2_reqwest::ReqwestClient = provider.client().clone().into();
    match client.revoke_token(token) {
        Ok(req) => {
            if let Err(err) = req.request_async(&oauth_client).await {
                tracing::warn!(?err, "Failed to revoke upstream IdP token");
            }
        }
        Err(err) => {
            tracing::warn!(
                ?err,
                "Failed to build revocation request for upstream token"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use dropshot::{HttpResponse, HttpResponseOk};
    use http::header::{CACHE_CONTROL, PRAGMA};

    use super::token_response;

    /// Every token response forbids caching, as RFC 6749 §5.1 requires
    #[test]
    fn token_responses_are_never_cached() {
        let response = token_response(HttpResponseOk(())).to_result().unwrap();

        assert_eq!(
            Some("no-store"),
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
        );
        assert_eq!(
            Some("no-cache"),
            response
                .headers()
                .get(PRAGMA)
                .and_then(|value| value.to_str().ok())
        );
    }
}
