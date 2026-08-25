// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseOk};
use oauth2::StandardRevocableToken;
use secrecy::{ExposeSecret, SecretString};
use v_model::{LoginAttempt, permissions::PermissionStorage};

use super::OAuthProvider;
use crate::{
    context::VContext,
    endpoints::login::UserInfo,
    permissions::{VAppPermission, VPermission},
};

pub mod code;
pub mod device_token;

pub use code::OAuthAuthzCodeExchangeResponse;

/// Tokens issued by the upstream identity provider during a code exchange.
///
/// These are held separately from [`UserInfo`] so that the caller can decide,
/// after the permission check has run, whether to hand them back to the client
/// or revoke them.
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
        revoke_upstream_tokens(provider, &upstream).await;
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

/// Revoke every upstream IdP token that will not be handed back to the caller.
///
/// The refresh token is revoked first because, per RFC 7009 §2.1, revoking a
/// refresh token also invalidates the access tokens issued under the same
/// grant. The access token is revoked afterwards for providers that do not
/// cascade.
async fn revoke_upstream_tokens(provider: &dyn OAuthProvider, upstream: &UpstreamTokens) {
    if let Some(refresh_token) = &upstream.refresh_token {
        revoke_upstream_token(
            provider,
            oauth2::RefreshToken::new(refresh_token.expose_secret().to_string()).into(),
        )
        .await;
    }

    if let Some(access_token) = &upstream.access_token {
        revoke_upstream_token(
            provider,
            oauth2::AccessToken::new(access_token.expose_secret().to_string()).into(),
        )
        .await;
    }
}

/// Revoke a single upstream IdP token if the provider supports revocation.
/// Failures are logged but do not propagate — callers should not fail the
/// overall exchange just because revocation was unsuccessful.
async fn revoke_upstream_token(provider: &dyn OAuthProvider, token: StandardRevocableToken) {
    let provider_info = match provider.authz_code_flow_info() {
        Some(info) => info,
        None => return,
    };

    if provider_info.remote.revocation_endpoint.is_some() {
        let client = match provider.as_web_client() {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "Failed to build web client for upstream token revocation"
                );
                return;
            }
        };
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
    } else {
        tracing::debug!("Provider does not support token revocation")
    }
}
