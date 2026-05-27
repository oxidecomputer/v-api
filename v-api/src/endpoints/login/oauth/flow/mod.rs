// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseOk};
use secrecy::ExposeSecret;
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

pub(crate) async fn complete_exchange<T>(
    ctx: &VContext<T>,
    mut info: UserInfo,
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
    request_idp_token: bool,
    upstream_token: Option<String>,
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

    // Revoke the upstream access token whenever it will NOT be returned to the caller.
    // This covers the cases where the token was never requested, where the user lacks
    // the RetrieveRemoteAccessToken permission, and where the provider did not return
    // a token at all.
    if !provide_idp_token && let Some(upstream) = upstream_token {
        revoke_upstream_token(provider, &upstream).await;
    }

    tracing::info!(api_user_id = ?api_user_info.user.id, "Retrieved api user to generate access token for");

    let scope = attempt
        .scope
        .as_deref()
        .map(|s| {
            s.split(' ')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

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

/// Revoke an upstream IdP access token if the provider supports revocation.
/// Failures are logged but do not propagate — callers should not fail the
/// overall exchange just because revocation was unsuccessful.
async fn revoke_upstream_token(provider: &dyn OAuthProvider, token_secret: &str) {
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
        let access_token = oauth2::AccessToken::new(token_secret.to_string());
        match client.revoke_token(access_token.into()) {
            Ok(req) => {
                if let Err(err) = req.request_async(&oauth_client).await {
                    tracing::warn!(?err, "Failed to revoke upstream IdP access token");
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
