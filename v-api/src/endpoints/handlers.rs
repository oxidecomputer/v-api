// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[rustfmt::skip]
mod macros {
    #[macro_export]
    macro_rules! v_system_endpoints {
        ($context_type:ident, $permission_type:ident) => {
            use dropshot::{
                endpoint, HttpError, HttpResponseCreated, HttpResponseHeaders, HttpResponseOk,
                HttpResponseTemporaryRedirect, HttpResponseUpdatedNoContent, Path, Query,
                RequestContext, TypedBody, Body,
            };
            use http::Response;
            use v_api::authn::client_key::SubmittedJwk;
            use v_model::{Mapper, ApiUserContactEmail, OAuthClient, OAuthClientKey, OAuthClientRedirectUri, OAuthClientSecret, AccessGroup, ApiUser, MagicLink, MagicLinkRedirectUri, MagicLinkSecret};

            use v_api::endpoints::{
                api_user::{
                    add_api_user_permission_op, add_api_user_to_group_op, create_api_user_token_op,
                    delete_api_user_token_op, get_api_user_op, list_api_user_op, get_api_user_token_op, get_self_op,
                    link_provider_op, list_api_user_tokens_op, remove_api_user_from_group_op, remove_api_user_permission_op,
                    set_api_user_contact_email_op, list_api_users_for_group_op,
                    AddGroupBody, ApiKeyCreateParams, ApiKeyResponse, ApiUserPath,
                    ApiUserPermissionParams, ApiUserProviderLinkPayload, ApiUserRemoveGroupPath, ApiUserTokenPath,
                    GetUserResponse, InitialApiKeyResponse, ApiUserEmailUpdateParams, ApiUserGroupPath
                },
                api_user_provider::{
                    create_link_token_op, ApiUserLinkRequestPayload, ApiUserLinkRequestResponse,
                    ApiUserProviderPath,
                },
                group::{
                    add_group_permission_op, create_group_op, delete_group_op, get_groups_op,
                    remove_group_permission_op, AccessGroupPath,
                    AccessGroupPermissionParams, AccessGroupUpdateParams,
                },
                login::{
                    magic_link:: {
                        client::{
                            create_magic_link_op,
                            get_magic_link_op,
                            GetMagicLinkPath,
                            list_magic_links_op,
                            create_magic_link_secret_op,
                            AddMagicLinkSecretPath,
                            InitialMagicLinkSecretResponse,
                            delete_magic_link_secret_op,
                            DeleteMagicLinkSecretPath,
                            create_magic_link_redirect_uri_op,
                            AddMagicLinkRedirectPath,
                            AddMagicLinkRedirectBody,
                            delete_magic_link_redirect_uri_op,
                            DeleteMagicLinkRedirectPath,
                        },
                        magic_link_send_op,
                        magic_link_exchange_op,
                        MagicLinkSendRequest,
                        MagicLinkSendResponse,
                        MagicLinkExchangeRequest,
                        MagicLinkExchangeResponse,
                        MagicLinkPath,
                    },
                    oauth::{
                        client::{
                            add_oauth_client_key_op, add_oauth_client_permission_op,
                            get_oauth_client_permissions_op, remove_oauth_client_permission_op,
                            list_service_account_tokens_op, ListServiceAccountTokensPath,
                            revoke_service_account_token_op, RevokeServiceAccountTokenPath,
                            OAuthClientPermissionParams, OAuthClientPermissionPath,
                            create_oauth_client_op,
                            create_oauth_client_redirect_uri_op, create_oauth_client_secret_op,
                            delete_oauth_client_key_op, delete_oauth_client_redirect_uri_op,
                            delete_oauth_client_secret_op,
                            get_oauth_client_op, list_oauth_clients_op, AddOAuthClientKeyPath,
                            AddOAuthClientRedirectBody, AddOAuthClientRedirectPath,
                            AddOAuthClientSecretPath, DeleteOAuthClientKeyPath,
                            DeleteOAuthClientRedirectPath, DeleteOAuthClientSecretPath,
                            GetOAuthClientPath, InitialOAuthClientSecretResponse,
                        },
                        flow::client_credentials::{
                            client_credentials_token_op, ClientCredentialsTokenBody,
                            ClientCredentialsTokenResponse,
                        },
                        flow::code::{
                            authz_code_callback_op, authz_code_exchange_op, authz_code_redirect_op,
                            get_public_pkce_provider_op,
                            OAuthAuthzCodeExchangeBody, OAuthAuthzCodeExchangeResponse, OAuthAuthzCodeExchangeQuery,
                            OAuthAuthzCodeQuery, OAuthAuthzCodeReturnQuery,
                        },
                        flow::device_token::{
                            exchange_device_token_op, device_authz_op, get_device_provider_op,
                            DeviceTokenExchangeRequest, DeviceAuthorizationRequest,
                        },
                        OAuthProviderNameParam, OAuthProviderAuthorizationCodePkceInfo,
                        OAuthProviderDeviceInfo
                    }
                },
                mappers::{
                    create_mapper_op, delete_mapper_op, get_mappers_op, CreateMapper, ListMappersQuery,
                    MapperPath,
                },
                well_known::{jwks_json_op, openid_configuration_op, Jwks, OpenIdConfiguration},
            };

            // OAUTH CLIENT

            /// List OAuth clients
            #[endpoint {
                method = GET,
                path = "/oauth/client"
            }]
            pub async fn list_oauth_clients(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<Vec<OAuthClient>>, HttpError> {
                list_oauth_clients_op(&rqctx).await
            }

            /// Create a new OAuth Client
            #[endpoint {
                method = POST,
                path = "/oauth/client"
            }]
            pub async fn create_oauth_client(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseCreated<OAuthClient>, HttpError> {
                create_oauth_client_op(&rqctx).await
            }

            /// Get an new OAuth Client
            #[endpoint {
                method = GET,
                path = "/oauth/client/{client_id}"
            }]
            pub async fn get_oauth_client(
                rqctx: RequestContext<$context_type>,
                path: Path<GetOAuthClientPath>,
            ) -> Result<HttpResponseOk<OAuthClient>, HttpError> {
                get_oauth_client_op(&rqctx, path).await
            }

            /// Add an OAuth client secret
            #[endpoint {
                method = POST,
                path = "/oauth/client/{client_id}/secret"
            }]
            pub async fn create_oauth_client_secret(
                rqctx: RequestContext<$context_type>,
                path: Path<AddOAuthClientSecretPath>,
            ) -> Result<HttpResponseOk<InitialOAuthClientSecretResponse>, HttpError> {
                create_oauth_client_secret_op(&rqctx, path).await
            }

            /// Delete an OAuth client secret
            #[endpoint {
                method = DELETE,
                path = "/oauth/client/{client_id}/secret/{secret_id}"
            }]
            pub async fn delete_oauth_client_secret(
                rqctx: RequestContext<$context_type>,
                path: Path<DeleteOAuthClientSecretPath>,
            ) -> Result<HttpResponseOk<OAuthClientSecret>, HttpError> {
                delete_oauth_client_secret_op(&rqctx, path).await
            }

            /// Add an OAuth client redirect uri
            #[endpoint {
                method = POST,
                path = "/oauth/client/{client_id}/redirect_uri"
            }]
            pub async fn create_oauth_client_redirect_uri(
                rqctx: RequestContext<$context_type>,
                path: Path<AddOAuthClientRedirectPath>,
                body: TypedBody<AddOAuthClientRedirectBody>,
            ) -> Result<HttpResponseOk<OAuthClientRedirectUri>, HttpError> {
                create_oauth_client_redirect_uri_op(&rqctx, path, body).await
            }

            /// Delete an OAuth client redirect uri
            #[endpoint {
                method = DELETE,
                path = "/oauth/client/{client_id}/redirect_uri/{redirect_uri_id}"
            }]
            pub async fn delete_oauth_client_redirect_uri(
                rqctx: RequestContext<$context_type>,
                path: Path<DeleteOAuthClientRedirectPath>,
            ) -> Result<HttpResponseOk<OAuthClientRedirectUri>, HttpError> {
                delete_oauth_client_redirect_uri_op(&rqctx, path).await
            }

            /// List the permissions an OAuth client's service account has
            #[endpoint {
                method = GET,
                path = "/oauth/client/{client_id}/service-account/permission"
            }]
            pub async fn get_oauth_client_permissions(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthClientPermissionPath>,
            ) -> Result<HttpResponseOk<v_model::Permissions<$permission_type>>, HttpError> {
                get_oauth_client_permissions_op(&rqctx, path).await
            }

            /// Grant a permission to an OAuth client's service account
            #[endpoint {
                method = POST,
                path = "/oauth/client/{client_id}/service-account/permission"
            }]
            pub async fn add_oauth_client_permission(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthClientPermissionPath>,
                body: TypedBody<OAuthClientPermissionParams<$permission_type>>,
            ) -> Result<HttpResponseOk<v_model::Permissions<$permission_type>>, HttpError> {
                add_oauth_client_permission_op(&rqctx, path, body.into_inner()).await
            }

            /// Remove a permission from an OAuth client's service account
            #[endpoint {
                method = DELETE,
                path = "/oauth/client/{client_id}/service-account/permission"
            }]
            pub async fn remove_oauth_client_permission(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthClientPermissionPath>,
                body: TypedBody<OAuthClientPermissionParams<$permission_type>>,
            ) -> Result<HttpResponseOk<v_model::Permissions<$permission_type>>, HttpError> {
                remove_oauth_client_permission_op(&rqctx, path, body.into_inner()).await
            }

            /// List the service account tokens issued to an OAuth client that have neither
            /// expired nor been revoked
            #[endpoint {
                method = GET,
                path = "/oauth/client/{client_id}/service-account/token"
            }]
            pub async fn list_service_account_tokens(
                rqctx: RequestContext<$context_type>,
                path: Path<ListServiceAccountTokensPath>,
            ) -> Result<HttpResponseOk<Vec<v_model::ServiceAccountToken>>, HttpError> {
                list_service_account_tokens_op(&rqctx, path).await
            }

            /// Revoke one of the service account tokens issued to an OAuth client
            #[endpoint {
                method = DELETE,
                path = "/oauth/client/{client_id}/service-account/token/{token_id}"
            }]
            pub async fn revoke_service_account_token(
                rqctx: RequestContext<$context_type>,
                path: Path<RevokeServiceAccountTokenPath>,
            ) -> Result<HttpResponseOk<v_model::ServiceAccountToken>, HttpError> {
                revoke_service_account_token_op(&rqctx, path).await
            }

            /// Register a public key for an OAuth client's client credential authentication
            #[endpoint {
                method = POST,
                path = "/oauth/client/{client_id}/service-account/key"
            }]
            pub async fn add_oauth_client_key(
                rqctx: RequestContext<$context_type>,
                path: Path<AddOAuthClientKeyPath>,
                body: TypedBody<SubmittedJwk>,
            ) -> Result<HttpResponseOk<OAuthClientKey>, HttpError> {
                add_oauth_client_key_op(&rqctx, path, body).await
            }

            /// Remove a public key from an OAuth client
            #[endpoint {
                method = DELETE,
                path = "/oauth/client/{client_id}/service-account/key/{key_id}"
            }]
            pub async fn delete_oauth_client_key(
                rqctx: RequestContext<$context_type>,
                path: Path<DeleteOAuthClientKeyPath>,
            ) -> Result<HttpResponseOk<OAuthClientKey>, HttpError> {
                delete_oauth_client_key_op(&rqctx, path).await
            }

            // MAGIC LINK CLIENT

            /// List Magic Link clients
            #[endpoint {
                method = GET,
                path = "/magic/client"
            }]
            pub async fn list_magic_links(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<Vec<MagicLink>>, HttpError> {
                list_magic_links_op(&rqctx).await
            }

            /// Create a new Magic Link Client
            #[endpoint {
                method = POST,
                path = "/magic/client"
            }]
            pub async fn create_magic_link(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseCreated<MagicLink>, HttpError> {
                create_magic_link_op(&rqctx).await
            }

            /// Get a Magic Link Client
            #[endpoint {
                method = GET,
                path = "/magic/client/{client_id}"
            }]
            pub async fn get_magic_link(
                rqctx: RequestContext<$context_type>,
                path: Path<GetMagicLinkPath>,
            ) -> Result<HttpResponseOk<MagicLink>, HttpError> {
                get_magic_link_op(&rqctx, path).await
            }

            /// Add a Magic Link client secret
            #[endpoint {
                method = POST,
                path = "/magic/client/{client_id}/secret"
            }]
            pub async fn create_magic_link_secret(
                rqctx: RequestContext<$context_type>,
                path: Path<AddMagicLinkSecretPath>,
            ) -> Result<HttpResponseOk<InitialMagicLinkSecretResponse>, HttpError> {
                create_magic_link_secret_op(&rqctx, path).await
            }

            /// Delete a Magic Link client secret
            #[endpoint {
                method = DELETE,
                path = "/magic/client/{client_id}/secret/{secret_id}"
            }]
            pub async fn delete_magic_link_secret(
                rqctx: RequestContext<$context_type>,
                path: Path<DeleteMagicLinkSecretPath>,
            ) -> Result<HttpResponseOk<MagicLinkSecret>, HttpError> {
                delete_magic_link_secret_op(&rqctx, path).await
            }

            /// Add a Magic Link client redirect uri
            #[endpoint {
                method = POST,
                path = "/magic/client/{client_id}/redirect_uri"
            }]
            pub async fn create_magic_link_redirect_uri(
                rqctx: RequestContext<$context_type>,
                path: Path<AddMagicLinkRedirectPath>,
                body: TypedBody<AddMagicLinkRedirectBody>,
            ) -> Result<HttpResponseOk<MagicLinkRedirectUri>, HttpError> {
                create_magic_link_redirect_uri_op(&rqctx, path, body).await
            }

            /// Delete a Magic Link client redirect uri
            #[endpoint {
                method = DELETE,
                path = "/magic/client/{client_id}/redirect_uri/{redirect_uri_id}"
            }]
            pub async fn delete_magic_link_redirect_uri(
                rqctx: RequestContext<$context_type>,
                path: Path<DeleteMagicLinkRedirectPath>,
            ) -> Result<HttpResponseOk<MagicLinkRedirectUri>, HttpError> {
                delete_magic_link_redirect_uri_op(&rqctx, path).await
            }

            // LOGIN ENDPOINTS

            // AUTHORIZATION CODE FLOW

            /// Generate the remote provider login url and redirect the user
            #[endpoint {
                method = GET,
                path = "/login/oauth/{provider}/code/authorize"
            }]
            pub async fn authz_code_redirect(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
                query: Query<OAuthAuthzCodeQuery>,
            ) -> Result<HttpResponseTemporaryRedirect, v_api::endpoints::login::oauth::flow::error::OAuthErrorResponse> {
                authz_code_redirect_op(&rqctx, path, query).await
            }

            /// Handle return calls from a remote OAuth provider
            #[endpoint {
                method = GET,
                path = "/login/oauth/{provider}/code/callback"
            }]
            pub async fn authz_code_callback(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
                query: Query<OAuthAuthzCodeReturnQuery>,
            ) -> Result<HttpResponseTemporaryRedirect, HttpError> {
                authz_code_callback_op(&rqctx, path, query).await
            }

            /// Exchange an authorization code for an access token
            #[endpoint {
                method = POST,
                path = "/login/oauth/{provider}/code/token",
                content_type = "application/x-www-form-urlencoded",
            }]
            pub async fn authz_code_exchange(
                rqctx: RequestContext<$context_type>,
                query: Query<OAuthAuthzCodeExchangeQuery>,
                path: Path<OAuthProviderNameParam>,
                body: TypedBody<OAuthAuthzCodeExchangeBody>,
            ) -> Result<HttpResponseHeaders<HttpResponseOk<OAuthAuthzCodeExchangeResponse>>, v_api::endpoints::login::oauth::flow::error::OAuthErrorResponse> {
                authz_code_exchange_op(&rqctx, query, path, body).await
            }

            // AUTHORIZATION CODE PKCE ONLY FLOW

            /// Retrieve the metadata about an OAuth provider for public PKCE authorization code flow
            #[endpoint {
                method = GET,
                path = "/login/oauth/{provider}/public-pkce"
            }]
            pub async fn get_web_pkce_provider(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
            ) -> Result<HttpResponseOk<OAuthProviderAuthorizationCodePkceInfo>, HttpError> {
                get_public_pkce_provider_op(&rqctx, path).await
            }

            // DEVICE CODE FLOW

            /// Retrieve the metadata about an OAuth provider for device authorization flow
            #[endpoint {
                method = GET,
                path = "/login/oauth/{provider}/device"
            }]
            pub async fn get_device_provider(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
            ) -> Result<HttpResponseOk<OAuthProviderDeviceInfo>, HttpError> {
                get_device_provider_op(&rqctx, path).await
            }

            /// Initiate a device authorization flow by proxying the request to the
            /// upstream OAuth provider. Creates a login attempt and returns the
            /// upstream device authorization response.
            #[endpoint {
                method = POST,
                path = "/login/oauth/{provider}/device"
            }]
            pub async fn device_authz(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
                body: TypedBody<DeviceAuthorizationRequest>,
            ) -> Result<Response<Body>, v_api::endpoints::login::oauth::flow::error::OAuthErrorResponse> {
                device_authz_op(&rqctx, path, body).await
            }

            /// Exchange an OAuth device code for an access token. The client polls
            /// this endpoint until the user completes authorization.
            #[endpoint {
                method = POST,
                path = "/login/oauth/{provider}/device/exchange",
                content_type = "application/x-www-form-urlencoded",
            }]
            pub async fn exchange_device_token(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
                body: TypedBody<DeviceTokenExchangeRequest>,
            ) -> Result<Response<Body>, v_api::endpoints::login::oauth::flow::error::OAuthErrorResponse> {
                exchange_device_token_op(&rqctx, path, body).await
            }

            // CLIENT CREDENTIALS

            /// Issue an access token to an OAuth client for authenticating as a service account
            #[endpoint {
                method = POST,
                path = "/oauth/token",
                content_type = "application/x-www-form-urlencoded",
            }]
            pub async fn client_credentials_token(
                rqctx: RequestContext<$context_type>,
                body: TypedBody<ClientCredentialsTokenBody>,
            ) -> Result<HttpResponseHeaders<HttpResponseOk<ClientCredentialsTokenResponse>>, v_api::endpoints::login::oauth::flow::error::OAuthErrorResponse> {
                client_credentials_token_op(&rqctx, body).await
            }

            // MAGIC LINK

            /// Send a new magic link authentication link
            #[endpoint {
                method = POST,
                path = "/login/magic/{channel}/send"
            }]
            pub async fn magic_link_send(
                rqctx: RequestContext<$context_type>,
                path: Path<MagicLinkPath>,
                body: TypedBody<MagicLinkSendRequest>,
            ) -> Result<HttpResponseOk<MagicLinkSendResponse>, HttpError> {
              magic_link_send_op(&rqctx, path, body).await
            }

            /// Exchange a magic link access code for an access token
            #[endpoint {
                method = POST,
                path = "/login/magic/{channel}/exchange"
            }]
            pub async fn magic_link_exchange(
                rqctx: RequestContext<$context_type>,
                _path: Path<MagicLinkPath>,
                body: TypedBody<MagicLinkExchangeRequest>,
            ) -> Result<HttpResponseHeaders<HttpResponseOk<MagicLinkExchangeResponse>>, HttpError> {
              magic_link_exchange_op(&rqctx, body).await
            }

            // WELL KNOWN

            #[endpoint {
                method = GET,
                path = "/.well-known/openid-configuration",
            }]
            pub async fn openid_configuration(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<OpenIdConfiguration>, HttpError> {
                openid_configuration_op(&rqctx).await
            }

            #[endpoint {
                method = GET,
                path = "/.well-known/jwks.json",
            }]
            pub async fn jwks_json(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<Jwks>, HttpError> {
                jwks_json_op(&rqctx).await
            }

            // API USER PROVIDER

            /// Create a new link token for linking this provider to a different api user
            #[endpoint {
                method = POST,
                path = "/api-user-provider/{provider_id}/link-token",
            }]
            pub async fn create_link_token(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserProviderPath>,
                body: TypedBody<ApiUserLinkRequestPayload>,
            ) -> Result<HttpResponseOk<ApiUserLinkRequestResponse>, HttpError> {
                create_link_token_op(&rqctx, path, body).await
            }

            // API USER

            /// View details for the calling user
            #[endpoint {
                method = GET,
                path = "/self",
            }]
            pub async fn get_self(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<GetUserResponse<$permission_type>>, HttpError> {
                get_self_op(&rqctx).await
            }

            /// List details for users
            #[endpoint {
                method = GET,
                path = "/api-user",
            }]
            pub async fn list_api_users(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<Vec<GetUserResponse<$permission_type>>>, HttpError> {
                list_api_user_op(&rqctx).await
            }

            /// View details for a user
            #[endpoint {
                method = GET,
                path = "/api-user/{user_id}",
            }]
            pub async fn get_api_user(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
            ) -> Result<HttpResponseOk<GetUserResponse<$permission_type>>, HttpError> {
                get_api_user_op(&rqctx, path).await
            }

            /// Add a single permission to a user
            #[endpoint {
                method = POST,
                path = "/api-user/{user_id}/permission",
            }]
            pub async fn add_api_user_permission(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<ApiUserPermissionParams<$permission_type>>,
            ) -> Result<HttpResponseOk<GetUserResponse<$permission_type>>, HttpError> {
                add_api_user_permission_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// Remove a single permission from a user
            #[endpoint {
                method = DELETE,
                path = "/api-user/{user_id}/permission",
            }]
            pub async fn remove_api_user_permission(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<ApiUserPermissionParams<$permission_type>>,
            ) -> Result<HttpResponseOk<GetUserResponse<$permission_type>>, HttpError> {
                remove_api_user_permission_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// List api keys for a user
            #[endpoint {
                method = GET,
                path = "/api-user/{user_id}/token",
            }]
            pub async fn list_api_user_tokens(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
            ) -> Result<HttpResponseOk<Vec<ApiKeyResponse<$permission_type>>>, HttpError> {
                list_api_user_tokens_op(&rqctx, path.into_inner()).await
            }

            /// Create a new api key for a user
            #[endpoint {
                method = POST,
                path = "/api-user/{user_id}/token",
            }]
            pub async fn create_api_user_token(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<ApiKeyCreateParams<$permission_type>>,
            ) -> Result<HttpResponseCreated<InitialApiKeyResponse<$permission_type>>, HttpError> {
                create_api_user_token_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// View details of an api key for a user
            #[endpoint {
                method = GET,
                path = "/api-user/{user_id}/token/{api_key_id}",
            }]
            pub async fn get_api_user_token(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserTokenPath>,
            ) -> Result<HttpResponseOk<ApiKeyResponse<$permission_type>>, HttpError> {
                get_api_user_token_op(&rqctx, path.into_inner()).await
            }

            /// Revoke an api key for a user
            #[endpoint {
                method = DELETE,
                path = "/api-user/{user_id}/token/{api_key_id}",
            }]
            pub async fn delete_api_user_token(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserTokenPath>,
            ) -> Result<HttpResponseOk<ApiKeyResponse<$permission_type>>, HttpError> {
                delete_api_user_token_op(&rqctx, path.into_inner()).await
            }

            /// Set the contact email for a user
            #[endpoint {
                method = PUT,
                path = "/api-user/{user_id}/contact/email",
            }]
            pub async fn set_api_user_contact_email(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<ApiUserEmailUpdateParams>,
            ) -> Result<HttpResponseOk<ApiUserContactEmail>, HttpError> {
                set_api_user_contact_email_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// Add a user to a group
            #[endpoint {
                method = POST,
                path = "/api-user/{user_id}/group",
            }]
            pub async fn add_api_user_to_group(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<AddGroupBody>,
            ) -> Result<HttpResponseOk<GetUserResponse<$permission_type>>, HttpError> {
                add_api_user_to_group_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// Remove a user from a group
            #[endpoint {
                method = DELETE,
                path = "/api-user/{user_id}/group/{group_id}",
            }]
            pub async fn remove_api_user_from_group(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserRemoveGroupPath>,
            ) -> Result<HttpResponseOk<GetUserResponse<$permission_type>>, HttpError> {
                remove_api_user_from_group_op(&rqctx, path.into_inner()).await
            }

            /// Link an existing login provider to this user
            #[endpoint {
                method = POST,
                path = "/api-user/{user_id}/link",
            }]
            pub async fn link_provider(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<ApiUserProviderLinkPayload>,
            ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
                link_provider_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            // GROUPS

            /// List all groups
            #[endpoint {
                method = GET,
                path = "/group",
            }]
            pub async fn get_groups(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<Vec<AccessGroup<$permission_type>>>, HttpError> {
                get_groups_op(&rqctx).await
            }

            /// Create a group
            #[endpoint {
                method = POST,
                path = "/group",
            }]
            pub async fn create_group(
                rqctx: RequestContext<$context_type>,
                body: TypedBody<AccessGroupUpdateParams<$permission_type>>,
            ) -> Result<HttpResponseCreated<AccessGroup<$permission_type>>, HttpError> {
                create_group_op(&rqctx, body.into_inner()).await
            }

            /// Add a permission to a group
            #[endpoint {
                method = POST,
                path = "/group/{group_id}/permission",
            }]
            pub async fn add_group_permission(
                rqctx: RequestContext<$context_type>,
                path: Path<AccessGroupPath>,
                body: TypedBody<AccessGroupPermissionParams<$permission_type>>,
            ) -> Result<HttpResponseOk<AccessGroup<$permission_type>>, HttpError> {
                add_group_permission_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// Remove a permission from a group
            #[endpoint {
                method = DELETE,
                path = "/group/{group_id}/permission",
            }]
            pub async fn remove_group_permission(
                rqctx: RequestContext<$context_type>,
                path: Path<AccessGroupPath>,
                body: TypedBody<AccessGroupPermissionParams<$permission_type>>,
            ) -> Result<HttpResponseOk<AccessGroup<$permission_type>>, HttpError> {
                remove_group_permission_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// Delete a group
            #[endpoint {
                method = DELETE,
                path = "/group/{group_id}",
            }]
            pub async fn delete_group(
                rqctx: RequestContext<$context_type>,
                path: Path<AccessGroupPath>,
            ) -> Result<HttpResponseOk<AccessGroup<$permission_type>>, HttpError> {
                delete_group_op(&rqctx, path.into_inner()).await
            }

            /// Get members of a group
            #[endpoint {
                method = GET,
                path = "/group-membership/{group_id}",
            }]
            pub async fn get_group_members(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserGroupPath>,
            ) -> Result<HttpResponseOk<Vec<GetUserResponse<$permission_type>>>, HttpError> {
                list_api_users_for_group_op(&rqctx, path.into_inner()).await
            }

            // MAPPERS

            /// List all mappers
            #[endpoint {
                method = GET,
                path = "/mapper",
            }]
            pub async fn get_mappers(
                rqctx: RequestContext<$context_type>,
                query: Query<ListMappersQuery>,
            ) -> Result<HttpResponseOk<Vec<Mapper>>, HttpError> {
                get_mappers_op(&rqctx, query.into_inner()).await
            }

            /// Create a mapper
            #[endpoint {
                method = POST,
                path = "/mapper",
            }]
            pub async fn create_mapper(
                rqctx: RequestContext<$context_type>,
                body: TypedBody<CreateMapper>,
            ) -> Result<HttpResponseCreated<Mapper>, HttpError> {
                create_mapper_op(&rqctx, body.into_inner()).await
            }

            /// Delete a mapper
            #[endpoint {
                method = DELETE,
                path = "/mapper/{mapper_id}",
            }]
            pub async fn delete_mapper(
                rqctx: RequestContext<$context_type>,
                path: Path<MapperPath>,
            ) -> Result<HttpResponseOk<Mapper>, HttpError> {
                delete_mapper_op(&rqctx, path.into_inner()).await
            }

            #[cfg(feature = "local-dev")]
            use v_api::endpoints::login::local::{local_login_op, LocalLogin};

            #[cfg(feature = "local-dev")]
            /// Login as a local development user
            #[endpoint {
                method = POST,
                path = "/login/local"
            }]
            pub async fn local_login(
                rqctx: RequestContext<$context_type>,
                body: TypedBody<LocalLogin>,
            ) -> Result<Response<Body>, HttpError> {
                local_login_op(&rqctx, body).await
            }
        };
    }

    #[macro_export]
    macro_rules! inject_endpoints {
        ($api:ident) => {
            // .well-known
            $api.register(openid_configuration)
                .expect("Failed to register endpoint");
            $api.register(jwks_json)
                .expect("Failed to register endpoint");

            // User Management
            $api.register(get_self)
                .expect("Failed to register endpoint");
            $api.register(list_api_users)
                .expect("Failed to register endpoint");
            $api.register(get_api_user)
                .expect("Failed to register endpoint");
            $api.register(add_api_user_permission)
                .expect("Failed to register endpoint");
            $api.register(remove_api_user_permission)
                .expect("Failed to register endpoint");
            $api.register(set_api_user_contact_email)
                .expect("Failed to register endpoint");
            $api.register(list_api_user_tokens)
                .expect("Failed to register endpoint");
            $api.register(get_api_user_token)
                .expect("Failed to register endpoint");
            $api.register(create_api_user_token)
                .expect("Failed to register endpoint");
            $api.register(delete_api_user_token)
                .expect("Failed to register endpoint");
            $api.register(add_api_user_to_group)
                .expect("Failed to register endpoint");
            $api.register(remove_api_user_from_group)
                .expect("Failed to register endpoint");
            $api.register(get_group_members)
                .expect("Failed to register endpoint");
            $api.register(link_provider)
                .expect("Failed to register endpoint");
            $api.register(create_link_token)
                .expect("Failed to register endpoint");

            // Group Management
            $api.register(get_groups)
                .expect("Failed to register endpoint");
            $api.register(create_group)
                .expect("Failed to register endpoint");
            $api.register(add_group_permission)
                .expect("Failed to register endpoint");
            $api.register(remove_group_permission)
                .expect("Failed to register endpoint");
            $api.register(delete_group)
                .expect("Failed to register endpoint");

            // Mapper Management
            $api.register(get_mappers)
                .expect("Failed to register endpoint");
            $api.register(create_mapper)
                .expect("Failed to register endpoint");
            $api.register(delete_mapper)
                .expect("Failed to register endpoint");

            // OAuth Client Management
            $api.register(list_oauth_clients)
                .expect("Failed to register endpoint");
            $api.register(create_oauth_client)
                .expect("Failed to register endpoint");
            $api.register(get_oauth_client)
                .expect("Failed to register endpoint");
            $api.register(create_oauth_client_secret)
                .expect("Failed to register endpoint");
            $api.register(delete_oauth_client_secret)
                .expect("Failed to register endpoint");
            $api.register(create_oauth_client_redirect_uri)
                .expect("Failed to register endpoint");
            $api.register(delete_oauth_client_redirect_uri)
                .expect("Failed to register endpoint");
            $api.register(get_oauth_client_permissions)
                .expect("Failed to register endpoint");
            $api.register(add_oauth_client_permission)
                .expect("Failed to register endpoint");
            $api.register(remove_oauth_client_permission)
                .expect("Failed to register endpoint");
            $api.register(list_service_account_tokens)
                .expect("Failed to register endpoint");
            $api.register(revoke_service_account_token)
                .expect("Failed to register endpoint");
            $api.register(add_oauth_client_key)
                .expect("Failed to register endpoint");
            $api.register(delete_oauth_client_key)
                .expect("Failed to register endpoint");

            // OAuth Authorization Login
            $api.register(authz_code_redirect)
                .expect("Failed to register endpoint");
            $api.register(authz_code_callback)
                .expect("Failed to register endpoint");
            $api.register(authz_code_exchange)
                .expect("Failed to register endpoint");

            // OAuth Login
            $api.register(get_web_pkce_provider)
                .expect("Failed to register endpoint");
            $api.register(get_device_provider)
                .expect("Failed to register endpoint");
            $api.register(device_authz)
                .expect("Failed to register endpoint");
            $api.register(exchange_device_token)
                .expect("Failed to register endpoint");

            // Client Credentials
            $api.register(client_credentials_token)
                .expect("Failed to register endpoint");

            // Magic Link Client Management
            $api.register(list_magic_links)
                .expect("Failed to register endpoint");
            $api.register(create_magic_link)
                .expect("Failed to register endpoint");
            $api.register(get_magic_link)
                .expect("Failed to register endpoint");
            $api.register(create_magic_link_secret)
                .expect("Failed to register endpoint");
            $api.register(delete_magic_link_secret)
                .expect("Failed to register endpoint");
            $api.register(create_magic_link_redirect_uri)
                .expect("Failed to register endpoint");
            $api.register(delete_magic_link_redirect_uri)
                .expect("Failed to register endpoint");

            // Magic Link Login
            $api.register(magic_link_send)
                .expect("Failed to register endpoint");
            $api.register(magic_link_exchange)
                .expect("Failed to register endpoint");

            // Local development mock login
            #[cfg(feature = "local-dev")]
            $api.register(local_login)
                .expect("Failed to register endpoint");
        };
    }

    #[cfg(feature = "sagas")]
    #[macro_export]
    macro_rules! v_saga_endpoints {
        ($context_type:ident, $permission_type:ident) => {
            use dropshot::{PaginationParams, ResultsPage};
            use v_api::endpoints::saga::{
                list_sagas_op,
                view_saga_op,
                SagaDetailView,
                SagaPageSelector,
                SagaPath,
                SagaScanParams,
            };
            use v_model::saga::view::SagaView;

            /// List all sagas
            #[endpoint {
                method = GET,
                path = "/saga"
            }]
            pub async fn list_sagas(
                rqctx: RequestContext<$context_type>,
                query: Query<PaginationParams<SagaScanParams, SagaPageSelector>>,
            ) -> Result<HttpResponseOk<ResultsPage<SagaView>>, HttpError> {
                list_sagas_op(&rqctx, query.into_inner()).await
            }

            /// Get detailed information about a specific saga including its events
            #[endpoint {
                method = GET,
                path = "/saga/{saga}"
            }]
            pub async fn view_saga(
                rqctx: RequestContext<$context_type>,
                path: Path<SagaPath>,
            ) -> Result<HttpResponseOk<SagaDetailView>, HttpError> {
                view_saga_op(&rqctx, path).await
            }
        }
    }

    #[cfg(feature = "sagas")]
    #[macro_export]
    macro_rules! inject_v_saga_endpoints {
        ($api:ident) => {
            // Saga endpoints
            $api.register(list_sagas)
                .expect("Failed to register endpoint");
            $api.register(view_saga)
                .expect("Failed to register endpoint");
        };
    }

    #[cfg(feature = "metrics")]
    #[macro_export]
    macro_rules! v_metrics_endpoints {
        ($context_type:ident) => {
            use v_api::endpoints::metrics::metrics_op;

            /// Report service metrics
            #[endpoint {
                method = GET,
                path = "/v/metrics"
            }]
            pub async fn metrics(
                rqctx: RequestContext<$context_type>,
            ) -> Result<Response<Body>, HttpError> {
                metrics_op(&rqctx).await
            }
        }
    }

    #[cfg(feature = "metrics")]
    #[macro_export]
    macro_rules! inject_v_metrics_endpoints {
        ($api:ident) => {
            // Metrics endpoints
            $api.register(metrics)
                .expect("Failed to register endpoint");
        };
    }
}
