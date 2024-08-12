// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[rustfmt::skip]
mod macros {
    #[macro_export]
    macro_rules! v_system_endpoints {
        ($context_type:ident, $permission_type:ident) => {
            use dropshot::{
                endpoint, HttpError, HttpResponseCreated, HttpResponseOk,
                HttpResponseTemporaryRedirect, HttpResponseUpdatedNoContent, Path, Query,
                RequestContext, TypedBody,
            };
            use http::Response;
            use hyper::Body;
            use v_model::{Mapper, OAuthClient, OAuthClientRedirectUri, OAuthClientSecret, AccessGroup, ApiUser};

            use v_api::endpoints::{
                api_user::{
                    add_api_user_to_group_op, create_api_user_op, create_api_user_token_op,
                    delete_api_user_token_op, get_api_user_op, get_api_user_token_op, get_self_op,
                    link_provider_op, list_api_user_tokens_op, remove_api_user_from_group_op,
                    update_api_user_op, AddGroupBody, ApiKeyCreateParams, ApiKeyResponse, ApiUserPath,
                    ApiUserProviderLinkPayload, ApiUserRemoveGroupPath, ApiUserTokenPath,
                    ApiUserUpdateParams, GetUserResponse, InitialApiKeyResponse,
                },
                api_user_provider::{
                    create_link_token_op, ApiUserLinkRequestPayload, ApiUserLinkRequestResponse,
                    ApiUserProviderPath,
                },
                group::{
                    create_group_op, delete_group_op, get_groups_op, update_group_op, AccessGroupPath,
                    AccessGroupUpdateParams,
                },
                login::{
                    magic_link:: {
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
                            create_oauth_client_op, create_oauth_client_redirect_uri_op,
                            create_oauth_client_secret_op, delete_oauth_client_redirect_uri_op,
                            delete_oauth_client_secret_op, get_oauth_client_op, list_oauth_clients_op,
                            AddOAuthClientRedirectBody, AddOAuthClientRedirectPath,
                            AddOAuthClientSecretPath, DeleteOAuthClientRedirectPath,
                            DeleteOAuthClientSecretPath, GetOAuthClientPath,
                            InitialOAuthClientSecretResponse,
                        },
                        code::{
                            authz_code_callback_op, authz_code_exchange_op, authz_code_redirect_op,
                            OAuthAuthzCodeExchangeBody, OAuthAuthzCodeExchangeResponse,
                            OAuthAuthzCodeQuery, OAuthAuthzCodeReturnQuery,
                        },
                        device_token::{
                            exchange_device_token_op, get_device_provider_op, AccessTokenExchangeRequest,
                        },
                        OAuthProviderInfo, OAuthProviderNameParam,
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

            // LOGIN ENDPOINTS

            // AUTHZ CODE

            /// Generate the remote provider login url and redirect the user
            #[endpoint {
                method = GET,
                path = "/login/oauth/{provider}/code/authorize"
            }]
            pub async fn authz_code_redirect(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
                query: Query<OAuthAuthzCodeQuery>,
            ) -> Result<Response<Body>, HttpError> {
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
                path: Path<OAuthProviderNameParam>,
                body: TypedBody<OAuthAuthzCodeExchangeBody>,
            ) -> Result<HttpResponseOk<OAuthAuthzCodeExchangeResponse>, HttpError> {
                authz_code_exchange_op(&rqctx, path, body).await
            }

            // DEVICE CODE

            // Get the metadata about an OAuth provider necessary to begin a device code exchange
            #[endpoint {
                method = GET,
                path = "/login/oauth/{provider}/device"
            }]
            pub async fn get_device_provider(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
            ) -> Result<HttpResponseOk<OAuthProviderInfo>, HttpError> {
                get_device_provider_op(&rqctx, path).await
            }

            #[endpoint {
                method = POST,
                path = "/login/oauth/{provider}/device/exchange",
                content_type = "application/x-www-form-urlencoded",
            }]
            pub async fn exchange_device_token(
                rqctx: RequestContext<$context_type>,
                path: Path<OAuthProviderNameParam>,
                body: TypedBody<AccessTokenExchangeRequest>,
            ) -> Result<Response<Body>, HttpError> {
                exchange_device_token_op(&rqctx, path, body).await
            }

            // MAGIC LINK

            #[endpoint {
                method = POST,
                path = "/login/magic/{medium}/send"
            }]
            pub async fn magic_link_send(
                rqctx: RequestContext<$context_type>,
                path: Path<MagicLinkPath>,
                body: TypedBody<MagicLinkSendRequest>,
            ) -> Result<HttpResponseOk<MagicLinkSendResponse>, HttpError> {
              magic_link_send_op(&rqctx, path, body).await
            }

            #[endpoint {
                method = POST,
                path = "/login/magic/{medium}/exchange"
            }]
            pub async fn magic_link_exchange(
                rqctx: RequestContext<$context_type>,
                _path: Path<MagicLinkPath>,
                body: TypedBody<MagicLinkExchangeRequest>,
            ) -> Result<HttpResponseOk<MagicLinkExchangeResponse>, HttpError> {
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

            /// Retrieve the user information of the calling user
            #[endpoint {
                method = GET,
                path = "/self",
            }]
            pub async fn get_self(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<GetUserResponse<$permission_type>>, HttpError> {
                get_self_op(&rqctx).await
            }

            /// Get user information for a given user id
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

            /// Create a new user with a given set of permissions
            #[endpoint {
                method = POST,
                path = "/api-user",
            }]
            pub async fn create_api_user(
                rqctx: RequestContext<$context_type>,
                body: TypedBody<ApiUserUpdateParams<$permission_type>>,
            ) -> Result<HttpResponseCreated<ApiUser<$permission_type>>, HttpError> {
                create_api_user_op(&rqctx, body).await
            }

            /// Update the permissions assigned to a given user
            #[endpoint {
                method = POST,
                path = "/api-user/{user_id}",
            }]
            pub async fn update_api_user(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<ApiUserUpdateParams<$permission_type>>,
            ) -> Result<HttpResponseOk<ApiUser<$permission_type>>, HttpError> {
                update_api_user_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            /// List the active and expired API tokens for a given user
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

            // Create a new API token for a given user with a specific set of permissions and expiration. This
            // is the only time that the returned token will be accessible
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

            // Get details for a specific API token
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

            // Revoke a specific API token so it can no longer be used
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

            #[endpoint {
                method = POST,
                path = "/api-user/{user_id}/group",
            }]
            pub async fn add_api_user_to_group(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserPath>,
                body: TypedBody<AddGroupBody>,
            ) -> Result<HttpResponseOk<ApiUser<$permission_type>>, HttpError> {
                add_api_user_to_group_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

            #[endpoint {
                method = DELETE,
                path = "/api-user/{user_id}/group/{group_id}",
            }]
            pub async fn remove_api_user_from_group(
                rqctx: RequestContext<$context_type>,
                path: Path<ApiUserRemoveGroupPath>,
            ) -> Result<HttpResponseOk<ApiUser<$permission_type>>, HttpError> {
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

            #[endpoint {
                method = GET,
                path = "/group",
            }]
            pub async fn get_groups(
                rqctx: RequestContext<$context_type>,
            ) -> Result<HttpResponseOk<Vec<AccessGroup<$permission_type>>>, HttpError> {
                get_groups_op(&rqctx).await
            }

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

            #[endpoint {
                method = PUT,
                path = "/group/{group_id}",
            }]
            pub async fn update_group(
                rqctx: RequestContext<$context_type>,
                path: Path<AccessGroupPath>,
                body: TypedBody<AccessGroupUpdateParams<$permission_type>>,
            ) -> Result<HttpResponseOk<AccessGroup<$permission_type>>, HttpError> {
                update_group_op(&rqctx, path.into_inner(), body.into_inner()).await
            }

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

            // MAPPERS

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
            $api.register(get_api_user)
                .expect("Failed to register endpoint");
            $api.register(create_api_user)
                .expect("Failed to register endpoint");
            $api.register(update_api_user)
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
            $api.register(link_provider)
                .expect("Failed to register endpoint");
            $api.register(create_link_token)
                .expect("Failed to register endpoint");

            // Group Management
            $api.register(get_groups)
                .expect("Failed to register endpoint");
            $api.register(create_group)
                .expect("Failed to register endpoint");
            $api.register(update_group)
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

            // OAuth Authorization Login
            $api.register(authz_code_redirect)
                .expect("Failed to register endpoint");
            $api.register(authz_code_callback)
                .expect("Failed to register endpoint");
            $api.register(authz_code_exchange)
                .expect("Failed to register endpoint");

            // OAuth Device Login
            $api.register(get_device_provider)
                .expect("Failed to register endpoint");
            $api.register(exchange_device_token)
                .expect("Failed to register endpoint");
        };
    }
}
