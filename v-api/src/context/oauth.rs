// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use newtype_uuid::TypedUuid;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use v_model::{
    NewOAuthClient, NewOAuthClientAssertion, NewOAuthClientKey, NewOAuthClientRedirectUri,
    NewOAuthClientSecret, NewServiceAccount, NewServiceAccountToken, OAuthClient, OAuthClientId,
    OAuthClientKey, OAuthClientKeyId, OAuthClientRedirectUri, OAuthClientSecret,
    OAuthRedirectUriId, OAuthSecretId, Permissions, ServiceAccountToken, ServiceAccountTokenId,
    jwk::PublicJwk,
    permissions::{AsScope, Caller, PermissionError, PermissionStorage, Principal},
    storage::{
        ListPagination, OAuthClientAssertionStore, OAuthClientFilter, OAuthClientKeyFilter,
        OAuthClientKeyStore, OAuthClientRedirectUriStore, OAuthClientSecretStore, OAuthClientStore,
        ServiceAccountStore, ServiceAccountTokenFilter, ServiceAccountTokenStore, StoreError,
    },
};

use crate::{
    VApiStorage,
    authn::{
        client_assertion::{AssertionError, AssertionPolicy, CLOCK_SKEW, UnverifiedAssertion},
        client_key::{ClientKeyError, JwkThumbprint},
        jwt::{JwtSigner, JwtSignerError, ServiceAccountClaims},
    },
    permissions::{VAppPermission, VPermission},
    response::{
        OptionalResource, ResourceError, ResourceResult, resource_conflict, resource_restricted,
    },
    util::{RedirectUrlError, parse_redirect_url},
};

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("Invalid client key")]
    ClientKey(#[from] ClientKeyError),
    #[error("Invalid redirect URI")]
    RedirectUri(#[from] RedirectUrlError),
    #[error("Storage layer error")]
    StoreError(#[from] StoreError),
    #[error("Failed to sign token")]
    Jwt(#[from] JwtSignerError),
}

#[derive(Debug, Error)]
pub enum ClientAuthenticationError {
    #[error(transparent)]
    Assertion(#[from] AssertionError),
    #[error("Assertion names a client that does not exist")]
    UnknownClient,
    #[error("Assertion names a key that the client does not hold")]
    UnknownKey,
    #[error("Request names a different client than the one that signed the assertion")]
    ClientMismatch,
    #[error("Assertion has already been used")]
    Replay,
    #[error("Caller is not allowed to authenticate clients")]
    Restricted,
    #[error("Inner storage failure: {0}")]
    Storage(#[from] StoreError),
}

pub struct RegisteredServiceAccountToken {
    pub token: ServiceAccountToken,
    pub signed_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Error)]
pub enum ServiceAccountCallerError {
    #[error("Failed to authenticate service account")]
    FailedToAuthenticate,
    #[error("Service account token has an unknown id, has been revoked, or names the wrong client")]
    InvalidToken,
    #[error("Invalid scope: {0}")]
    Scope(#[from] PermissionError),
    #[error("Inner storage failure: {0}")]
    Storage(#[from] StoreError),
}

/// A change to the permissions a client's service account holds. Each kind of change carries what
/// is needed to check the caller's authority to make it.
enum ServiceAccountChange<'a, T> {
    AddPermission(T),
    RemovePermission(&'a T),
}

#[derive(Clone)]
pub struct OAuthContext<T> {
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> OAuthContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self { storage }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub async fn create_oauth_client(
        &self,
        caller: &Caller<T>,
        id: TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClient, OAuthError> {
        if caller.can(&VPermission::CreateOAuthClient.into()) {
            Ok(OAuthClientStore::upsert(&*self.storage, NewOAuthClient { id }).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn get_oauth_client(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClient, OAuthError> {
        if caller.can(&VPermission::GetOAuthClient(*id).into()) {
            OAuthClientStore::get(&*self.storage, id, false)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }

    pub async fn list_oauth_clients(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<Vec<OAuthClient>, OAuthError> {
        let mut clients = OAuthClientStore::list(
            &*self.storage,
            OAuthClientFilter {
                id: None,
                deleted: false,
            },
            &ListPagination::unlimited(),
        )
        .await?;

        clients.retain(|client| caller.can(&VPermission::GetOAuthClient(client.id).into()));

        Ok(clients)
    }

    /// Registers the public half of a key pair whose private key the client keeps and signs its
    /// client credentials assertions with. Assertions are verified against the registered public
    /// key.
    pub async fn add_oauth_client_key(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        jwk: PublicJwk,
    ) -> ResourceResult<OAuthClientKey, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        if caller.can(&VPermission::ManageOAuthClient(client.id).into()) {
            let thumbprint = jwk
                .thumbprint()
                .map_err(|err| ResourceError::InternalError(OAuthError::ClientKey(err)))?;

            Ok(OAuthClientKeyStore::insert(
                &*self.storage,
                NewOAuthClientKey {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: client.id,
                    thumbprint,
                    jwk,
                },
            )
            .await?)
        } else {
            resource_restricted()
        }
    }

    /// Removes one of the client's public keys, so that assertions signed with the matching
    /// private key are no longer accepted. This does not revoke any existing tokens issued against
    /// this key.
    pub async fn delete_oauth_client_key(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        key_id: &TypedUuid<OAuthClientKeyId>,
    ) -> ResourceResult<OAuthClientKey, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        if !client.keys.iter().any(|key| &key.id == key_id) {
            Err(ResourceError::DoesNotExist)
        } else if caller.can(&VPermission::ManageOAuthClient(client.id).into()) {
            OAuthClientKeyStore::delete(&*self.storage, key_id)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }

    /// Authenticates a client by the JWT assertion it presented under RFC 7523 §2.2. The assertion
    /// is only verified against the key on that client whose thumbprint matches the
    /// assertion's key id. By recording the assertion we are "accepting" it, after which it may
    /// never be accepted again.
    pub async fn authenticate_client(
        &self,
        caller: &Caller<T>,
        assertion: &str,
        requested_client: Option<&TypedUuid<OAuthClientId>>,
        policy: &AssertionPolicy,
    ) -> Result<OAuthClient, ClientAuthenticationError> {
        let unverified = UnverifiedAssertion::parse(assertion)?;
        let key = OAuthClientKeyStore::list(
            &*self.storage,
            OAuthClientKeyFilter {
                thumbprint: Some(vec![unverified.untrusted_kid().to_string()]),
                ..Default::default()
            },
            &ListPagination::latest(),
        )
        .await?
        .pop();

        if let Some(key) = key {
            let claims = unverified.verify(&key.jwk, policy)?;
            if key.oauth_client_id != claims.iss {
                Err(ClientAuthenticationError::UnknownKey)
            } else if requested_client.is_some_and(|requested| requested != &claims.iss) {
                Err(ClientAuthenticationError::ClientMismatch)
            } else {
                let client = self
                    .get_oauth_client(caller, &claims.iss)
                    .await
                    .map_err(|err| match err {
                        ResourceError::DoesNotExist => ClientAuthenticationError::UnknownClient,
                        ResourceError::InternalError(OAuthError::StoreError(err)) => {
                            ClientAuthenticationError::Storage(err)
                        }
                        err => {
                            tracing::error!(
                                ?err,
                                "Failed to read the client named by an assertion"
                            );
                            ClientAuthenticationError::Restricted
                        }
                    })?;

                if caller.can(&VPermission::ManageOAuthClient(client.id).into()) {
                    OAuthClientAssertionStore::record(
                        &*self.storage,
                        NewOAuthClientAssertion {
                            oauth_client_id: client.id,
                            jti: claims.jti,
                            expires_at: DateTime::<Utc>::from_timestamp(
                                claims.exp.saturating_add(CLOCK_SKEW),
                                0,
                            )
                            .unwrap_or(DateTime::<Utc>::MAX_UTC),
                        },
                    )
                    .await
                    .map_err(|err| match err {
                        StoreError::Conflict => ClientAuthenticationError::Replay,
                        err => ClientAuthenticationError::Storage(err),
                    })?;

                    tracing::info!(client_id = ?client.id, kid = ?key.thumbprint, "Authenticated client by assertion");

                    Ok(client)
                } else {
                    Err(ClientAuthenticationError::Restricted)
                }
            }
        } else {
            Err(ClientAuthenticationError::UnknownKey)
        }
    }

    /// List all service account tokens issued to a client that are active.
    pub async fn list_service_account_tokens(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<Vec<ServiceAccountToken>, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        Ok(ServiceAccountTokenStore::list(
            &*self.storage,
            ServiceAccountTokenFilter {
                oauth_client_id: Some(vec![client.id]),
                revoked: false,
                expired: false,
            },
            &ListPagination::unlimited(),
        )
        .await?)
    }

    /// Revokes one of a client's service account tokens.
    pub async fn revoke_service_account_token(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        token_id: &TypedUuid<ServiceAccountTokenId>,
    ) -> ResourceResult<ServiceAccountToken, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        if !caller.can(&VPermission::ManageOAuthClient(client.id).into()) {
            resource_restricted()
        } else {
            let token = ServiceAccountTokenStore::get(&*self.storage, token_id, false).await?;

            if token.is_some_and(|token| token.oauth_client_id == client.id) {
                let revoked = ServiceAccountTokenStore::revoke(&*self.storage, token_id)
                    .await
                    .optional()?;
                tracing::info!(client_id = ?client.id, ?token_id, "Revoked service account token");

                Ok(revoked)
            } else {
                Err(ResourceError::DoesNotExist)
            }
        }
    }

    /// Removes the records of client assertions that can no longer be accepted, returning how many
    /// were removed.
    pub async fn delete_expired_client_assertions(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<usize, OAuthError> {
        if caller.can(&VPermission::ManageOAuthClientsAll.into()) {
            let removed =
                OAuthClientAssertionStore::delete_expired(&*self.storage, Utc::now()).await?;
            tracing::info!(removed, "Removed expired client assertions");

            Ok(removed)
        } else {
            resource_restricted()
        }
    }

    /// Records and signs an access token for a client acting as its service account. The token is
    /// recorded before it is signed, so every token that is handed out can be resolved and
    /// revoked.
    pub async fn register_service_account_token(
        &self,
        caller: &Caller<T>,
        signer: &JwtSigner,
        claims: &ServiceAccountClaims,
    ) -> ResourceResult<RegisteredServiceAccountToken, OAuthError> {
        if caller.can(&VPermission::CreateAccessToken.into()) {
            let client = self.get_oauth_client(caller, &claims.client_id).await?;
            let token = ServiceAccountTokenStore::create(
                &*self.storage,
                NewServiceAccountToken {
                    id: claims.jti,
                    oauth_client_id: client.id,
                    expires_at: DateTime::<Utc>::from_timestamp(claims.exp, 0)
                        .unwrap_or(DateTime::<Utc>::MAX_UTC),
                },
            )
            .await?;

            let signed_token = signer
                .sign(claims)
                .await
                .map_err(|err| ResourceError::InternalError(OAuthError::Jwt(err)))?;

            Ok(RegisteredServiceAccountToken {
                token,
                signed_token,
                expires_in: claims.exp - Utc::now().timestamp(),
            })
        } else {
            resource_restricted()
        }
    }

    /// The client a service account token was issued to. The token must name the same client as
    /// its subject and as its client id.
    fn token_client_id(
        claims: &ServiceAccountClaims,
    ) -> Result<TypedUuid<OAuthClientId>, ServiceAccountCallerError> {
        if claims.sub == claims.client_id {
            Ok(claims.client_id)
        } else {
            tracing::warn!(sub = ?claims.sub, client_id = ?claims.client_id, "Service account token names two different clients");
            Err(ServiceAccountCallerError::InvalidToken)
        }
    }

    /// Resolves the caller for a verified service account token.
    pub async fn get_caller(
        &self,
        registration_user: &Caller<T>,
        claims: &ServiceAccountClaims,
    ) -> Result<Caller<T>, ServiceAccountCallerError> {
        let client_id = Self::token_client_id(claims)?;

        let client = self
            .get_oauth_client(registration_user, &client_id)
            .await
            .map_err(|err| match err {
                ResourceError::InternalError(OAuthError::StoreError(err)) => {
                    ServiceAccountCallerError::Storage(err)
                }
                err => {
                    tracing::info!(?err, ?client_id, "Service account client could not be read");
                    ServiceAccountCallerError::FailedToAuthenticate
                }
            })?;

        // The token must be known, must not have been revoked, and must have been issued to this
        // client. From here on the caller is the client the token was issued to.
        let token = ServiceAccountTokenStore::get(&*self.storage, &claims.jti, false)
            .await?
            .filter(|token| token.oauth_client_id == client.id)
            .ok_or(ServiceAccountCallerError::InvalidToken)?;

        let held = ServiceAccountStore::get(&*self.storage, &token.oauth_client_id)
            .await?
            .map(|account| account.permissions.expand_values())
            .unwrap_or_default();
        let extensions = HashMap::new();
        let held = <T as PermissionStorage>::expand(&held, None, Some(&held), &extensions);

        let permissions = if claims.scp.iter().any(|scope| scope == "full") {
            held
        } else {
            let scoped = <T as AsScope>::from_scope(claims.scp.iter())?;
            <T as PermissionStorage>::expand(&scoped, None, Some(&held), &extensions)
                .intersect(&held)
        };

        let caller = Caller {
            principal: Principal::ServiceAccount(token.oauth_client_id),
            permissions: permissions.into_iter().collect(),
            extensions,
        };

        tracing::info!(?caller.principal, "Resolved service account caller");
        tracing::debug!(?caller.permissions, "Caller permissions");

        Ok(caller)
    }

    pub async fn get_service_account_permissions(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<Permissions<T>, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        Ok(ServiceAccountStore::get(&*self.storage, &client.id)
            .await?
            .map(|account| account.permissions)
            .unwrap_or_default())
    }

    /// Grants a permission to the client's service account.
    pub async fn add_permission_to_service_account(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        permission: T,
    ) -> ResourceResult<Permissions<T>, OAuthError> {
        self.modify_service_account(
            caller,
            client_id,
            ServiceAccountChange::AddPermission(permission),
        )
        .await
    }

    /// Removes a permission from the client's service account.
    pub async fn remove_permission_from_service_account(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        permission: &T,
    ) -> ResourceResult<Permissions<T>, OAuthError> {
        self.modify_service_account(
            caller,
            client_id,
            ServiceAccountChange::RemovePermission(permission),
        )
        .await
    }

    /// Applies a change to the permissions of a client's service account.
    async fn modify_service_account(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        change: ServiceAccountChange<'_, T>,
    ) -> ResourceResult<Permissions<T>, OAuthError> {
        if !Self::can_make_change(caller, client_id, &change) {
            resource_restricted()
        } else {
            let client = self.get_oauth_client(caller, client_id).await?;
            let current = ServiceAccountStore::get(&*self.storage, &client.id).await?;

            let mut update = NewServiceAccount {
                id: client.id,
                permissions: current
                    .as_ref()
                    .map(|account| account.permissions.expand_values())
                    .unwrap_or_default(),
            };
            Self::apply_change(&mut update, change);
            update.permissions = <T as PermissionStorage>::contract(&update.permissions);

            let written = match current {
                Some(account) => {
                    ServiceAccountStore::update(&*self.storage, update, account.generation).await?
                }
                None => ServiceAccountStore::create(&*self.storage, update)
                    .await
                    .map(Some)
                    .or_else(|err| match err {
                        StoreError::Conflict => Ok(None),
                        err => Err(err),
                    })?,
            };

            match written {
                Some(account) => Ok(account.permissions),
                None => {
                    tracing::info!(
                        ?client_id,
                        "Service account was written by someone else since it was read"
                    );
                    resource_conflict()
                }
            }
        }
    }

    /// Returns true if the caller has the authority to make the change to the client's service
    /// account
    fn can_make_change(
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        change: &ServiceAccountChange<T>,
    ) -> bool {
        let permission = match change {
            ServiceAccountChange::AddPermission(permission) => permission,
            ServiceAccountChange::RemovePermission(permission) => *permission,
        };

        caller.can(&VPermission::ManageOAuthClient(*client_id).into())
            && caller.can_grant(permission)
    }

    fn apply_change(update: &mut NewServiceAccount<T>, change: ServiceAccountChange<T>) {
        match change {
            ServiceAccountChange::AddPermission(permission) => {
                for value in Permissions::from_iter([permission])
                    .expand_values()
                    .into_iter()
                {
                    update.permissions.insert(value);
                }
            }
            ServiceAccountChange::RemovePermission(permission) => {
                update.permissions = update.permissions.without(permission);
            }
        }
    }

    pub async fn add_oauth_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthSecretId>,
        client_id: &TypedUuid<OAuthClientId>,
        secret: &str,
    ) -> ResourceResult<OAuthClientSecret, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        if caller.can(&VPermission::ManageOAuthClient(client.id).into()) {
            Ok(OAuthClientSecretStore::upsert(
                &*self.storage,
                NewOAuthClientSecret {
                    id: *id,
                    oauth_client_id: client.id,
                    secret_signature: secret.to_string(),
                },
            )
            .await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_oauth_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthSecretId>,
        client_id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClientSecret, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        // Verify the secret belongs to the client
        if client.secrets.into_iter().any(|s| s.id == *id) {
            if caller.can(&VPermission::ManageOAuthClient(*client_id).into()) {
                OAuthClientSecretStore::delete(&*self.storage, id)
                    .await
                    .optional()
            } else {
                resource_restricted()
            }
        } else {
            Err(ResourceError::DoesNotExist)
        }
    }

    pub async fn add_oauth_redirect_uri(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        uri: &str,
    ) -> ResourceResult<OAuthClientRedirectUri, OAuthError> {
        // Validate that the redirect URI is a well-formed URL before storing it.
        // Per RFC 6749 §3.1.2, redirect URIs must be absolute URIs and must not
        // include a fragment component.
        let redirect_url = parse_redirect_url(uri)
            .map_err(|e| ResourceError::InternalError(OAuthError::RedirectUri(e)))?;
        let client = self.get_oauth_client(caller, client_id).await?;

        if caller.can(&VPermission::ManageOAuthClient(client.id).into()) {
            Ok(OAuthClientRedirectUriStore::upsert(
                &*self.storage,
                NewOAuthClientRedirectUri {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: client.id,
                    redirect_uri: redirect_url.to_string(),
                },
            )
            .await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_oauth_redirect_uri(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthRedirectUriId>,
        client_id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClientRedirectUri, OAuthError> {
        let client = self.get_oauth_client(caller, client_id).await?;

        // Verify the redirect_uris belongs to the client
        if client.redirect_uris.into_iter().any(|r| r.id == *id) {
            if caller.can(&VPermission::ManageOAuthClient(*client_id).into()) {
                OAuthClientRedirectUriStore::delete(&*self.storage, id)
                    .await
                    .optional()
            } else {
                resource_restricted()
            }
        } else {
            Err(ResourceError::DoesNotExist)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use chrono::Utc;
    use newtype_uuid::TypedUuid;
    use v_model::{
        OAuthClient, OAuthClientRedirectUri, OAuthClientSecret,
        permissions::{Caller, Principal},
        storage::{
            MockOAuthClientRedirectUriStore, MockOAuthClientSecretStore, MockOAuthClientStore,
        },
    };

    use crate::{context::test_mocks::MockStorage, permissions::VPermission};

    use super::OAuthContext;

    #[tokio::test]
    async fn cannot_delete_secret_of_unauthorized_client() {
        let attacker_client_id = TypedUuid::new_v4();
        let victim_client_id = TypedUuid::new_v4();
        let victim_secret_id = TypedUuid::new_v4();

        // Faithfully model the Postgres store, which soft-deletes purely by
        // secret id and returns the deleted record (owned by the victim).
        let mut secret_store = MockOAuthClientSecretStore::new();
        secret_store.expect_delete().returning(move |id| {
            Ok(Some(OAuthClientSecret {
                id: *id,
                oauth_client_id: victim_client_id,
                secret_signature: "victim-secret".to_string(),
                created_at: Utc::now(),
                deleted_at: Some(Utc::now()),
            }))
        });

        // Defensive: if a fix verifies ownership by fetching the authorized
        // client, that client legitimately does not contain the victim's secret.
        let mut client_store = MockOAuthClientStore::new();
        client_store.expect_get().returning(move |id, _| {
            Ok(Some(OAuthClient {
                id: *id,
                keys: vec![],
                secrets: vec![],
                redirect_uris: vec![],
                created_at: Utc::now(),
                deleted_at: None,
            }))
        });

        let mut storage = MockStorage::new();
        storage.oauth_client_secret_store = Some(Arc::new(secret_store));
        storage.oauth_client_store = Some(Arc::new(client_store));
        let ctx = OAuthContext::new(Arc::new(storage));

        // Attacker only manages their own client C.
        let attacker = Caller {
            principal: Principal::User(TypedUuid::new_v4()),
            permissions: vec![VPermission::ManageOAuthClient(attacker_client_id)].into(),
            extensions: HashMap::default(),
        };

        // They target the victim's secret while authorizing against their own client.
        let result = ctx
            .delete_oauth_secret(&attacker, &victim_secret_id, &attacker_client_id)
            .await;

        if let Ok(deleted) = result {
            assert_eq!(
                deleted.oauth_client_id, attacker_client_id,
                "IDOR: deleted secret {:?} owned by client {:?} while only authorized to manage \
                 client {:?}",
                deleted.id, deleted.oauth_client_id, attacker_client_id,
            );
        }
    }

    #[tokio::test]
    async fn cannot_delete_redirect_uri_of_unauthorized_client() {
        let attacker_client_id = TypedUuid::new_v4();
        let victim_client_id = TypedUuid::new_v4();
        let victim_redirect_uri_id = TypedUuid::new_v4();

        let mut redirect_store = MockOAuthClientRedirectUriStore::new();
        redirect_store.expect_delete().returning(move |id| {
            Ok(Some(OAuthClientRedirectUri {
                id: *id,
                oauth_client_id: victim_client_id,
                redirect_uri: "https://victim.example.com/callback".to_string(),
                created_at: Utc::now(),
                deleted_at: Some(Utc::now()),
            }))
        });

        let mut client_store = MockOAuthClientStore::new();
        client_store.expect_get().returning(move |id, _| {
            Ok(Some(OAuthClient {
                id: *id,
                keys: vec![],
                secrets: vec![],
                redirect_uris: vec![],
                created_at: Utc::now(),
                deleted_at: None,
            }))
        });

        let mut storage = MockStorage::new();
        storage.oauth_client_redirect_uri_store = Some(Arc::new(redirect_store));
        storage.oauth_client_store = Some(Arc::new(client_store));
        let ctx = OAuthContext::new(Arc::new(storage));

        let attacker = Caller {
            principal: Principal::User(TypedUuid::new_v4()),
            permissions: vec![VPermission::ManageOAuthClient(attacker_client_id)].into(),
            extensions: HashMap::default(),
        };

        let result = ctx
            .delete_oauth_redirect_uri(&attacker, &victim_redirect_uri_id, &attacker_client_id)
            .await;

        if let Ok(deleted) = result {
            assert_eq!(
                deleted.oauth_client_id, attacker_client_id,
                "IDOR: deleted redirect URI {:?} owned by client {:?} while only authorized to \
                 manage client {:?}",
                deleted.id, deleted.oauth_client_id, attacker_client_id,
            );
        }
    }
}
