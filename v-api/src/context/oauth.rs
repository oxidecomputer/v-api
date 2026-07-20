// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use std::sync::Arc;
use thiserror::Error;
use v_model::{
    NewOAuthClient, NewOAuthClientRedirectUri, NewOAuthClientSecret, OAuthClient, OAuthClientId,
    OAuthClientRedirectUri, OAuthClientSecret, OAuthRedirectUriId, OAuthSecretId,
    permissions::Caller,
    storage::{
        ListPagination, OAuthClientFilter, OAuthClientRedirectUriStore, OAuthClientSecretStore,
        OAuthClientStore, StoreError,
    },
};

use crate::{
    VApiStorage,
    permissions::{VAppPermission, VPermission},
    response::{OptionalResource, ResourceError, ResourceResult, resource_restricted},
    util::{RedirectUrlError, parse_redirect_url},
};

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("Invalid redirect URI")]
    RedirectUri(#[from] RedirectUrlError),
    #[error("Storage layer error")]
    StoreError(#[from] StoreError),
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
            &ListPagination::default(),
        )
        .await?;

        clients.retain(|client| caller.can(&VPermission::GetOAuthClient(client.id).into()));

        Ok(clients)
    }

    pub async fn add_oauth_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthSecretId>,
        client_id: &TypedUuid<OAuthClientId>,
        secret: &str,
    ) -> ResourceResult<OAuthClientSecret, OAuthError> {
        if caller.can(&VPermission::ManageOAuthClient(*client_id).into()) {
            Ok(OAuthClientSecretStore::upsert(
                &*self.storage,
                NewOAuthClientSecret {
                    id: *id,
                    oauth_client_id: *client_id,
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

        if caller.can(&VPermission::ManageOAuthClient(*client_id).into()) {
            Ok(OAuthClientRedirectUriStore::upsert(
                &*self.storage,
                NewOAuthClientRedirectUri {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: *client_id,
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
        permissions::Caller,
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
            id: TypedUuid::new_v4(),
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
            id: TypedUuid::new_v4(),
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
