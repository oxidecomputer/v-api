// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use std::sync::Arc;
use v_model::{
    permissions::Caller,
    storage::{
        ListPagination, OAuthClientFilter, OAuthClientRedirectUriStore, OAuthClientSecretStore,
        OAuthClientStore, StoreError,
    },
    NewOAuthClient, NewOAuthClientRedirectUri, NewOAuthClientSecret, OAuthClient, OAuthClientId,
    OAuthClientRedirectUri, OAuthClientSecret, OAuthRedirectUriId, OAuthSecretId,
};

use crate::{
    permissions::{VAppPermission, VPermission},
    response::{resource_restricted, OptionalResource, ResourceResult},
    VApiStorage,
};

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
    ) -> ResourceResult<OAuthClient, StoreError> {
        if caller.can(&VPermission::CreateOAuthClient.into()) {
            Ok(OAuthClientStore::upsert(
                &*self.storage,
                NewOAuthClient {
                    id: TypedUuid::new_v4(),
                },
            )
            .await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn get_oauth_client(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClient, StoreError> {
        if caller.any(
            &mut [
                VPermission::GetOAuthClient(*id).into(),
                VPermission::GetOAuthClientsAll.into(),
            ]
            .iter(),
        ) {
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
    ) -> ResourceResult<Vec<OAuthClient>, StoreError> {
        let mut clients = OAuthClientStore::list(
            &*self.storage,
            OAuthClientFilter {
                id: None,
                deleted: false,
            },
            &ListPagination::default(),
        )
        .await?;

        clients.retain(|client| {
            caller.any(
                &mut [
                    VPermission::GetOAuthClient(client.id).into(),
                    VPermission::GetOAuthClientsAll.into(),
                ]
                .iter(),
            )
        });

        Ok(clients)
    }

    pub async fn add_oauth_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthSecretId>,
        client_id: &TypedUuid<OAuthClientId>,
        secret: &str,
    ) -> ResourceResult<OAuthClientSecret, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageOAuthClient(*client_id).into(),
                VPermission::ManageOAuthClientsAll.into(),
            ]
            .iter(),
        ) {
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
    ) -> ResourceResult<OAuthClientSecret, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageOAuthClient(*client_id).into(),
                VPermission::ManageOAuthClientsAll.into(),
            ]
            .iter(),
        ) {
            OAuthClientSecretStore::delete(&*self.storage, id)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }

    pub async fn add_oauth_redirect_uri(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        uri: &str,
    ) -> ResourceResult<OAuthClientRedirectUri, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageOAuthClient(*client_id).into(),
                VPermission::ManageOAuthClientsAll.into(),
            ]
            .iter(),
        ) {
            Ok(OAuthClientRedirectUriStore::upsert(
                &*self.storage,
                NewOAuthClientRedirectUri {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: *client_id,
                    redirect_uri: uri.to_string(),
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
    ) -> ResourceResult<OAuthClientRedirectUri, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageOAuthClient(*client_id).into(),
                VPermission::ManageOAuthClientsAll.into(),
            ]
            .iter(),
        ) {
            OAuthClientRedirectUriStore::delete(&*self.storage, id)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }
}
