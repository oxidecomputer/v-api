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
    response::{resource_restricted, ResourceResult, ToResourceResult, ToResourceResultOpt},
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

    pub async fn create_oauth_client(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<OAuthClient, StoreError> {
        if caller.can(&VPermission::CreateOAuthClient.into()) {
            OAuthClientStore::upsert(
                &*self.storage,
                NewOAuthClient {
                    id: TypedUuid::new_v4(),
                },
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn get_oauth_client(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClient, StoreError> {
        if caller.any(&[
            &VPermission::GetOAuthClient(*id).into(),
            &VPermission::GetOAuthClientsAll.into(),
        ]) {
            OAuthClientStore::get(&*self.storage, id, false)
                .await
                .opt_to_resource_result()
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
        .await
        .to_resource_result()?;

        clients.retain(|client| {
            caller.any(&[
                &VPermission::GetOAuthClient(client.id).into(),
                &VPermission::GetOAuthClientsAll.into(),
            ])
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
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientSecretStore::upsert(
                &*self.storage,
                NewOAuthClientSecret {
                    id: *id,
                    oauth_client_id: *client_id,
                    secret_signature: secret.to_string(),
                },
            )
            .await
            .to_resource_result()
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
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientSecretStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
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
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientRedirectUriStore::upsert(
                &*self.storage,
                NewOAuthClientRedirectUri {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: *client_id,
                    redirect_uri: uri.to_string(),
                },
            )
            .await
            .to_resource_result()
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
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientRedirectUriStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }
}
