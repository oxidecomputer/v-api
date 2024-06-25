use chrono::{TimeDelta, Utc};
use newtype_uuid::{GenericUuid, TypedUuid};
use std::{ops::Add, sync::Arc};
use v_model::{
    permissions::Caller,
    storage::{LinkRequestStore, StoreError},
    LinkRequest, LinkRequestId, NewLinkRequest, UserId, UserProviderId,
};

use crate::{
    authn::{
        key::{RawApiKey, SignedApiKey},
        Signer,
    },
    permissions::{VAppPermission, VPermission},
    response::{resource_restricted, ResourceResult, ToResourceResult},
    VApiStorage,
};

#[derive(Clone)]
pub struct LinkContext<T> {
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> LinkContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self { storage }
    }

    // TODO: Need a permission for this action
    pub async fn get_link_request(
        &self,
        id: &TypedUuid<LinkRequestId>,
    ) -> Result<Option<LinkRequest>, StoreError> {
        Ok(LinkRequestStore::get(&*self.storage, id, false, false).await?)
    }

    pub async fn create_link_request_token(
        &self,
        caller: &Caller<T>,
        signer: &dyn Signer,
        source_provider: &TypedUuid<UserProviderId>,
        source_user: &TypedUuid<UserId>,
        target: &TypedUuid<UserId>,
    ) -> ResourceResult<SignedApiKey, StoreError> {
        if caller.can(&VPermission::CreateUserApiProviderLinkToken.into()) {
            let link_id = TypedUuid::new_v4();
            let secret = RawApiKey::generate::<8>(link_id.as_untyped_uuid());
            let signed = secret.sign(signer).await.unwrap();

            LinkRequestStore::upsert(
                &*self.storage,
                &NewLinkRequest {
                    id: link_id,
                    source_provider_id: *source_provider,
                    source_user_id: *source_user,
                    target_user_id: *target,
                    secret_signature: signed.signature().to_string(),
                    expires_at: Utc::now().add(TimeDelta::try_minutes(15).unwrap()),
                    completed_at: None,
                },
            )
            .await
            .map(|_| signed)
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }
}
