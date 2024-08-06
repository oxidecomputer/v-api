// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use newtype_uuid::TypedUuid;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use v_model::{
    schema_ext::{MagicLinkAttemptState, MagicLinkMedium},
    storage::{
        ListPagination, MagicLinkAttemptFilter, MagicLinkAttemptStore, MagicLinkFilter,
        MagicLinkStore, StoreError,
    },
    MagicLink, MagicLinkAttempt, MagicLinkAttemptId, MagicLinkId, NewMagicLinkAttempt,
};

use crate::{
    authn::{key::RawKey, Signer},
    response::{ResourceResult, ToResourceResult, ToResourceResultOpt},
};

use super::VApiStorage;

#[derive(Debug, Error)]
pub enum MagicLinkSendError {
    #[error(transparent)]
    Storage(#[from] StoreError),
}

#[derive(Debug, Error)]
pub enum MagicLinkTransitionError {
    #[error("Magic link attempt is expired")]
    Expired,
    #[error("Invalid nonce supplied")]
    Nonce,
    #[error("Magic link is in an incompatible state")]
    State(MagicLinkAttemptState),
    #[error(transparent)]
    Storage(#[from] StoreError),
    #[error("An unknown error occurred")]
    Unknown,
}

pub struct MagicLinkContext<T> {
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> MagicLinkContext<T> {
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self { storage }
    }

    pub async fn find_client(
        &self,
        signature: &str,
        redirect_uri: &str,
    ) -> ResourceResult<MagicLink, StoreError> {
        let filter = MagicLinkFilter {
            signature: Some(vec![signature.to_string()]),
            redirect_uri: Some(vec![redirect_uri.to_string()]),
            ..Default::default()
        };

        MagicLinkStore::list(&*self.storage, filter, &ListPagination::latest())
            .await
            .map(|mut results| results.pop())
            .opt_to_resource_result()
    }

    pub async fn find_login_attempt(
        &self,
        signature: &str,
    ) -> ResourceResult<MagicLinkAttempt, StoreError> {
        let mut filter = MagicLinkAttemptFilter::default();
        filter.signature = Some(vec![signature.to_string()]);
        MagicLinkAttemptStore::list(&*self.storage, filter, &ListPagination::latest())
            .await
            .map(|mut results| results.pop())
            .opt_to_resource_result()
    }

    pub async fn send_login_attempt(
        &self,
        signer: &dyn Signer,
        client_id: TypedUuid<MagicLinkId>,
        redirect_uri: &str,
        medium: MagicLinkMedium,
        scope: &str,
        expiration: DateTime<Utc>,
        recipient: &str,
    ) -> ResourceResult<MagicLinkAttempt, MagicLinkSendError> {
        let key_id = Uuid::new_v4();
        let key = RawKey::generate::<8>(&key_id).sign(signer).await.unwrap();
        let (signature, key) = (key.signature().to_string(), key.key());

        let recipient_signature = signer
            .sign(recipient.as_bytes())
            .await
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            .unwrap();
        // .map_err(to_internal_error)?;

        // TODO: Construct the url to send

        // TODO: Perform a send

        MagicLinkAttemptStore::upsert(
            &*self.storage,
            NewMagicLinkAttempt {
                id: TypedUuid::new_v4(),
                attempt_state: MagicLinkAttemptState::Sent,
                magic_link_client_id: client_id,
                recipient: recipient_signature.to_string(),
                medium: medium.to_string(),
                redirect_uri: redirect_uri.to_string(),
                scope: scope.to_string(),
                nonce_signature: signature,
                expiration,
            },
        )
        .await
        .to_resource_result()
        .map_err(|err| err.inner_into())
    }

    pub async fn complete_login_attempt(
        &self,
        attempt_id: TypedUuid<MagicLinkAttemptId>,
        signature: &str,
    ) -> ResourceResult<MagicLinkAttempt, MagicLinkTransitionError> {
        let attempt = MagicLinkAttemptStore::transition(
            &*self.storage,
            &attempt_id,
            signature,
            MagicLinkAttemptState::Sent,
            MagicLinkAttemptState::Complete,
        )
        .await
        .to_resource_result()
        .map_err(|err| err.inner_into())?;

        // If the transition did not return a model then we need to inspect the model and determine
        // why it failed
        match attempt {
            Some(attempt) => {
                // TODO: How do we do all of the login stuff here?

                Ok(attempt)
            }
            None => {
                let attempt = MagicLinkAttemptStore::get(&*self.storage, &attempt_id)
                    .await
                    .opt_to_resource_result()
                    .map_err(|err| err.inner_into())?;

                Self::inspect_failed_transition(attempt, signature, MagicLinkAttemptState::Sent)
            }
        }
    }

    fn inspect_failed_transition(
        attempt: MagicLinkAttempt,
        signature: &str,
        state: MagicLinkAttemptState,
    ) -> ResourceResult<MagicLinkAttempt, MagicLinkTransitionError> {
        if attempt.nonce_signature != signature {
            Err(MagicLinkTransitionError::Nonce).to_resource_result()
        } else if attempt.attempt_state != state {
            Err(MagicLinkTransitionError::State(attempt.attempt_state)).to_resource_result()
        } else if attempt.expiration <= Utc::now() {
            Err(MagicLinkTransitionError::Expired).to_resource_result()
        } else {
            tracing::error!(id = ?attempt.id, "Unknown error occurred in attempting to determine magic link transition failure");
            Err(MagicLinkTransitionError::Unknown).to_resource_result()
        }
    }
}
