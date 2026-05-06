// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use oauth2::CsrfToken;
use std::sync::Arc;
use v_model::{
    storage::{ListPagination, LoginAttemptFilter, LoginAttemptStore, StoreError},
    LoginAttempt, LoginAttemptId, LoginAttemptState, NewLoginAttempt,
};

use crate::{permissions::VAppPermission, VApiStorage};

#[derive(Clone)]
pub struct LoginContext<T> {
    storage: Arc<dyn VApiStorage<T>>,
}

// TODO: Create permissions around login attempts that are assigned to only the builtin
// registration user

impl<T> LoginContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self { storage }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub async fn create_login_attempt(
        &self,
        attempt: NewLoginAttempt,
    ) -> Result<LoginAttempt, StoreError> {
        LoginAttemptStore::upsert(&*self.storage, attempt).await
    }

    pub async fn set_login_provider_authz_code(
        &self,
        attempt: LoginAttempt,
        code: String,
    ) -> Result<LoginAttempt, StoreError> {
        let mut update: NewLoginAttempt = attempt.into();
        update.provider_authz_code = Some(code);
        update.attempt_state = LoginAttemptState::RemoteAuthenticated;
        update.authz_code = Some(CsrfToken::new_random().secret().to_string());

        LoginAttemptStore::update_if_state(&*self.storage, update, LoginAttemptState::New).await
    }

    pub async fn get_login_attempt(
        &self,
        id: &TypedUuid<LoginAttemptId>,
    ) -> Result<Option<LoginAttempt>, StoreError> {
        LoginAttemptStore::get(&*self.storage, id).await
    }

    pub async fn get_login_attempt_for_code(
        &self,
        code: &str,
    ) -> Result<Option<LoginAttempt>, StoreError> {
        let filter = LoginAttemptFilter {
            attempt_state: Some(vec![LoginAttemptState::RemoteAuthenticated]),
            authz_code: Some(vec![code.to_string()]),
            ..Default::default()
        };

        let mut attempts = LoginAttemptStore::list(
            &*self.storage,
            filter,
            &ListPagination {
                offset: 0,
                limit: 1,
            },
        )
        .await?;

        Ok(attempts.pop())
    }

    /// Atomically claim a login attempt by transitioning it from `RemoteAuthenticated`
    /// to `Complete`. Returns an error if the attempt has already been claimed by a
    /// concurrent request (i.e., the state is no longer `RemoteAuthenticated`).
    /// This must be called before exchanging the authorization code with the remote
    /// provider to prevent the same code from being used twice (RFC 6749 §4.1.2).
    pub async fn claim_login_attempt(
        &self,
        attempt: LoginAttempt,
    ) -> Result<LoginAttempt, StoreError> {
        let mut update: NewLoginAttempt = attempt.into();
        update.attempt_state = LoginAttemptState::Complete;

        LoginAttemptStore::update_if_state(
            &*self.storage,
            update,
            LoginAttemptState::RemoteAuthenticated,
        )
        .await
    }

    pub async fn fail_login_attempt(
        &self,
        attempt: LoginAttempt,
        expected_state: LoginAttemptState,
        error: Option<&str>,
        provider_error: Option<&str>,
    ) -> Result<LoginAttempt, StoreError> {
        let mut update: NewLoginAttempt = attempt.into();
        update.attempt_state = LoginAttemptState::Failed;
        update.error = error.map(|s| s.to_string());
        update.provider_error = provider_error.map(|s| s.to_string());

        LoginAttemptStore::update_if_state(&*self.storage, update, expected_state).await
    }
}
