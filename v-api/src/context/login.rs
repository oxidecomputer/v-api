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
        let mut attempt: NewLoginAttempt = attempt.into();
        attempt.provider_authz_code = Some(code);

        // TODO: Internal state changes to the struct
        attempt.attempt_state = LoginAttemptState::RemoteAuthenticated;
        attempt.authz_code = Some(CsrfToken::new_random().secret().to_string());

        LoginAttemptStore::upsert(&*self.storage, attempt).await
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

    pub async fn fail_login_attempt(
        &self,
        attempt: LoginAttempt,
        error: Option<&str>,
        provider_error: Option<&str>,
    ) -> Result<LoginAttempt, StoreError> {
        let mut attempt: NewLoginAttempt = attempt.into();
        attempt.attempt_state = LoginAttemptState::Failed;
        attempt.error = error.map(|s| s.to_string());
        attempt.provider_error = provider_error.map(|s| s.to_string());
        LoginAttemptStore::upsert(&*self.storage, attempt).await
    }
}
