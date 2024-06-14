// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use std::sync::Arc;
use v_model::{UserId, UserProviderId};

pub struct PostUserRegisterAction(pub(crate) Vec<Arc<dyn PostUserRegister>>);
impl PostUserRegisterAction {
    pub fn new(actions: Vec<Arc<dyn PostUserRegister>>) -> Self {
        Self(actions)
    }
}

#[async_trait]
pub trait PostUserRegister: Send + Sync {
    async fn run(&self, user: &TypedUuid<UserId>, provider: &TypedUuid<UserProviderId>);
}
