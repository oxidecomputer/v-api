// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use std::{future::Future, pin::Pin, sync::Arc};
use v_model::{UserId, UserProviderId};

pub struct PostUserRegisterAction(pub(crate) Vec<Arc<dyn PostUserRegister>>);
impl PostUserRegisterAction {
    pub fn new(actions: Vec<Arc<dyn PostUserRegister>>) -> Self {
        Self(actions)
    }
}

pub trait PostUserRegister: Send + Sync + 'static {
    fn run(
        &self,
        user: &TypedUuid<UserId>,
        provider: &TypedUuid<UserProviderId>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>>;
}
