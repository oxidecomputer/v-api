// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use std::error::Error;

pub struct Message {
    pub recipient: String,
    pub subject: Option<String>,
    pub text: String,
    pub html: Option<String>,
}

pub type MessengerError = Box<dyn Error + Send + Sync + 'static>;

#[async_trait]
pub trait Messenger: Send + Sync {
    async fn send(&self, message: Message) -> Result<(), MessengerError>;
}
