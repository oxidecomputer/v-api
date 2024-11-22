// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use newtype_uuid::TypedUuid;
use secrecy::ExposeSecret;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tracing::instrument;
use url::Url;
use v_model::{
    permissions::Caller,
    schema_ext::{MagicLinkAttemptState, MagicLinkMedium},
    storage::{
        ListPagination, MagicLinkAttemptFilter, MagicLinkAttemptStore, MagicLinkFilter,
        MagicLinkRedirectUriStore, MagicLinkSecretStore, MagicLinkStore, StoreError,
    },
    MagicLink, MagicLinkAttempt, MagicLinkAttemptId, MagicLinkId, MagicLinkRedirectUri,
    MagicLinkRedirectUriId, MagicLinkSecret, MagicLinkSecretId, NewMagicLink, NewMagicLinkAttempt,
    NewMagicLinkRedirectUri, NewMagicLinkSecret,
};

use crate::{
    authn::{
        key::{ApiKeyError, RawKey},
        Signer, SigningKeyError,
    },
    messenger::{Message, Messenger, MessengerError},
    permissions::{VAppPermission, VPermission},
    response::{resource_restricted, ResourceResult, ToResourceResult, ToResourceResultOpt},
};

use super::VApiStorage;

#[derive(Debug, Error)]
pub enum MagicLinkSendError {
    #[error(transparent)]
    ApiKey(#[from] ApiKeyError),
    #[error("Failed to build message to send")]
    FailedToBuildMessage,
    #[error("No message builder has been registered for the target")]
    NoMessageBuilder(MagicLinkTarget),
    #[error("No message sender has been registered for the target")]
    NoMessageSender(MagicLinkTarget),
    #[error(transparent)]
    Send(#[from] MessengerError),
    #[error(transparent)]
    Signing(#[from] SigningKeyError),
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MagicLinkTarget {
    pub medium: MagicLinkMedium,
    pub channel: String,
}

pub struct MagicLinkContext<T> {
    message_builders: HashMap<MagicLinkTarget, Box<dyn MagicLinkMessage>>,
    messengers: HashMap<MagicLinkTarget, Box<dyn Messenger>>,
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> MagicLinkContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self {
            message_builders: HashMap::new(),
            messengers: HashMap::new(),
            storage,
        }
    }

    pub fn set_message_builder<U>(&mut self, target: MagicLinkTarget, builder: U) -> &mut Self
    where
        U: MagicLinkMessage + 'static,
    {
        self.message_builders.insert(target, Box::new(builder));
        self
    }

    pub fn set_messenger<U>(&mut self, target: MagicLinkTarget, messenger: U) -> &mut Self
    where
        U: Messenger + 'static,
    {
        self.messengers.insert(target, Box::new(messenger));
        self
    }

    pub async fn create_magic_link(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<MagicLink, StoreError> {
        if caller.can(&VPermission::CreateMagicLinkClient.into()) {
            MagicLinkStore::upsert(
                &*self.storage,
                NewMagicLink {
                    id: TypedUuid::new_v4(),
                },
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn get_magic_link(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MagicLinkId>,
    ) -> ResourceResult<MagicLink, StoreError> {
        if caller.any(&[
            &VPermission::GetMagicLinkClient(*id).into(),
            &VPermission::GetMagicLinkClientsAll.into(),
        ]) {
            MagicLinkStore::get(&*self.storage, id, false)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn list_magic_links(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<Vec<MagicLink>, StoreError> {
        let mut clients = MagicLinkStore::list(
            &*self.storage,
            MagicLinkFilter {
                id: None,
                signature: None,
                redirect_uri: None,
                deleted: false,
            },
            &ListPagination::default(),
        )
        .await
        .to_resource_result()?;

        clients.retain(|client| {
            caller.any(&[
                &VPermission::GetMagicLinkClient(client.id).into(),
                &VPermission::GetMagicLinkClientsAll.into(),
            ])
        });

        Ok(clients)
    }

    pub async fn add_magic_link_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MagicLinkSecretId>,
        client_id: &TypedUuid<MagicLinkId>,
        secret: &str,
    ) -> ResourceResult<MagicLinkSecret, StoreError> {
        if caller.any(&[
            &VPermission::ManageMagicLinkClient(*client_id).into(),
            &VPermission::ManageMagicLinkClientsAll.into(),
        ]) {
            MagicLinkSecretStore::upsert(
                &*self.storage,
                NewMagicLinkSecret {
                    id: *id,
                    magic_link_client_id: *client_id,
                    secret_signature: secret.to_string(),
                },
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_magic_link_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MagicLinkSecretId>,
        client_id: &TypedUuid<MagicLinkId>,
    ) -> ResourceResult<MagicLinkSecret, StoreError> {
        if caller.any(&[
            &VPermission::ManageMagicLinkClient(*client_id).into(),
            &VPermission::ManageMagicLinkClientsAll.into(),
        ]) {
            MagicLinkSecretStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn add_magic_link_redirect_uri(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<MagicLinkId>,
        uri: &str,
    ) -> ResourceResult<MagicLinkRedirectUri, StoreError> {
        if caller.any(&[
            &VPermission::ManageMagicLinkClient(*client_id).into(),
            &VPermission::ManageMagicLinkClientsAll.into(),
        ]) {
            MagicLinkRedirectUriStore::upsert(
                &*self.storage,
                NewMagicLinkRedirectUri {
                    id: TypedUuid::new_v4(),
                    magic_link_client_id: *client_id,
                    redirect_uri: uri.to_string(),
                },
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_magic_link_redirect_uri(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MagicLinkRedirectUriId>,
        client_id: &TypedUuid<MagicLinkId>,
    ) -> ResourceResult<MagicLinkRedirectUri, StoreError> {
        if caller.any(&[
            &VPermission::ManageMagicLinkClient(*client_id).into(),
            &VPermission::ManageMagicLinkClientsAll.into(),
        ]) {
            MagicLinkRedirectUriStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    #[instrument(skip(self))]
    pub async fn find_client(
        &self,
        signature: &str,
        redirect_uri: &Url,
    ) -> ResourceResult<MagicLink, StoreError> {
        tracing::debug!("Looking up magic link client");

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

    #[instrument(skip(self, key, signer, redirect_uri, recipient), err(Debug))]
    pub async fn send_login_attempt(
        &self,
        key: RawKey,
        signer: &dyn Signer,
        client_id: TypedUuid<MagicLinkId>,
        redirect_uri: &Url,
        medium: MagicLinkMedium,
        channel: &str,
        scope: &str,
        expiration: DateTime<Utc>,
        recipient: &str,
    ) -> ResourceResult<MagicLinkAttempt, MagicLinkSendError> {
        tracing::debug!("Signing login key");
        let key = key
            .sign(signer)
            .await
            .map_err(|err| err.into())
            .to_resource_result()?;
        let (signature, key) = (key.signature().to_string(), key.key());

        tracing::debug!("Constructing login signature");
        let recipient_signature = signer
            .sign(recipient.as_bytes())
            .await
            .map(|bytes| hex::encode(&bytes))
            .map_err(|err| err.into())
            .to_resource_result()?;

        tracing::debug!("Appending login key to redirect target");
        let mut url = redirect_uri.clone();
        url.query_pairs_mut()
            .append_pair("code", key.expose_secret());

        let target = MagicLinkTarget {
            medium,
            channel: channel.to_string(),
        };

        tracing::debug!("Constructing message to send to recipient");
        let builder_target = target.clone();
        let message = self
            .message_builders
            .get(&builder_target)
            .ok_or_else(move || MagicLinkSendError::NoMessageBuilder(builder_target))
            .to_resource_result()?
            .create_message(recipient, &url)
            .ok_or(MagicLinkSendError::FailedToBuildMessage)
            .to_resource_result()?;

        tracing::info!("Sending magic link login attempt message");
        let sender_target = target.clone();
        self.messengers
            .get(&sender_target)
            .ok_or_else(move || MagicLinkSendError::NoMessageSender(sender_target))
            .to_resource_result()?
            .send(message)
            .await
            .to_resource_result()
            .map_err(|err| err.inner_into())?;

        tracing::info!("Storing magic link attempt");
        MagicLinkAttemptStore::upsert(
            &*self.storage,
            NewMagicLinkAttempt {
                id: TypedUuid::new_v4(),
                attempt_state: MagicLinkAttemptState::Sent,
                magic_link_client_id: client_id,
                recipient: recipient_signature.to_string(),
                medium: medium.to_string(),
                channel: channel.to_string(),
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
            Some(attempt) => Ok(attempt),
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

pub trait MagicLinkMessage: Send + Sync {
    fn create_message(&self, recipient: &str, url: &Url) -> Option<Message>;
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use newtype_uuid::TypedUuid;
    use std::{
        ops::Add,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
    };
    use url::Url;
    use uuid::Uuid;
    use v_model::{
        schema_ext::{MagicLinkAttemptState, MagicLinkMedium},
        storage::MockMagicLinkAttemptStore,
        MagicLinkAttempt,
    };

    use super::{MagicLinkContext, MagicLinkMessage, MagicLinkTarget};
    use crate::{
        authn::key::RawKey,
        context::test_mocks::{mock_context, MockStorage},
        messenger::{Message, Messenger, MessengerError},
        permissions::VPermission,
        response::ResourceError,
    };

    struct TestMessageBuilder {}
    impl MagicLinkMessage for TestMessageBuilder {
        fn create_message(&self, recipient: &str, url: &Url) -> Option<Message> {
            Some(Message {
                recipient: recipient.to_string(),
                subject: None,
                text: url.to_string(),
                html: None,
            })
        }
    }

    struct TestMessenger {}

    #[async_trait]
    impl Messenger for TestMessenger {
        async fn send(&self, _message: Message) -> Result<(), MessengerError> {
            Ok(())
        }
    }

    fn mock_mlink_context(storage: Arc<MockStorage>) -> MagicLinkContext<VPermission> {
        let message_builders = [(
            MagicLinkTarget {
                medium: MagicLinkMedium::Email,
                channel: "all".to_string(),
            },
            Box::new(TestMessageBuilder {}) as Box<dyn MagicLinkMessage>,
        )]
        .into_iter()
        .collect();
        let messengers = [(
            MagicLinkTarget {
                medium: MagicLinkMedium::Email,
                channel: "all".to_string(),
            },
            Box::new(TestMessenger {}) as Box<dyn Messenger>,
        )]
        .into_iter()
        .collect();

        MagicLinkContext {
            message_builders,
            messengers,
            storage,
        }
    }

    #[tokio::test]
    async fn test_send_adds_magic_link_attempt() {
        let mut storage = MockStorage::new();
        let mut attempt_store = MockMagicLinkAttemptStore::new();
        attempt_store.expect_upsert().returning(move |arg| {
            Ok(MagicLinkAttempt {
                id: arg.id,
                attempt_state: arg.attempt_state,
                magic_link_client_id: arg.magic_link_client_id,
                recipient: arg.recipient,
                medium: arg.medium,
                channel: arg.channel,
                redirect_uri: arg.redirect_uri,
                scope: arg.scope,
                nonce_signature: arg.nonce_signature,
                expiration: arg.expiration,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
        });
        storage.magic_link_attempt_store = Some(Arc::new(attempt_store));

        let storage = Arc::new(storage);
        let ctx = mock_context(storage.clone()).await;
        let mlink_ctx = mock_mlink_context(storage);
        let key = RawKey::generate::<8>(&Uuid::new_v4());
        let attempt = mlink_ctx
            .send_login_attempt(
                key,
                ctx.signer(),
                TypedUuid::new_v4(),
                &Url::parse("http://127.0.0.1").unwrap(),
                MagicLinkMedium::Email,
                "all",
                "",
                Utc::now().add(Duration::seconds(60)),
                "user@company",
            )
            .await;

        assert!(attempt.is_ok())
    }

    #[tokio::test]
    async fn test_send_sends_message() {
        let mut storage = MockStorage::new();
        let mut attempt_store = MockMagicLinkAttemptStore::new();
        attempt_store.expect_upsert().returning(move |arg| {
            Ok(MagicLinkAttempt {
                id: arg.id,
                attempt_state: arg.attempt_state,
                magic_link_client_id: arg.magic_link_client_id,
                recipient: arg.recipient,
                medium: arg.medium,
                channel: arg.channel,
                redirect_uri: arg.redirect_uri,
                scope: arg.scope,
                nonce_signature: arg.nonce_signature,
                expiration: arg.expiration,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
        });
        storage.magic_link_attempt_store = Some(Arc::new(attempt_store));

        let storage = Arc::new(storage);
        let ctx = mock_context(storage.clone()).await;
        let mut mlink_ctx = mock_mlink_context(storage);

        struct SendMonitor {
            pub sent: Arc<AtomicBool>,
        }
        #[async_trait]
        impl Messenger for SendMonitor {
            async fn send(&self, _message: Message) -> Result<(), MessengerError> {
                self.sent.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let sent = Arc::new(AtomicBool::new(false));
        mlink_ctx.messengers = [(
            MagicLinkTarget {
                medium: MagicLinkMedium::Email,
                channel: "all".to_string(),
            },
            Box::new(SendMonitor { sent: sent.clone() }) as Box<dyn Messenger>,
        )]
        .into_iter()
        .collect();
        let key = RawKey::generate::<8>(&Uuid::new_v4());

        mlink_ctx
            .send_login_attempt(
                key,
                ctx.signer(),
                TypedUuid::new_v4(),
                &Url::parse("http://127.0.0.1").unwrap(),
                MagicLinkMedium::Email,
                "all",
                "",
                Utc::now().add(Duration::seconds(60)),
                "user@company",
            )
            .await
            .expect("Magic link attempt created");

        assert!(sent.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_send_appends_code_to_uri() {
        let mut storage = MockStorage::new();
        let mut attempt_store = MockMagicLinkAttemptStore::new();
        attempt_store.expect_upsert().returning(move |arg| {
            Ok(MagicLinkAttempt {
                id: arg.id,
                attempt_state: arg.attempt_state,
                magic_link_client_id: arg.magic_link_client_id,
                recipient: arg.recipient,
                medium: arg.medium,
                channel: arg.channel,
                redirect_uri: arg.redirect_uri,
                scope: arg.scope,
                nonce_signature: arg.nonce_signature,
                expiration: arg.expiration,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
        });
        storage.magic_link_attempt_store = Some(Arc::new(attempt_store));

        let storage = Arc::new(storage);
        let ctx = mock_context(storage.clone()).await;
        let mut mlink_ctx = mock_mlink_context(storage);

        struct MessageMonitor {
            pub message: Arc<RwLock<String>>,
        }
        #[async_trait]
        impl Messenger for MessageMonitor {
            async fn send(&self, message: Message) -> Result<(), MessengerError> {
                *self.message.write().unwrap() = message.text;
                Ok(())
            }
        }

        let message = Arc::new(RwLock::new(String::new()));
        mlink_ctx.messengers = [(
            MagicLinkTarget {
                medium: MagicLinkMedium::Email,
                channel: "all".to_string(),
            },
            Box::new(MessageMonitor {
                message: message.clone(),
            }) as Box<dyn Messenger>,
        )]
        .into_iter()
        .collect();
        let key = RawKey::generate::<8>(&Uuid::new_v4());

        mlink_ctx
            .send_login_attempt(
                key,
                ctx.signer(),
                TypedUuid::new_v4(),
                &Url::parse("http://127.0.0.1").unwrap(),
                MagicLinkMedium::Email,
                "all",
                "",
                Utc::now().add(Duration::seconds(60)),
                "user@company",
            )
            .await
            .expect("Magic link attempt created");

        assert!(message.read().unwrap().contains("?code="));
    }

    #[tokio::test]
    async fn test_complete_transitions_attempt() {
        let storage = Arc::new(MockStorage::new());
        let ctx = mock_context(storage.clone()).await;
        let signer = ctx.signer();

        let mut storage = MockStorage::new();
        let mut attempt_store = MockMagicLinkAttemptStore::new();
        let key_id = Uuid::new_v4();
        let key = RawKey::generate::<8>(&key_id).sign(signer).await.unwrap();
        let (signature, _key) = (key.signature().to_string(), key.key());
        let attempt = MagicLinkAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: MagicLinkAttemptState::Sent,
            magic_link_client_id: TypedUuid::new_v4(),
            recipient: String::new(),
            medium: String::new(),
            channel: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            nonce_signature: signature,
            expiration: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let attempt_transition = attempt.clone();
        attempt_store
            .expect_transition()
            .returning(move |id, signature, from, _to| {
                if &attempt_transition.id == id
                    && &attempt_transition.nonce_signature == signature
                    && attempt_transition.attempt_state == from
                {
                    Ok(Some(MagicLinkAttempt {
                        attempt_state: MagicLinkAttemptState::Complete,
                        ..attempt_transition.clone()
                    }))
                } else {
                    Ok(None)
                }
            });
        let attempt_get = attempt.clone();
        attempt_store.expect_get().returning(move |id| {
            if &attempt_get.id == id {
                Ok(Some(attempt_get.clone()))
            } else {
                Ok(None)
            }
        });
        storage.magic_link_attempt_store = Some(Arc::new(attempt_store));

        let mlink_ctx = mock_mlink_context(Arc::new(storage));

        let error = mlink_ctx
            .complete_login_attempt(TypedUuid::new_v4(), &attempt.nonce_signature)
            .await
            .unwrap_err();
        assert!(match error {
            ResourceError::DoesNotExist => true,
            _ => false,
        });

        let transitioned_attempt = mlink_ctx
            .complete_login_attempt(attempt.id, &attempt.nonce_signature)
            .await
            .unwrap();
        assert_eq!(
            MagicLinkAttemptState::Complete,
            transitioned_attempt.attempt_state
        );
    }
}
