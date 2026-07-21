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
    MagicLink, MagicLinkAttempt, MagicLinkAttemptId, MagicLinkId, MagicLinkRedirectUri,
    MagicLinkRedirectUriId, MagicLinkSecret, MagicLinkSecretId, NewMagicLink, NewMagicLinkAttempt,
    NewMagicLinkRedirectUri, NewMagicLinkSecret,
    permissions::Caller,
    schema_ext::{MagicLinkAttemptState, MagicLinkMedium},
    storage::{
        ListPagination, MagicLinkAttemptFilter, MagicLinkAttemptStore, MagicLinkFilter,
        MagicLinkRedirectUriStore, MagicLinkSecretStore, MagicLinkStore, StoreError,
    },
};

use crate::{
    authn::{
        Sign, SigningKeyError,
        key::{ApiKeyError, RawKey},
    },
    messenger::{Message, Messenger, MessengerError},
    permissions::{VAppPermission, VPermission},
    response::{
        OptionalResource, ResourceError, ResourceErrorInner, ResourceResult, resource_error,
        resource_restricted,
    },
    util::{RedirectUrlError, parse_redirect_url},
};

use super::VApiStorage;

#[derive(Debug, Error)]
pub enum MagicLinkError {
    #[error("Invalid redirect URI")]
    RedirectUri(#[from] RedirectUrlError),
    #[error("Storage layer error")]
    StoreError(#[from] StoreError),
}

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
            Ok(MagicLinkStore::upsert(
                &*self.storage,
                NewMagicLink {
                    id: TypedUuid::new_v4(),
                },
            )
            .await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn get_magic_link(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MagicLinkId>,
    ) -> ResourceResult<MagicLink, StoreError> {
        if caller.can(&VPermission::GetMagicLinkClient(*id).into()) {
            MagicLinkStore::get(&*self.storage, id, false)
                .await
                .optional()
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
        .await?;

        clients.retain(|client| caller.can(&VPermission::GetMagicLinkClient(client.id).into()));

        Ok(clients)
    }

    pub async fn add_magic_link_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MagicLinkSecretId>,
        client_id: &TypedUuid<MagicLinkId>,
        secret: &str,
    ) -> ResourceResult<MagicLinkSecret, StoreError> {
        if caller.can(&VPermission::ManageMagicLinkClient(*client_id).into()) {
            Ok(MagicLinkSecretStore::upsert(
                &*self.storage,
                NewMagicLinkSecret {
                    id: *id,
                    magic_link_client_id: *client_id,
                    secret_signature: secret.to_string(),
                },
            )
            .await?)
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
        let client = self.get_magic_link(caller, client_id).await?;

        // Verify the secret belongs to the client
        if client.secrets.into_iter().any(|s| s.id == *id) {
            if caller.can(&VPermission::ManageMagicLinkClient(*client_id).into()) {
                MagicLinkSecretStore::delete(&*self.storage, id)
                    .await
                    .optional()
            } else {
                resource_restricted()
            }
        } else {
            Err(ResourceError::DoesNotExist)
        }
    }

    pub async fn add_magic_link_redirect_uri(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<MagicLinkId>,
        uri: &str,
    ) -> ResourceResult<MagicLinkRedirectUri, MagicLinkError> {
        let redirect_url = parse_redirect_url(uri)
            .map_err(|err| ResourceError::InternalError(MagicLinkError::RedirectUri(err)))?;
        if caller.can(&VPermission::ManageMagicLinkClient(*client_id).into()) {
            Ok(MagicLinkRedirectUriStore::upsert(
                &*self.storage,
                NewMagicLinkRedirectUri {
                    id: TypedUuid::new_v4(),
                    magic_link_client_id: *client_id,
                    redirect_uri: redirect_url.to_string(),
                },
            )
            .await?)
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
        let client = self.get_magic_link(caller, client_id).await?;

        // Verify the redirect_uris belongs to the client
        if client.redirect_uris.into_iter().any(|r| r.id == *id) {
            if caller.can(&VPermission::ManageMagicLinkClient(*client_id).into()) {
                MagicLinkRedirectUriStore::delete(&*self.storage, id)
                    .await
                    .optional()
            } else {
                resource_restricted()
            }
        } else {
            Err(ResourceError::DoesNotExist)
        }
    }

    #[instrument(skip(self))]
    pub async fn find_client(
        &self,
        signature: &str,
        redirect_uri: &Url,
    ) -> ResourceResult<MagicLink, StoreError> {
        let filter = MagicLinkFilter {
            signature: Some(vec![signature.to_string()]),
            redirect_uri: Some(vec![redirect_uri.to_string()]),
            ..Default::default()
        };

        tracing::debug!(?filter, "Looking up magic link client");

        MagicLinkStore::list(&*self.storage, filter, &ListPagination::latest())
            .await
            .map(|mut results| results.pop())
            .optional()
    }

    pub async fn find_login_attempt(
        &self,
        signature: &str,
    ) -> ResourceResult<MagicLinkAttempt, StoreError> {
        let filter = MagicLinkAttemptFilter {
            signature: Some(vec![signature.to_string()]),
            ..Default::default()
        };
        MagicLinkAttemptStore::list(&*self.storage, filter, &ListPagination::latest())
            .await
            .map(|mut results| results.pop())
            .optional()
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, key, signer, redirect_uri, recipient), err(Debug))]
    pub async fn send_login_attempt(
        &self,
        key: RawKey,
        signer: &dyn Sign,
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
            .map_err(ResourceError::InternalError)
            .inner_err_into()?;
        let (signature, key) = (key.signature().to_string(), key.key());

        tracing::debug!("Constructing login signature");
        let recipient_signature = signer
            .sign(recipient.as_bytes())
            .await
            .map(|bytes| hex::encode(&bytes))
            .map_err(ResourceError::InternalError)
            .inner_err_into()?;

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
            .map_err(ResourceError::InternalError)?
            .create_message(recipient, key.expose_secret(), &url)
            .ok_or(MagicLinkSendError::FailedToBuildMessage)
            .map_err(ResourceError::InternalError)?;

        tracing::info!("Sending magic link login attempt message");
        let sender_target = target.clone();
        self.messengers
            .get(&sender_target)
            .ok_or_else(move || MagicLinkSendError::NoMessageSender(sender_target))
            .map_err(ResourceError::InternalError)?
            .send(message)
            .await
            .map_err(ResourceError::InternalError)
            .inner_err_into()?;

        tracing::info!("Storing magic link attempt");
        Ok(MagicLinkAttemptStore::upsert(
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
        .await?)
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
        .await?;

        // If the transition did not return a model then we need to inspect the model and determine
        // why it failed
        match attempt {
            Some(attempt) => Ok(attempt),
            None => {
                let attempt = MagicLinkAttemptStore::get(&*self.storage, &attempt_id)
                    .await
                    .optional()?;

                resource_error(Self::inspect_failed_transition(
                    attempt,
                    signature,
                    MagicLinkAttemptState::Sent,
                ))
            }
        }
    }

    #[instrument]
    fn inspect_failed_transition(
        attempt: MagicLinkAttempt,
        signature: &str,
        state: MagicLinkAttemptState,
    ) -> MagicLinkTransitionError {
        if attempt.nonce_signature != signature {
            tracing::info!("Nonce signature does not match stored signature");
            MagicLinkTransitionError::Nonce
        } else if attempt.attempt_state != state {
            tracing::info!("Attempt is not in a valid state to transition");
            MagicLinkTransitionError::State(attempt.attempt_state)
        } else if attempt.expiration <= Utc::now() {
            tracing::info!("Attempt is expired");
            MagicLinkTransitionError::Expired
        } else {
            tracing::error!(id = ?attempt.id, "Unknown error occurred in attempting to determine magic link transition failure");
            MagicLinkTransitionError::Unknown
        }
    }
}

pub trait MagicLinkMessage: Send + Sync {
    fn create_message(&self, recipient: &str, token: &str, url: &Url) -> Option<Message>;
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use newtype_uuid::TypedUuid;
    use std::{
        collections::HashMap,
        ops::Add,
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, Ordering},
        },
    };
    use url::Url;
    use uuid::Uuid;
    use v_model::{
        MagicLink, MagicLinkAttempt, MagicLinkId, MagicLinkRedirectUri, MagicLinkSecret,
        permissions::Caller,
        schema_ext::{MagicLinkAttemptState, MagicLinkMedium},
        storage::{
            MockMagicLinkAttemptStore, MockMagicLinkRedirectUriStore, MockMagicLinkSecretStore,
            MockMagicLinkStore,
        },
    };

    use super::{MagicLinkContext, MagicLinkMessage, MagicLinkTarget};
    use crate::{
        authn::key::RawKey,
        context::test_mocks::{MockStorage, mock_context},
        messenger::{Message, Messenger, MessengerError},
        permissions::VPermission,
        response::ResourceError,
    };

    struct TestMessageBuilder {}
    impl MagicLinkMessage for TestMessageBuilder {
        fn create_message(&self, recipient: &str, _token: &str, url: &Url) -> Option<Message> {
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
                    && attempt_transition.nonce_signature == signature
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
        assert!(matches!(error, ResourceError::DoesNotExist));

        let transitioned_attempt = mlink_ctx
            .complete_login_attempt(attempt.id, &attempt.nonce_signature)
            .await
            .unwrap();
        assert_eq!(
            MagicLinkAttemptState::Complete,
            transitioned_attempt.attempt_state
        );
    }

    fn caller_for_client(client_id: TypedUuid<MagicLinkId>) -> Caller<VPermission> {
        Caller {
            id: TypedUuid::new_v4(),
            permissions: vec![
                VPermission::GetMagicLinkClient(client_id),
                VPermission::ManageMagicLinkClient(client_id),
            ]
            .into(),
            extensions: HashMap::default(),
        }
    }

    /// An attacker managing their own client `C` must NOT be able
    /// to delete a secret belonging to a different client `V`, even though they
    /// authorize the request against `C` and know `V`'s secret id.
    #[tokio::test]
    async fn cannot_delete_secret_of_unauthorized_client() {
        let attacker_client_id = TypedUuid::new_v4();
        let victim_client_id = TypedUuid::new_v4();
        let victim_secret_id = TypedUuid::new_v4();

        // The attacker's own client owns no secrets.
        let mut client_store = MockMagicLinkStore::new();
        client_store.expect_get().returning(move |id, _| {
            Ok(Some(MagicLink {
                id: *id,
                secrets: vec![],
                redirect_uris: vec![],
                created_at: Utc::now(),
                deleted_at: None,
            }))
        });

        // Faithfully model the Postgres store, which would soft-delete purely
        // by secret id and return the victim's record if reached.
        let mut secret_store = MockMagicLinkSecretStore::new();
        secret_store.expect_delete().returning(move |id| {
            Ok(Some(MagicLinkSecret {
                id: *id,
                magic_link_client_id: victim_client_id,
                secret_signature: "victim-secret".to_string(),
                created_at: Utc::now(),
                deleted_at: Some(Utc::now()),
            }))
        });

        let mut storage = MockStorage::new();
        storage.magic_link_store = Some(Arc::new(client_store));
        storage.magic_link_secret_store = Some(Arc::new(secret_store));
        let ctx = mock_mlink_context(Arc::new(storage));

        let attacker = caller_for_client(attacker_client_id);
        let result = ctx
            .delete_magic_link_secret(&attacker, &victim_secret_id, &attacker_client_id)
            .await;

        if let Ok(deleted) = result {
            assert_eq!(
                deleted.magic_link_client_id, attacker_client_id,
                "IDOR: deleted secret {:?} owned by client {:?} while only authorized to manage \
                 client {:?}",
                deleted.id, deleted.magic_link_client_id, attacker_client_id,
            );
        }
    }

    #[tokio::test]
    async fn cannot_delete_redirect_uri_of_unauthorized_client() {
        let attacker_client_id = TypedUuid::new_v4();
        let victim_client_id = TypedUuid::new_v4();
        let victim_redirect_uri_id = TypedUuid::new_v4();

        let mut client_store = MockMagicLinkStore::new();
        client_store.expect_get().returning(move |id, _| {
            Ok(Some(MagicLink {
                id: *id,
                secrets: vec![],
                redirect_uris: vec![],
                created_at: Utc::now(),
                deleted_at: None,
            }))
        });

        let mut redirect_store = MockMagicLinkRedirectUriStore::new();
        redirect_store.expect_delete().returning(move |id| {
            Ok(Some(MagicLinkRedirectUri {
                id: *id,
                magic_link_client_id: victim_client_id,
                redirect_uri: "https://victim.example.com/callback".to_string(),
                created_at: Utc::now(),
                deleted_at: Some(Utc::now()),
            }))
        });

        let mut storage = MockStorage::new();
        storage.magic_link_store = Some(Arc::new(client_store));
        storage.magic_link_redirect_store = Some(Arc::new(redirect_store));
        let ctx = mock_mlink_context(Arc::new(storage));

        let attacker = caller_for_client(attacker_client_id);
        let result = ctx
            .delete_magic_link_redirect_uri(&attacker, &victim_redirect_uri_id, &attacker_client_id)
            .await;

        if let Ok(deleted) = result {
            assert_eq!(
                deleted.magic_link_client_id, attacker_client_id,
                "IDOR: deleted redirect URI {:?} owned by client {:?} while only authorized to \
                 manage client {:?}",
                deleted.id, deleted.magic_link_client_id, attacker_client_id,
            );
        }
    }

    #[tokio::test]
    async fn can_delete_own_secret() {
        let client_id = TypedUuid::new_v4();
        let secret_id = TypedUuid::new_v4();

        let owned_secret = MagicLinkSecret {
            id: secret_id,
            magic_link_client_id: client_id,
            secret_signature: "own-secret".to_string(),
            created_at: Utc::now(),
            deleted_at: None,
        };

        let client = MagicLink {
            id: client_id,
            secrets: vec![owned_secret.clone()],
            redirect_uris: vec![],
            created_at: Utc::now(),
            deleted_at: None,
        };

        let mut client_store = MockMagicLinkStore::new();
        client_store
            .expect_get()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut secret_store = MockMagicLinkSecretStore::new();
        secret_store.expect_delete().returning(move |id| {
            Ok(Some(MagicLinkSecret {
                id: *id,
                magic_link_client_id: client_id,
                secret_signature: "own-secret".to_string(),
                created_at: Utc::now(),
                deleted_at: Some(Utc::now()),
            }))
        });

        let mut storage = MockStorage::new();
        storage.magic_link_store = Some(Arc::new(client_store));
        storage.magic_link_secret_store = Some(Arc::new(secret_store));
        let ctx = mock_mlink_context(Arc::new(storage));

        let caller = caller_for_client(client_id);
        let deleted = ctx
            .delete_magic_link_secret(&caller, &secret_id, &client_id)
            .await
            .expect("a client manager should be able to delete their own secret");

        assert_eq!(deleted.id, secret_id);
        assert_eq!(deleted.magic_link_client_id, client_id);
    }

    #[tokio::test]
    async fn can_delete_own_redirect_uri() {
        let client_id = TypedUuid::new_v4();
        let redirect_uri_id = TypedUuid::new_v4();

        let owned_redirect = MagicLinkRedirectUri {
            id: redirect_uri_id,
            magic_link_client_id: client_id,
            redirect_uri: "https://client.example.com/callback".to_string(),
            created_at: Utc::now(),
            deleted_at: None,
        };

        let client = MagicLink {
            id: client_id,
            secrets: vec![],
            redirect_uris: vec![owned_redirect.clone()],
            created_at: Utc::now(),
            deleted_at: None,
        };

        let mut client_store = MockMagicLinkStore::new();
        client_store
            .expect_get()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut redirect_store = MockMagicLinkRedirectUriStore::new();
        redirect_store.expect_delete().returning(move |id| {
            Ok(Some(MagicLinkRedirectUri {
                id: *id,
                magic_link_client_id: client_id,
                redirect_uri: "https://client.example.com/callback".to_string(),
                created_at: Utc::now(),
                deleted_at: Some(Utc::now()),
            }))
        });

        let mut storage = MockStorage::new();
        storage.magic_link_store = Some(Arc::new(client_store));
        storage.magic_link_redirect_store = Some(Arc::new(redirect_store));
        let ctx = mock_mlink_context(Arc::new(storage));

        let caller = caller_for_client(client_id);
        let deleted = ctx
            .delete_magic_link_redirect_uri(&caller, &redirect_uri_id, &client_id)
            .await
            .expect("a client manager should be able to delete their own redirect URI");

        assert_eq!(deleted.id, redirect_uri_id);
        assert_eq!(deleted.magic_link_client_id, client_id);
    }
}
