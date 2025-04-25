// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use google_cloudkms1::{
    hyper_rustls::{HttpsConnector, HttpsConnectorBuilder},
    hyper_util::client::legacy::{connect::HttpConnector, Client},
    hyper_util::rt::TokioExecutor,
    CloudKMS,
};

use crate::authn::CloudKmsError;

pub mod request {
    use cookie::Cookie;
    use dropshot::RequestInfo;
    use http::header::COOKIE;

    pub trait RequestCookies {
        fn cookie(&self, name: &str) -> Option<Cookie>;
    }

    impl RequestCookies for RequestInfo {
        fn cookie(&self, name: &str) -> Option<Cookie> {
            let cookie_header = self.headers().get(COOKIE)?;

            Cookie::split_parse(String::from_utf8(cookie_header.as_bytes().to_vec()).unwrap())
                .filter_map(|cookie| match cookie {
                    Ok(cookie) => {
                        if cookie.name() == name {
                            Some(cookie)
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .nth(0)
        }
    }
}

pub mod response {
    use dropshot::{ClientErrorStatusCode, HttpError};
    use std::{error::Error, fmt::Debug};
    use thiserror::Error;
    use tracing::instrument;
    use v_model::storage::StoreError;

    pub fn conflict() -> HttpError {
        client_error(ClientErrorStatusCode::CONFLICT, "Already exists")
    }

    pub fn unauthorized() -> HttpError {
        client_error(ClientErrorStatusCode::UNAUTHORIZED, "Unauthorized")
    }

    pub fn forbidden() -> HttpError {
        client_error(ClientErrorStatusCode::FORBIDDEN, "Unauthorized")
    }

    pub fn client_error<S>(status_code: ClientErrorStatusCode, message: S) -> HttpError
    where
        S: ToString,
    {
        HttpError::for_client_error(None, status_code, message.to_string())
    }

    pub fn bad_request<S>(message: S) -> HttpError
    where
        S: ToString,
    {
        HttpError::for_bad_request(None, message.to_string())
    }

    pub fn not_found(internal_message: &str) -> HttpError {
        HttpError::for_not_found(None, internal_message.to_string())
    }

    #[instrument(skip(error))]
    pub fn to_internal_error<E>(error: E) -> HttpError
    where
        E: Error,
    {
        tracing::error!(?error, "Encountered internal error");
        internal_error(error.to_string())
    }

    #[instrument(skip(internal_message))]
    pub fn internal_error<S>(internal_message: S) -> HttpError
    where
        S: ToString + Debug,
    {
        let internal_message_fmt = internal_message.to_string();
        tracing::error!(error = ?internal_message, message = internal_message_fmt, "Request failed");
        HttpError::for_internal_error(internal_message_fmt)
    }

    pub type ResourceResult<T, E> = Result<T, ResourceError<E>>;

    #[derive(Debug, Error)]
    pub enum ResourceError<E> {
        #[error("Resource operation resulted in a conflict")]
        Conflict,
        #[error("Resource does not exist")]
        DoesNotExist,
        #[error("Caller does not have required access")]
        Restricted,
        #[error("Internal server error")]
        InternalError(#[source] E),
    }

    pub trait ResourceErrorInner<T, E> {
        fn inner_err_into<F>(self) -> ResourceResult<T, F>
        where
            F: From<E>;
    }

    impl<T, E> ResourceErrorInner<T, E> for ResourceResult<T, E> {
        fn inner_err_into<F>(self) -> ResourceResult<T, F>
        where
            F: From<E>,
        {
            match self {
                Ok(v) => Ok(v),
                Err(ResourceError::Conflict) => Err(ResourceError::Conflict),
                Err(ResourceError::DoesNotExist) => Err(ResourceError::DoesNotExist),
                Err(ResourceError::Restricted) => Err(ResourceError::Restricted),
                Err(ResourceError::InternalError(inner)) => {
                    Err(ResourceError::InternalError(inner.into()))
                }
            }
        }
    }

    impl<T> From<StoreError> for ResourceError<T>
    where
        T: From<StoreError>,
    {
        fn from(value: StoreError) -> Self {
            match value {
                StoreError::Conflict => ResourceError::Conflict,
                _ => ResourceError::InternalError(value.into()),
            }
        }
    }

    pub trait OptionalResource<T, E> {
        fn optional<F>(self) -> ResourceResult<T, F>
        where
            F: From<E>;
    }

    impl<T, E> OptionalResource<T, E> for Result<Option<T>, E> {
        fn optional<F>(self) -> ResourceResult<T, F>
        where
            F: From<E>,
        {
            match self {
                Ok(Some(v)) => Ok(v),
                Ok(None) => Err(ResourceError::DoesNotExist),
                Err(e) => Err(ResourceError::InternalError(e.into())),
            }
        }
    }

    pub fn resource_not_found<T, E>() -> ResourceResult<T, E> {
        ResourceResult::Err(ResourceError::DoesNotExist)
    }

    pub fn resource_restricted<T, E>() -> ResourceResult<T, E> {
        ResourceResult::Err(ResourceError::Restricted)
    }

    pub fn resource_error<T, E>(err: E) -> ResourceResult<T, E> {
        ResourceResult::Err(ResourceError::InternalError(err))
    }

    impl<E> From<ResourceError<E>> for HttpError
    where
        E: Error,
    {
        fn from(value: ResourceError<E>) -> Self {
            match value {
                ResourceError::Conflict => conflict(),
                ResourceError::DoesNotExist => not_found(""),
                ResourceError::InternalError(err) => to_internal_error(err),
                ResourceError::Restricted => forbidden(),
            }
        }
    }
}

pub async fn cloud_kms_client() -> Result<CloudKMS<HttpsConnector<HttpConnector>>, CloudKmsError> {
    let opts = yup_oauth2::ApplicationDefaultCredentialsFlowOpts::default();

    tracing::trace!(?opts, "Request GCP credentials");

    let gcp_credentials =
        yup_oauth2::ApplicationDefaultCredentialsAuthenticator::builder(opts).await;

    tracing::trace!("Retrieved GCP credentials");

    let gcp_auth = match gcp_credentials {
        yup_oauth2::authenticator::ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => {
            tracing::debug!("Create GCP service account based credentials");

            auth.build().await.map_err(|err| {
                tracing::error!(
                    ?err,
                    "Failed to construct Cloud KMS credentials from service account"
                );
                CloudKmsError::RemoteKeyAuthMissing(err)
            })?
        }
        yup_oauth2::authenticator::ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => {
            tracing::debug!("Create GCP instance based credentials");

            auth.build().await.map_err(|err| {
                tracing::error!(
                    ?err,
                    "Failed to construct Cloud KMS credentials from instance metadata"
                );
                CloudKmsError::RemoteKeyAuthMissing(err)
            })?
        }
    };

    let gcp_kms = CloudKMS::new(
        Client::builder(TokioExecutor::new()).build(
            HttpsConnectorBuilder::new()
                .with_native_roots()
                .unwrap()
                .https_only()
                .enable_http2()
                .build(),
        ),
        gcp_auth,
    );

    Ok(gcp_kms)
}

#[cfg(test)]
pub mod tests {
    use dropshot::{HttpCodedResponse, HttpError};
    use http::StatusCode;
    use rand_core::RngCore;
    use rsa::{
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        RsaPrivateKey, RsaPublicKey,
    };

    use crate::config::AsymmetricKey;

    pub fn get_status<T>(res: &Result<T, HttpError>) -> StatusCode
    where
        T: HttpCodedResponse,
    {
        match res {
            Ok(_) => T::STATUS_CODE,
            Err(err) => err.status_code.as_status(),
        }
    }

    pub fn mock_key() -> AsymmetricKey {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);

        let mut kid = [0; 24];
        rng.fill_bytes(&mut kid);

        AsymmetricKey::Local {
            kid: hex::encode(kid),
            private: String::from_utf8(
                priv_key
                    .to_pkcs8_pem(LineEnding::LF)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap(),
            public: pub_key.to_public_key_pem(LineEnding::LF).unwrap(),
        }
    }
}
