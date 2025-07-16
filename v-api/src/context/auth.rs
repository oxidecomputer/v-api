// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use dropshot::RequestContext;
use jsonwebtoken::jwk::JwkSet;
use std::{collections::HashMap, sync::Arc};
use v_model::permissions::Caller;

use crate::{
    authn::{
        jwt::{Claims, JwtSigner, JwtSignerError},
        AuthError, AuthToken, Signer, VerificationResult, Verifier,
    },
    config::{AsymmetricKey, JwtConfig},
    endpoints::login::oauth::{
        OAuthProvider, OAuthProviderError, OAuthProviderFn, OAuthProviderName,
    },
    error::AppError,
    permissions::{VAppPermission, VPermission},
    ApiContext,
};

pub struct AuthContext<T> {
    unauthenticated_caller: Caller<T>,
    registration_caller: Caller<T>,
    jwt: JwtContext,
    secrets: SecretContext,
    oauth_providers: HashMap<OAuthProviderName, Box<dyn OAuthProviderFn>>,
}

impl<T> AuthContext<T>
where
    T: VAppPermission,
{
    pub fn new(jwt: JwtConfig, keys: Vec<AsymmetricKey>) -> Result<Self, AppError> {
        let mut signers = vec![];
        let mut verifiers = vec![];

        for key in &keys {
            match &key {
                &AsymmetricKey::LocalSigner { .. } | &AsymmetricKey::CkmsSigner { .. } => {
                    signers.push(key);
                }
                &AsymmetricKey::LocalVerifier { .. } | &AsymmetricKey::CkmsVerifier { .. } => {
                    verifiers.push(key);
                }
            }
        }

        Ok(Self {
            unauthenticated_caller: Caller {
                id: "00000000-0000-4000-8000-000000000000".parse().unwrap(),
                permissions: vec![].into(),
                extensions: HashMap::default(),
            },
            registration_caller: Caller {
                id: "00000000-0000-4000-8000-000000000001".parse().unwrap(),
                permissions: vec![
                    VPermission::CreateApiUser.into(),
                    VPermission::GetApiUsersAll.into(),
                    VPermission::ManageApiUsersAll.into(),
                    VPermission::GetApiKeysAll.into(),
                    VPermission::CreateGroup.into(),
                    VPermission::GetGroupsAll.into(),
                    VPermission::CreateMapper.into(),
                    VPermission::GetMappersAll.into(),
                    VPermission::GetOAuthClientsAll.into(),
                    VPermission::CreateAccessToken.into(),
                ]
                .into(),
                extensions: HashMap::default(),
            },
            jwt: JwtContext {
                default_expiration: jwt.default_expiration,
                jwks: JwkSet {
                    keys: verifiers
                        .iter()
                        .map(|k| k.as_jwk())
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?,
                },
                signers: signers
                    .iter()
                    .map(|k| JwtSigner::new(k))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?,
            },
            secrets: SecretContext {
                signers: signers
                    .iter()
                    .map(|k| k.as_signer())
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?,
                verifiers: verifiers
                    .iter()
                    .map(|k| k.as_verifier())
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?,
            },
            oauth_providers: HashMap::new(),
        })
    }

    pub fn builtin_unauthenticated_caller(&self) -> Caller<T> {
        self.unauthenticated_caller.clone()
    }

    pub fn builtin_unauthenticated_caller_mut(&mut self) -> &mut Caller<T> {
        &mut self.unauthenticated_caller
    }

    pub fn builtin_registration_user(&self) -> Caller<T> {
        self.registration_caller.clone()
    }

    pub fn builtin_registration_user_mut(&mut self) -> &mut Caller<T> {
        &mut self.registration_caller
    }

    pub fn default_jwt_expiration(&self) -> i64 {
        self.jwt.default_expiration
    }

    pub async fn jwks(&self) -> &JwkSet {
        &self.jwt.jwks
    }

    pub async fn sign_jwt(&self, claims: &Claims) -> Result<String, JwtSignerError> {
        let signer = self.jwt.signers.first().unwrap();
        signer.sign(claims).await
    }

    pub fn jwt_signer(&self) -> &JwtSigner {
        // We would have panic'd via from invalid index access with an empty list
        self.jwt.signers.first().unwrap()
    }

    pub fn signer(&self) -> &dyn Signer {
        &*self.secrets.signers[0]
    }

    pub fn verifiers(&self) -> &[Arc<dyn Verifier>] {
        &self.secrets.verifiers
    }

    pub fn insert_oauth_provider(
        &mut self,
        name: OAuthProviderName,
        provider_fn: Box<dyn OAuthProviderFn>,
    ) {
        self.oauth_providers.insert(name, provider_fn);
    }

    pub async fn get_oauth_provider(
        &self,
        provider: &OAuthProviderName,
    ) -> Result<Box<dyn OAuthProvider + Send + Sync>, OAuthProviderError> {
        self.oauth_providers
            .get(provider)
            .map(|factory| (*factory)())
            .ok_or(OAuthProviderError::FailToCreateInvalidProvider)
    }

    pub async fn authn_token(
        &self,
        rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    ) -> Result<Option<AuthToken>, AuthError> {
        match AuthToken::extract(rqctx).await {
            Ok(token) => Ok(Some(token)),
            Err(err) => match err {
                AuthError::NoToken => Ok(None),
                other => Err(other),
            },
        }
    }
}

#[async_trait]
impl<T> Verifier for AuthContext<T>
where
    T: VAppPermission,
{
    fn verify(&self, message: &[u8], signature: &[u8]) -> VerificationResult {
        let mut combined_result = VerificationResult::default();
        for verifier in self.verifiers() {
            let mut result = verifier.verify(message, signature);
            combined_result.verified = combined_result.verified || result.verified;
            combined_result.errors.append(&mut result.errors);
        }

        combined_result
    }
}

pub struct JwtContext {
    pub default_expiration: i64,
    pub signers: Vec<JwtSigner>,
    pub jwks: JwkSet,
}

pub struct SecretContext {
    pub signers: Vec<Arc<dyn Signer>>,
    pub verifiers: Vec<Arc<dyn Verifier>>,
}

#[cfg(test)]
mod tests {
    use crate::{
        authn::Verifier,
        config::JwtConfig,
        context::auth::AuthContext,
        permissions::VPermission,
        util::tests::{mock_key, MockKey},
    };

    #[tokio::test]
    async fn test_construct_with_signers_and_verifiers() {
        let MockKey {
            verifier: wrong_verifier,
            ..
        } = mock_key("test1");
        let MockKey { signer, verifier } = mock_key("test2");
        let ctx = AuthContext::<VPermission>::new(
            JwtConfig {
                default_expiration: 5000,
            },
            vec![signer, wrong_verifier, verifier],
        )
        .unwrap();

        let data = vec![1, 2, 3, 4, 5, 6];
        let signature = ctx.signer().sign(&data).await.unwrap();
        let verification = ctx.verify(&data, &signature);
        assert!(verification.verified);
    }
}
