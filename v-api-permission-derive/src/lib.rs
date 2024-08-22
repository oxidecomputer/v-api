// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use heck::ToSnakeCase;
use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::{format_ident, quote, quote_spanned};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    Data, DeriveInput, Error, Ident, Result, Token, Variant,
};

static MACRO_ID: &str = "v_api";

#[derive(Clone, Debug)]
struct DerivePermissionsFrom {
    source: Ident,
}

impl Parse for DerivePermissionsFrom {
    fn parse(input: ParseStream) -> Result<Self> {
        let _: Ident = input.parse()?;
        let source;
        syn::parenthesized!(source in input);

        Ok(DerivePermissionsFrom {
            source: source.parse()?,
        })
    }
}

#[derive(Clone, Debug)]
struct VariantSettings(Vec<VariantSetting>);

#[derive(Clone, Debug)]
enum VariantSetting {
    Contract(ContractSettings),
    Expand(ExpandSettings),
    Scope(ScopeSettings),
}

#[derive(Clone, Debug)]
struct ScopeSettings {
    from: Option<Literal>,
    to: Option<Literal>,
}

#[derive(Clone, Debug)]
struct ContractSettings {
    kind: ContractKind,
    variant: Ident,
}

#[derive(Clone, Debug, PartialEq)]
enum ContractKind {
    Append,
    Drop,
    Extend,
}

#[derive(Clone, Debug)]
struct ExpandSettings {
    kind: ExpandKind,
    variant: Ident,
    source: Option<ExternalSource>,
    ext: Option<String>,
    field: Option<ExternalField>,
}

#[derive(Clone, Debug)]
enum ExternalSource {
    Actor,
    Extension,
}

impl ExternalSource {
    fn to_ident(&self) -> Ident {
        match self {
            Self::Actor => format_ident!("actor"),
            Self::Extension => format_ident!("extensions"),
        }
    }
}

#[derive(Clone, Debug)]
enum ExternalField {
    Id,
    Groups,
    Extension(String),
}

impl ExternalField {
    fn to_ident(&self) -> Ident {
        match self {
            Self::Id => format_ident!("id"),
            Self::Groups => format_ident!("groups"),
            Self::Extension(field) => format_ident!("{}", field),
        }
    }
}

#[derive(Clone, Debug)]
enum ExpandKind {
    Alias,
    Iter,
    Replace,
}

impl Parse for VariantSettings {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut settings = vec![];

        while !input.is_empty() {
            let name: Ident = input.parse()?;
            let content;
            syn::parenthesized!(content in input);
            let _: Result<Token![,]> = input.parse();

            if name == "contract" {
                settings.push(VariantSetting::Contract(
                    content.parse::<ContractSettings>()?,
                ));
            } else if name == "expand" {
                settings.push(VariantSetting::Expand(content.parse::<ExpandSettings>()?));
            } else if name == "scope" {
                settings.push(VariantSetting::Scope(content.parse::<ScopeSettings>()?));
            }
        }

        Ok(Self(settings))
    }
}

#[derive(Clone, Debug)]
struct SettingValue<T> {
    name: Ident,
    value: T,
}

fn parse_setting<T>(input: ParseStream) -> Result<Option<SettingValue<T>>>
where
    T: Parse,
{
    let name: Ident = input.parse()?;
    let _: Token![=] = input.parse()?;
    let value: T = input.parse()?;
    Ok(Some(SettingValue { name, value }))
}

impl Parse for ContractSettings {
    fn parse(input: ParseStream) -> Result<Self> {
        let span = input.span();
        let mut settings = vec![];
        while !input.is_empty() {
            if let Some(setting) = parse_setting::<Ident>(input)? {
                let _: Result<Token![,]> = input.parse();
                settings.push(setting);
            }
        }

        let kind = settings
            .iter()
            .cloned()
            .find(|s| s.name == "kind")
            .ok_or_else(|| Error::new(span, "Expand must contain a \"kind\" setting"))?;

        Ok(ContractSettings {
            kind: match kind.value.to_string().as_str() {
                "append" => ContractKind::Append,
                "drop" => ContractKind::Drop,
                "extend" => ContractKind::Extend,
                _ => return Err(Error::new(span, "Unexpected contract kind")),
            },
            variant: settings
                .pop()
                .expect("Contract must contain a \"variant\" setting")
                .value,
        })
    }
}

impl Parse for ExpandSettings {
    fn parse(input: ParseStream) -> Result<Self> {
        let span = input.span();
        let mut settings = vec![];
        while !input.is_empty() {
            if let Some(setting) = parse_setting::<Ident>(input)? {
                let _: Result<Token![,]> = input.parse();
                settings.push(setting);
            }
        }

        let kind = settings
            .iter()
            .cloned()
            .find(|s| s.name == "kind")
            .ok_or_else(|| Error::new(span, "Expand must contain a \"kind\" setting"))?;

        Ok(ExpandSettings {
            kind: match kind.value.to_string().as_str() {
                "alias" => ExpandKind::Alias,
                "iter" => ExpandKind::Iter,
                "replace" => ExpandKind::Replace,
                _ => return Err(Error::new(span, "Unexpected expand kind")),
            },
            variant: settings
                .iter()
                .cloned()
                .find(|s| s.name == "variant")
                .expect("Expand must contain a \"variant\" setting")
                .value,
            source: settings.iter().find(|s| s.name == "source").map(|s| {
                match s.value.to_string().as_str() {
                    "actor" => ExternalSource::Actor,
                    "ext" => ExternalSource::Extension,
                    _ => panic!("Unexpected source value"),
                }
            }),
            ext: settings
                .iter()
                .find(|s| s.name == "ext")
                .map(|s| s.value.to_string()),
            field: settings.iter().find(|s| s.name == "field").map(|s| {
                match s.value.to_string().as_str() {
                    "id" => ExternalField::Id,
                    "groups" => ExternalField::Groups,
                    other => ExternalField::Extension(other.to_string()),
                }
            }),
        })
    }
}

impl Parse for ScopeSettings {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut settings = vec![];
        while !input.is_empty() {
            if let Some(setting) = parse_setting::<Literal>(input)? {
                let _: Result<Token![,]> = input.parse();
                settings.push(setting);
            }
        }

        Ok(ScopeSettings {
            from: settings
                .iter()
                .cloned()
                .find(|v| v.name == "from")
                .map(|v| v.value),
            to: settings
                .iter()
                .cloned()
                .find(|v| v.name == "to")
                .map(|v| v.value),
        })
    }
}

#[proc_macro_attribute]
pub fn v_api(attr: TokenStream, input: TokenStream) -> TokenStream {
    let attr = parse_macro_input!(attr as DerivePermissionsFrom);
    let mut input = parse_macro_input!(input as DeriveInput);
    input = match inject_system_permission_variants(input) {
        Ok(input) => input,
        Err(err) => return err.to_compile_error().into(),
    };
    let input_span = input.span();

    let mut contract_settings = vec![];
    let mut expand_settings = vec![];
    let mut scope_settings = vec![];

    let trait_impl_tokens: proc_macro2::TokenStream = match input.data {
        Data::Enum(ref mut data_enum) => {
            for variant in data_enum.variants.iter_mut() {
                let variant_clone = variant.clone();
                for variant_attrs in variant.attrs.iter_mut() {
                    if variant_attrs.path().is_ident(MACRO_ID) {
                        match variant_attrs.parse_args::<VariantSettings>() {
                            Ok(VariantSettings(settings)) => {
                                for setting in settings {
                                    match setting {
                                        VariantSetting::Contract(setting) => contract_settings
                                            .push((variant_clone.clone(), setting.clone())),
                                        VariantSetting::Expand(setting) => expand_settings
                                            .push((variant_clone.clone(), setting.clone())),
                                        VariantSetting::Scope(setting) => scope_settings
                                            .push((variant_clone.clone(), setting.clone())),
                                    }
                                }
                            }
                            Err(err) => return err.into_compile_error().into(),
                        }
                    }
                }

                variant.attrs.retain(|attr| !attr.path().is_ident(MACRO_ID));
            }
            let as_scope_out = as_scope_trait_tokens(input.ident.clone(), scope_settings);
            let permission_storage_out =
                permission_storage_trait_tokens(&input.ident, contract_settings, expand_settings);

            quote! {
                #as_scope_out
                #permission_storage_out
            }
            .into()
        }
        _ => quote_spanned! {
                input_span => compile_error!("v_api may only be applied to enums");
        }
        .into(),
    };

    let from = from_system_permission_tokens(&attr.source, &input.ident);

    // TODO: Inspect existing derive and add only the missing derive attributes
    // #[derive(
    //     Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema, PartialOrd, Ord,
    // )]

    quote! {
        #input
        #from
        #trait_impl_tokens
    }
    .into()
}

struct LiteralKey {
    key: String,
    inner: Literal,
}

impl LiteralKey {
    pub fn new(inner: &Literal) -> Self {
        Self {
            key: inner.to_string(),
            inner: inner.clone(),
        }
    }
}

impl PartialEq for LiteralKey {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for LiteralKey {}

impl Hash for LiteralKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

fn from_system_permission_tokens(
    source: &Ident,
    permission_type: &Ident,
) -> proc_macro2::TokenStream {
    if source != permission_type {
        quote! {
            impl From<#source> for #permission_type {
                fn from(value: VPermission) -> Self {
                    match value {
                        VPermission::CreateApiUser => Self::CreateApiUser,
                        VPermission::GetApiUser(inner) => Self::GetApiUser(inner),
                        VPermission::GetApiUsers(inner) => Self::GetApiUsers(inner),
                        VPermission::GetApiUserSelf => Self::GetApiUserSelf,
                        VPermission::GetApiUsersAssigned => Self::GetApiUsersAssigned,
                        VPermission::GetApiUsersAll => Self::GetApiUsersAll,
                        VPermission::ManageApiUser(inner) => Self::ManageApiUser(inner),
                        VPermission::ManageApiUsers(inner) => Self::ManageApiUsers(inner),
                        VPermission::ManageApiUsersAssigned => Self::ManageApiUsersAssigned,
                        VPermission::ManageApiUsersAll => Self::ManageApiUsersAll,

                        VPermission::CreateApiKey(inner) => Self::CreateApiKey(inner),
                        VPermission::CreateApiKeySelf => Self::CreateApiKeySelf,
                        VPermission::CreateApiKeyAssigned => Self::CreateApiKeyAssigned,
                        VPermission::CreateApiKeyAll => Self::CreateApiKeyAll,
                        VPermission::GetApiKey(inner) => Self::GetApiKey(inner),
                        VPermission::GetApiKeys(inner) => Self::GetApiKeys(inner),
                        VPermission::GetApiKeysAssigned => Self::GetApiKeysAssigned,
                        VPermission::GetApiKeysAll => Self::GetApiKeysAll,
                        VPermission::ManageApiKey(inner) => Self::ManageApiKey(inner),
                        VPermission::ManageApiKeys(inner) => Self::ManageApiKeys(inner),
                        VPermission::ManageApiKeysAssigned => Self::ManageApiKeysAssigned,
                        VPermission::ManageApiKeysAll => Self::ManageApiKeysAll,

                        VPermission::CreateUserApiProviderLinkToken => Self::CreateUserApiProviderLinkToken,

                        VPermission::CreateGroup => Self::CreateGroup,
                        VPermission::GetGroup(inner) => Self::GetGroup(inner),
                        VPermission::GetGroupsJoined => Self::GetGroupsJoined,
                        VPermission::GetGroupsAll => Self::GetGroupsAll,
                        VPermission::ManageGroup(inner) => Self::ManageGroup(inner),
                        VPermission::ManageGroups(inner) => Self::ManageGroups(inner),
                        VPermission::ManageGroupsAssigned => Self::ManageGroupsAssigned,
                        VPermission::ManageGroupsAll => Self::ManageGroupsAll,

                        VPermission::ManageGroupMembership(inner) => Self::ManageGroupMembership(inner),
                        VPermission::ManageGroupMemberships(inner) => Self::ManageGroupMemberships(inner),
                        VPermission::ManageGroupMembershipsAssigned => Self::ManageGroupMembershipsAssigned,
                        VPermission::ManageGroupMembershipsAll => Self::ManageGroupMembershipsAll,

                        VPermission::CreateMapper => Self::CreateMapper,
                        VPermission::GetMappersAll => Self::GetMappersAll,
                        VPermission::ManageMapper(inner) => Self::ManageMapper(inner),
                        VPermission::ManageMappers(inner) => Self::ManageMappers(inner),
                        VPermission::ManageMappersAssigned => Self::ManageMappersAssigned,
                        VPermission::ManageMappersAll => Self::ManageMappersAll,

                        VPermission::CreateOAuthClient => Self::CreateOAuthClient,
                        VPermission::GetOAuthClient(inner) => Self::GetOAuthClient(inner),
                        VPermission::GetOAuthClients(inner) => Self::GetOAuthClients(inner),
                        VPermission::GetOAuthClientsAssigned => Self::GetOAuthClientsAssigned,
                        VPermission::GetOAuthClientsAll => Self::GetOAuthClientsAll,
                        VPermission::ManageOAuthClient(inner) => Self::ManageOAuthClient(inner),
                        VPermission::ManageOAuthClients(inner) => Self::ManageOAuthClients(inner),
                        VPermission::ManageOAuthClientsAssigned => Self::ManageOAuthClientsAssigned,
                        VPermission::ManageOAuthClientsAll => Self::ManageOAuthClientsAll,

                        VPermission::CreateMagicLinkClient => Self::CreateMagicLinkClient,
                        VPermission::GetMagicLinkClient(inner) => Self::GetMagicLinkClient(inner),
                        VPermission::GetMagicLinkClients(inner) => Self::GetMagicLinkClients(inner),
                        VPermission::GetMagicLinkClientsAssigned => Self::GetMagicLinkClientsAssigned,
                        VPermission::GetMagicLinkClientsAll => Self::GetMagicLinkClientsAll,
                        VPermission::ManageMagicLinkClient(inner) => Self::ManageMagicLinkClient(inner),
                        VPermission::ManageMagicLinkClients(inner) => Self::ManageMagicLinkClients(inner),
                        VPermission::ManageMagicLinkClientsAssigned => Self::ManageMagicLinkClientsAssigned,
                        VPermission::ManageMagicLinkClientsAll => Self::ManageMagicLinkClientsAll,

                        VPermission::CreateAccessToken => Self::CreateAccessToken,
                        VPermission::Removed => Self::Removed,
                    }
                }
            }
        }
    } else {
        quote! {}
    }
}

fn inject_system_permission_variants(mut input: DeriveInput) -> Result<DeriveInput> {
    let input_span = input.span();
    let tokens = system_permission_tokens();
    let system_permissions: DeriveInput = syn::parse(tokens).unwrap();
    let system_variants = match system_permissions.data {
        Data::Enum(data_enum) => data_enum.variants,
        _ => unreachable!("System permissions are always an enum"),
    };

    match input.data {
        Data::Enum(ref mut data_enum) => {
            data_enum.variants.extend(system_variants);
        }
        _ => return Err(Error::new(input_span, "v_api may only be applied to enums")),
    }

    Ok(input)
}

fn system_permission_tokens() -> TokenStream {
    quote! {
        enum VPermission {
            #[v_api(scope(to = "user:info:w", from = "user:info:w"))]
            CreateApiUser,
            #[v_api(
                contract(kind = append, variant = GetApiUsers),
                scope(to = "user:info:r")
            )]
            GetApiUser(newtype_uuid::TypedUuid<v_model::UserId>),
            #[v_api(
                contract(kind = extend, variant = GetApiUsers),
                expand(kind = iter, variant = GetApiUser),
                scope(to = "user:info:r")
            )]
            GetApiUsers(BTreeSet<newtype_uuid::TypedUuid<v_model::UserId>>),
            #[v_api(
                expand(kind = replace, variant = GetApiUser, source = actor, field = id)
                scope(to = "user:info:r", from = "user:info:r")
            )]
            GetApiUserSelf,
            #[v_api(
                expand(kind = alias, variant = GetApiUser, source = actor),
                scope(to = "user:info:r", from = "user:info:r")
            )]
            GetApiUsersAssigned,
            #[v_api(
                scope(to = "user:info:r", from = "user:info:r")
            )]
            GetApiUsersAll,
            #[v_api(
                contract(kind = append, variant = ManageApiUsers),
                scope(to = "user:info:w")
            )]
            ManageApiUser(newtype_uuid::TypedUuid<v_model::UserId>),
            #[v_api(
                contract(kind = extend, variant = ManageApiUsers),
                expand(kind = iter, variant = ManageApiUser),
                scope(to = "user:info:w")
            )]
            ManageApiUsers(BTreeSet<newtype_uuid::TypedUuid<v_model::UserId>>),
            #[v_api(
                expand(kind = alias, variant = ManageApiUser, source = actor),
                scope(to = "user:info:w", from = "user:info:w")
            )]
            ManageApiUsersAssigned,
            #[v_api(scope(to = "user:info:w", from = "user:info:w"))]
            ManageApiUsersAll,
            #[v_api(scope(to = "user:token:w"))]
            CreateApiKey(newtype_uuid::TypedUuid<v_model::UserId>),
            #[v_api(
                expand(kind = replace, variant = CreateApiKey, source = actor, field = id),
                scope(to = "user:token:w", from = "user:token:w")
            )]
            CreateApiKeySelf,
            #[v_api(scope(to = "user:token:w", from = "user:token:w"))]
            CreateApiKeyAssigned,
            #[v_api(scope(to = "user:token:w", from = "user:token:w"))]
            CreateApiKeyAll,
            #[v_api(
                contract(kind = append, variant = GetApiKeys),
                scope(to = "user:token:r")
            )]
            GetApiKey(newtype_uuid::TypedUuid<v_model::ApiKeyId>),
            #[v_api(
                contract(kind = extend, variant = GetApiKeys),
                expand(kind = iter, variant = GetApiKey),
                scope(to = "user:token:r")
            )]
            GetApiKeys(BTreeSet<newtype_uuid::TypedUuid<v_model::ApiKeyId>>),
            #[v_api(
                expand(kind = alias, variant = GetApiKey, source = actor),
                scope(to = "user:token:r", from = "user:token:r")
            )]
            GetApiKeysAssigned,
            #[v_api(scope(to = "user:token:r", from = "user:token:r"))]
            GetApiKeysAll,
            #[v_api(
                contract(kind = append, variant = ManageApiKeys),
                scope(to = "user:token:w")
            )]
            ManageApiKey(newtype_uuid::TypedUuid<v_model::ApiKeyId>),
            #[v_api(
                contract(kind = extend, variant = ManageApiKeys),
                expand(kind = iter, variant = ManageApiKey),
                scope(to = "user:token:w")
            )]
            ManageApiKeys(BTreeSet<newtype_uuid::TypedUuid<v_model::ApiKeyId>>),
            #[v_api(
                expand(kind = alias, variant = ManageApiKey, source = actor),
                scope(to = "user:token:w", from = "user:token:w")
            )]
            ManageApiKeysAssigned,
            #[v_api(scope(to = "user:token:w", from = "user:token:w"))]
            ManageApiKeysAll,
            #[v_api(scope(to = "user:provider:w", from = "user:provider:w"))]
            CreateUserApiProviderLinkToken,
            #[v_api(scope(to = "group:info:w", from = "group:info:w"))]
            CreateGroup,
            #[v_api(
                contract(kind = drop, variant = GetGroupsJoined),
                scope(to = "group:info:r")
            )]
            GetGroup(newtype_uuid::TypedUuid<v_model::AccessGroupId>),
            #[v_api(
                expand(kind = iter, variant = GetGroup, source = actor, field = groups)
                scope(to = "group:info:r", from = "group:info:r")
            )]
            GetGroupsJoined,
            #[v_api(scope(to = "group:info:r", from = "group:info:r"))]
            GetGroupsAll,
            #[v_api(
                contract(kind = append, variant = ManageGroups),
                scope(to = "group:info:w")
            )]
            ManageGroup(newtype_uuid::TypedUuid<v_model::AccessGroupId>),
            #[v_api(
                contract(kind = extend, variant = ManageGroups),
                expand(kind = iter, variant = ManageGroup),
                scope(to = "group:info:w")
            )]
            ManageGroups(BTreeSet<newtype_uuid::TypedUuid<v_model::AccessGroupId>>),
            #[v_api(
                expand(kind = alias, variant = ManageGroup, source = actor),
                scope(to = "group:info:w", from = "group:info:w")
            )]
            ManageGroupsAssigned,
            #[v_api(scope(to = "group:info:w", from = "group:info:w"))]
            ManageGroupsAll,
            #[v_api(
                contract(kind = append, variant = ManageGroupMemberships)
                scope(to = "group:membership:w")
            )]
            ManageGroupMembership(newtype_uuid::TypedUuid<v_model::AccessGroupId>),
            #[v_api(
                contract(kind = extend, variant = ManageGroupMemberships)
                expand(kind = iter, variant = ManageGroupMembership)
                scope(to = "group:membership:w")
            )]
            ManageGroupMemberships(BTreeSet<newtype_uuid::TypedUuid<v_model::AccessGroupId>>),
            #[v_api(
                expand(kind = alias, variant = ManageGroupMembership, source = actor),
                scope(to = "group:membership:w", from = "group:membership:w")
            )]
            ManageGroupMembershipsAssigned,
            #[v_api(scope(to = "group:membership:w", from = "group:membership:w"))]
            ManageGroupMembershipsAll,

            #[v_api(scope(to = "mapper:w", from = "mapper:w"))]
            CreateMapper,
            #[v_api(scope(to = "mapper:r", from = "mapper:r"))]
            GetMappersAll,
            #[v_api(
                contract(kind = append, variant = ManageMappers),
                scope(to = "mapper:w")
            )]
            ManageMapper(newtype_uuid::TypedUuid<v_model::MapperId>),
            #[v_api(
                contract(kind = extend, variant = ManageMappers),
                expand(kind = iter, variant = ManageMapper)
                scope(to = "mapper:w")
            )]
            ManageMappers(BTreeSet<newtype_uuid::TypedUuid<v_model::MapperId>>),
            #[v_api(
                expand(kind = alias, variant = ManageMapper, source = actor)
                scope(to = "mapper:w", from = "mapper:w")
            )]
            ManageMappersAssigned,
            #[v_api(scope(to = "mapper:w", from = "mapper:w"))]
            ManageMappersAll,

            #[v_api(scope(to = "oauth:client:w", from = "oauth:client:w"))]
            CreateOAuthClient,
            #[v_api(
                contract(kind = append, variant = GetOAuthClients),
                scope(to = "oauth:client:r")
            )]
            GetOAuthClient(newtype_uuid::TypedUuid<v_model::OAuthClientId>),
            #[v_api(
                contract(kind = extend, variant = GetOAuthClients),
                expand(kind = iter, variant = GetOAuthClient),
                scope(to = "oauth:client:r")
            )]
            GetOAuthClients(BTreeSet<newtype_uuid::TypedUuid<v_model::OAuthClientId>>),
            #[v_api(
                expand(kind = alias, variant = GetOAuthClient, source = actor),
                scope(to = "oauth:client:r", from = "oauth:client:r")
            )]
            GetOAuthClientsAssigned,
            #[v_api(scope(to = "oauth:client:r", from = "oauth:client:r"))]
            GetOAuthClientsAll,
            #[v_api(
                contract(kind = append, variant = ManageOAuthClients),
                scope(to = "oauth:client:w")
            )]
            ManageOAuthClient(newtype_uuid::TypedUuid<v_model::OAuthClientId>),
            #[v_api(
                contract(kind = extend, variant = ManageOAuthClients),
                expand(kind = iter, variant = ManageOAuthClient),
                scope(to = "oauth:client:w")
            )]
            ManageOAuthClients(BTreeSet<newtype_uuid::TypedUuid<v_model::OAuthClientId>>),
            #[v_api(
                expand(kind = alias, variant = ManageOAuthClient, source = actor),
                scope(to = "oauth:client:w", from = "oauth:client:w")
            )]
            ManageOAuthClientsAssigned,
            #[v_api(scope(to = "oauth:client:w", from = "oauth:client:w"))]
            ManageOAuthClientsAll,

            #[v_api(scope(to = "mlink:client:w", from = "mlink:client:w"))]
            CreateMagicLinkClient,
            #[v_api(
                contract(kind = append, variant = GetMagicLinkClients),
                scope(to = "mlink:client:r")
            )]
            GetMagicLinkClient(newtype_uuid::TypedUuid<v_model::MagicLinkId>),
            #[v_api(
                contract(kind = extend, variant = GetMagicLinkClients),
                expand(kind = iter, variant = GetMagicLinkClient),
                scope(to = "mlink:client:r")
            )]
            GetMagicLinkClients(BTreeSet<newtype_uuid::TypedUuid<v_model::MagicLinkId>>),
            #[v_api(
                expand(kind = alias, variant = GetMagicLinkClient, source = actor),
                scope(to = "mlink:client:r", from = "mlink:client:r")
            )]
            GetMagicLinkClientsAssigned,
            #[v_api(scope(to = "mlink:client:r", from = "mlink:client:r"))]
            GetMagicLinkClientsAll,
            #[v_api(
                contract(kind = append, variant = ManageMagicLinkClients),
                scope(to = "mlink:client:w")
            )]
            ManageMagicLinkClient(newtype_uuid::TypedUuid<v_model::MagicLinkId>),
            #[v_api(
                contract(kind = extend, variant = ManageMagicLinkClients),
                expand(kind = iter, variant = ManageMagicLinkClient),
                scope(to = "mlink:client:w")
            )]
            ManageMagicLinkClients(BTreeSet<newtype_uuid::TypedUuid<v_model::MagicLinkId>>),
            #[v_api(
                expand(kind = alias, variant = ManageMagicLinkClient, source = actor),
                scope(to = "mlink:client:w", from = "mlink:client:w")
            )]
            ManageMagicLinkClientsAssigned,
            #[v_api(scope(to = "mlink:client:w", from = "mlink:client:w"))]
            ManageMagicLinkClientsAll,

            CreateAccessToken,

            #[serde(other)]
            Removed,
        }
    }
    .into()
}

fn as_scope_trait_tokens(
    permission_type: Ident,
    scope_settings: Vec<(Variant, ScopeSettings)>,
) -> proc_macro2::TokenStream {
    let as_scope_mapping = scope_settings.iter().filter_map(|(variant, settings)| {
        settings.to.as_ref().map(|to| {
            let fields = if variant.fields.len() > 0 {
                let mut fields = quote! {};
                variant
                    .fields
                    .iter()
                    .for_each(|_| fields = quote! { _, #fields });
                quote! { (#fields) }
            } else {
                quote! {}
            };
            let variant_ident = variant.ident.clone();
            quote! { #permission_type::#variant_ident #fields => #to }
        })
    });
    let from_scope_mapping = scope_settings
        .iter()
        .fold(HashMap::new(), |mut map, (variant, settings)| {
            if let Some(from) = &settings.from {
                for from in from.to_string().trim_matches('"').split(' ') {
                    let inner = Literal::string(from);
                    let entry: &mut Vec<Ident> = map.entry(LiteralKey::new(&inner)).or_default();
                    entry.push(variant.ident.clone());
                }
            }

            map
        })
        .into_iter()
        .map(|(scope, variants)| {
            let scope = scope.inner;
            let inserts = variants.into_iter().map(|variant| {
                quote! { permissions.insert(#permission_type::#variant); }
            });
            quote! {
                #scope => {
                    #(#inserts)*
                }
            }
        });

    quote! {
        impl v_model::permissions::AsScope for #permission_type {
            fn as_scope(&self) -> &str {
                match self {
                    #(#as_scope_mapping,)*
                    _ => "",
                }
            }

            fn from_scope<S>(
                scope: impl Iterator<Item = S>,
            ) -> Result<v_model::Permissions<Self>, v_model::permissions::PermissionError>
            where
                S: AsRef<str>,
            {
                let mut permissions = v_model::Permissions::default();

                for entry in scope {
                    match entry.as_ref() {
                        #(#from_scope_mapping,)*
                        other => return Err(v_model::permissions::PermissionError::InvalidScope(other.to_string())),
                    }
                }

                Ok(permissions)
            }
        }
    }
    .into()
}

fn permission_storage_trait_tokens(
    permission_type: &Ident,
    contract_settings: Vec<(Variant, ContractSettings)>,
    expand_settings: Vec<(Variant, ExpandSettings)>,
) -> proc_macro2::TokenStream {
    let contract_tokens = permission_storage_contract_tokens(permission_type, contract_settings);
    let expand_tokens = permission_storage_expand_tokens(permission_type, expand_settings);

    quote! {
        impl v_model::permissions::PermissionStorage for #permission_type {
            #contract_tokens
            #expand_tokens
        }
    }
}

fn permission_storage_contract_tokens(
    permission_type: &Ident,
    contract_settings: Vec<(Variant, ContractSettings)>,
) -> proc_macro2::TokenStream {
    let mut branches = vec![];
    let mut sets = HashMap::new();
    let stock_field_names = [
        format_ident!("f0"),
        format_ident!("f1"),
        format_ident!("f2"),
        format_ident!("f3"),
    ];

    for (variant, setting) in contract_settings {
        let variant_ident = variant.ident;
        let target_variant_ident = setting.variant;
        let set_name = format_ident!("{}", target_variant_ident.to_string().to_snake_case());
        sets.insert(
            target_variant_ident.clone(),
            (setting.kind != ContractKind::Drop).then(|| set_name.clone()),
        );

        let fields = if variant.fields.len() > 0 && setting.kind != ContractKind::Drop {
            let mut fields = quote! {};
            variant
                .fields
                .iter()
                .enumerate()
                .for_each(|(index, field)| {
                    let field_ident = field.ident.as_ref().unwrap_or(&stock_field_names[index]);
                    fields = quote! { #field_ident, #fields }
                });
            fields
        } else {
            quote! {}
        };

        match setting.kind {
            ContractKind::Append => branches.push(quote! {
                #permission_type::#variant_ident(#fields) => {
                    #set_name.insert(*#fields);
                }
            }),
            ContractKind::Drop => {
                // We are dropping the specific permission value
            }
            ContractKind::Extend => branches.push(quote! {
                #permission_type::#variant_ident(#fields) => {
                    #set_name.extend(#fields);
                }
            }),
        }
    }

    let collections = sets.values().filter_map(|v| v.as_ref()).collect::<Vec<_>>();

    // TODO: This should support arbitrary collection types as defined by the collecting variant.
    // This similarly has need for a global read only store of variants and their properties
    let collection_instantiation = quote! {
        #(let mut #collections = BTreeSet::new();)*
    };

    let collections_add = sets
        .into_iter()
        .fold(quote! {}, |tokens, (key, value)| match value {
            Some(value) => quote! {
                #tokens
                if !#value.is_empty() {
                    contracted.push(#permission_type::#key(#value));
                }
            },
            None => quote! { #tokens },
        });

    quote! {
        fn contract(collection: &v_model::Permissions<Self>) -> v_model::Permissions<Self> {
            let mut contracted = Vec::new();

            #collection_instantiation

            for p in collection.iter() {
                match p {
                    #(#branches,)*

                    // Add the remaining permissions as is
                    other => contracted.push(other.clone()),
                }
            }

            #collections_add

            contracted.into()
        }
    }
}

fn permission_storage_expand_tokens(
    permission_type: &Ident,
    expand_settings: Vec<(Variant, ExpandSettings)>,
) -> proc_macro2::TokenStream {
    let mut branches = vec![];

    for (variant, setting) in expand_settings {
        let variant_ident = variant.ident;

        branches.push(match setting.kind {
            ExpandKind::Alias => {
                let target_variant = setting.variant;
                let permission_source = setting.source.map(|source| {
                    match source {
                        ExternalSource::Actor => format_ident!("actor_permissions"),
                        ExternalSource::Extension => panic!("Extensions not yet supported"),
                    }
                }).expect("Alias expansions must always have a source defined");

                // TODO: Do not hardcode the target_variant fields. We need some kind of global
                // read only meta store for the item we are deriving impls for
                quote! {
                    #permission_type::#variant_ident => {
                        if let Some(#permission_source) = #permission_source {
                            expanded.extend(
                                #permission_source
                                    .iter()
                                    .filter(|op| match op {
                                        #permission_type::#target_variant(_) => true,
                                        _ => false
                                    })
                                    .cloned(),
                            );
                        }
                    }
                }
            }
            ExpandKind::Iter => {
                let target_variant = setting.variant;
                match (setting.source, setting.field) {
                    (Some(source), Some(field)) => {
                        let source = source.to_ident();
                        let field = field.to_ident();

                        quote! {
                            #permission_type::#variant_ident => {
                                for f0 in &#source.#field {
                                    expanded.push(#permission_type::#target_variant(*f0))
                                }
                            }
                        }
                    },
                    (Some(_), None) => panic!("Iter expansions must define field if a source is defined"),
                    (None, Some(_)) => panic!("Iter expansions must define a source if a field is defined"),
                    _ => {
                        quote! {
                            #permission_type::#variant_ident(field) => {
                                for f0 in field {
                                    expanded.push(#permission_type::#target_variant(*f0))
                                }
                            }
                        }
                    }
                }
            }
            ExpandKind::Replace => {
                let target_variant = setting.variant;
                match (setting.source, setting.field) {
                    (Some(source), Some(field)) => {
                        let field = field.to_ident();
                        match &source {
                            ExternalSource::Actor => {
                                let source = source.to_ident();
                                quote! {
                                    #permission_type::#variant_ident => expanded.push(#permission_type::#target_variant(#source.#field)),
                                }
                            },
                            ExternalSource::Extension => {
                                if let Some(ext) = setting.ext {
                                    let source = source.to_ident();
                                    let ext = format_ident!("{}", ext);
                                    quote! {
                                        #permission_type::#variant_ident => {
                                            if let Some(entry) = #source.get(&std::any::TypeId::of::<#ext>()) {
                                                use std::any::Any;
                                                let entry: Option<&#ext> = (**entry).downcast_ref();
                                                if let Some(entry) = entry {
                                                    expanded.push(#permission_type::#target_variant(entry.#field));
                                                }
                                            }
                                        },
                                    }
                                } else {
                                    panic!("Extension sources must specify an ext key to read from")
                                }
                            }
                        }
                    },
                    _ => panic!("Replace expansions must define a value source and field")
                }
            }
        });
    }

    quote! {
        fn expand(
            collection: &v_model::Permissions<Self>,
            actor: &v_model::ApiUser<Self>,
            actor_permissions: Option<&v_model::Permissions<Self>>,
            extensions: &v_model::ArcMap,
        ) -> v_model::Permissions<Self> {
            let mut expanded = Vec::new();

            for p in collection.iter() {
                match p {
                    #(#branches)*

                    other => expanded.push(other.clone()),
                }
            }

            expanded.into()
        }
    }
}
