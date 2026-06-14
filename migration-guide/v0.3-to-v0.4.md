# Migrating from v-api v0.3.0 to v0.4.0

This guide covers all breaking changes and new features introduced between v0.3.0 and
v0.4.0 of the v-api framework. Work through each section in order — later sections may
depend on earlier ones.

---

## Table of Contents

1. [Database Migrations](#1-database-migrations)
2. [Migration System Restructure (`v-api-installer` Removed)](#2-migration-system-restructure)
3. [Permission Implication](#3-permission-implication)
4. [OAuth Rework](#4-oauth-rework)
5. [API Key and Scope Refactoring](#5-api-key-and-scope-refactoring)
6. [Preset Mappers](#6-preset-mappers)
7. [v-cli-sdk Introduction](#7-v-cli-sdk-introduction)
8. [Other Breaking Changes](#8-other-breaking-changes)

---

## 1. Database Migrations

Four new migrations must be applied **in order** before deploying v0.4.0. If you use
`run_migrations()` (see section 2), they run automatically. Otherwise apply them manually.

| Migration | Table | Description |
|---|---|---|
| `2026-05-16-000000_add_device_code_fields` | `login_attempt` | Adds `grant_type` (VARCHAR NOT NULL, default `'authorization_code'`), `device_code` (nullable), and `provider_device_code` (nullable). |
| `2026-05-17-000000_nullable_login_attempt_redirect_uri` | `login_attempt` | Makes `redirect_uri` nullable (device flows have no redirect). |
| `2026-05-18-150000_mapper_event` | `mapper_event` (**new**) | Creates the mapper event audit table with columns `id`, `mapper_id`, `mapper_name`, `user_id`, `rule`, `source`, `created_at`. |
| `2026-05-28-000000_require_scope_on_attempts` | `magic_link_attempt` | Backfills NULL `scope` values to `''`, adds a default, and sets `NOT NULL`. |

If you use the **sagas** feature, a new saga migration is also included at
`v-model/src/saga/migrations/2026-05-19-172630_sagas/` (creates `sagas` and `saga_events`
tables). This was missing in v0.3.0 and is now applied automatically.

---

## 2. Migration System Restructure

The `v-api-installer` crate has been **removed**. Its responsibilities are now handled
by `v-model` directly.

### What to change

**`Cargo.toml`** — remove the `v-api-installer` dependency:

```diff
- v-api-installer = { ... }
```

**Imports** — update your migration call site:

```diff
- use v_api_installer::run_migrations;
+ use v_model::migrations::run_migrations;
```

The function signature is identical: `run_migrations(url: &str)`.

You should now call `v_model::migrations::run_migrations()` from your
application's startup code in place of `v_api_installer::migrations::run_migrations()`

### Feature-gated migrations

Migrations are now organized by feature. Core migrations live in `v-model/migrations/`.
Feature-specific migrations (e.g. sagas) live in `v-model/src/<feature>/migrations/` and
are only applied when the corresponding Cargo feature is enabled. `run_migrations()`
handles this automatically.

---

## 3. Permission Implication

v0.3.0 used **strict equality** for permission checks. Holding `GetApiUsersAll` did _not_
automatically satisfy a check for `GetApiUser(id)` — every call site had to check both
explicitly. v0.4.0 introduces **permission implication**: a formal hierarchy where holding
a broader permission automatically satisfies checks for narrower ones.

### 3.1 New `implies` method on `PermissionStorage`

`PermissionStorage` now has a required method:

```rust
pub trait PermissionStorage {
    fn contract(...) -> ...;
    fn expand(...) -> ...;
    fn implies(held: &Self, target: &Self) -> bool; // NEW — required
}
```

If you implement `PermissionStorage` manually, you must add this method:

```rust
fn implies(held: &Self, target: &Self) -> bool {
    if held == target { return true; }
    match (held, target) {
        (Self::AdminAll, _) => true,
        (Self::ReadItems(set), Self::ReadItem(id)) => set.contains(id),
        _ => false,
    }
}
```

### 3.2 New derive macro attribute: `#[v_api(implies(variant = ...))]`

If you use the `v_api` derive macro, permission implication for built-in permissions are
pre-defined. Using the `implies` annotations for your own permission variants is optional.

```diff
+ #[v_api(
+     implies(variant = GetWidget),
+     implies(variant = GetWidgets),
+     implies(variant = GetWidgetsAssigned),
+     scope(to = "widget:r", from = "widget:r")
+ )]
  GetWidgetsAll,
```

The macro generates the `implies()` implementation automatically. For variants annotated
with `expand(kind = iter)`, set-containment logic is also generated (e.g.
`ManageGroups({a,b,c})` implies `ManageGroup(a)`).

### 3.3 Simplify authorization checks

For built-in permissions (or any permissions you define implication for) you can replace
`caller.any(...)` disjunctions with a single `caller.can(...)`:

```diff
- if caller.any(&mut [
-     VPermission::GetApiUser(*id).into(),
-     VPermission::GetApiUsersAll.into(),
- ].iter()) { ... }
+ if caller.can(&VPermission::GetApiUser(*id).into()) { ... }
```

### 3.4 Privilege escalation guards

Permission-granting operations now verify that the caller holds every permission they are
trying to assign. This includes both direct permission grants to a user or group as well as
transitive grants via group assignment. New helper methods:

```rust
// On Permissions<T> and Caller<T>:
fn can_grant(&self, target: &T) -> bool;
fn can_grant_all(&self, targets: &Permissions<T>) -> bool;
```

If you have custom endpoints that grant permissions or group memberships, add
`can_grant_all` checks:

```rust
if caller.can(&VPermission::ManageApiUser(*user_id).into())
    && caller.can_grant_all(&new_permissions)
{
    // proceed
}
```

This means that the registration user must be assigned all of the permissions that it will
eventually assign to users and groups. It is recommended to pass this full permission set to
`AuthContext::new`.

### 3.5 API changes for user and group management

| v0.3.0 | v0.4.0 | Notes |
|---|---|---|
| `ctx.user.update_api_user(&caller, new_api_user)` | `ctx.user.set_api_user_permissions(&caller, &user_id, permissions)` | Group membership now managed separately. |
| `ctx.group.get_groups(&caller)` | `ctx.group.list_groups(&caller, AccessGroupFilter::default())` | Now accepts a filter. |
| `ctx.user.create_api_user(&caller, perms, BTreeSet<AccessGroupId>)` | `ctx.user.create_api_user(&caller, perms, Vec<AccessGroup<T>>)` | Takes resolved group objects for permission verification. |

New endpoints:

| Method | Path | Description |
|---|---|---|
| `POST` | `/api-user/{user_id}/permission` | Add a single permission to a user. |
| `DELETE` | `/api-user/{user_id}/permission` | Remove a single permission from a user. |

---

## 4. OAuth Rework

This is the largest change in v0.4.0 and affects the OAuth provider trait, configuration,
data models, and endpoint signatures.

### 4.1 Module reorganization

Provider and flow implementations have been split into separate submodules:

| v0.3.0 path | v0.4.0 path |
|---|---|
| `endpoints/login/oauth/code.rs` | `endpoints/login/oauth/flow/code.rs` |
| `endpoints/login/oauth/device_token.rs` | `endpoints/login/oauth/flow/device_token.rs` |
| `endpoints/login/oauth/github.rs` | `endpoints/login/oauth/remote/github.rs` |
| `endpoints/login/oauth/google.rs` | `endpoints/login/oauth/remote/google.rs` |

Update your imports accordingly.

### 4.2 `OAuthProvider` trait overhaul

Many methods were removed and replaced with structured info accessors:

**Removed methods:** `scopes()`, `client_id()`, `client_secret()`, `device_code_endpoint()`,
`auth_url_endpoint()`, `token_exchange_content_type()`, `token_exchange_endpoint()`,
`token_revocation_endpoint()`, `provider_info()`.

**New methods:**

```rust
fn authz_code_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodeInfo>;
fn authz_code_pkce_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodePkceInfo>;
fn device_code_flow_info(&self) -> Option<&OAuthProviderDeviceInfo>;
fn expires_in(&self) -> Option<u64>;
fn default_scopes(&self) -> &[String];  // replaces scopes() -> Vec<&str>
```

**Changed signatures:**

```diff
- fn as_web_client(&self, config: &WebClientConfig) -> Result<WebClient, ParseError>;
+ fn as_web_client(&self) -> Result<WebClient, OAuthProviderError>;
```

If you implement a custom `OAuthProvider`, replace the removed method implementations
with the new structured info methods. Providers now take `ResolvedOAuthConfig` and a
`public_url: String` at construction instead of individual client ID/secret strings.

### 4.3 PKCE is now mandatory

All authorization code flows require PKCE. Two new required fields on `OAuthAuthzCodeQuery`:

```rust
pub struct OAuthAuthzCodeQuery {
    // ... existing fields ...
    pub code_challenge: String,          // NEW — required
    pub code_challenge_method: String,   // NEW — must be "S256"
}
```

`OAuthAuthzCodeExchangeBody.pkce_verifier` changed from `Option<String>` to `String`.

### 4.4 Device code flow is now proxied

v-api now initiates upstream device authorization itself and issues its own device codes.
New endpoints:

| Method | Path | Handler |
|---|---|---|
| `GET` | `/login/oauth/{provider}/public-pkce` | Returns PKCE provider metadata. |
| `POST` | `/login/oauth/{provider}/device` | Initiates device authorization flow. |

`AccessTokenExchangeRequest` was renamed to `DeviceTokenExchangeRequest` with a new
`client_id` field and the `expires_at` field removed.

### 4.5 Configuration changes

OAuth provider configs were restructured. For `web` clients this is a change to clarify the intent
of the parameters. For `device` clients, the new internal client id is required to support proxying
of device flows. All sub-configs (`device`, `web`) are now **optional**, and credential fields were
renamed:

```toml
# v0.3.0
[oauth.github.device]
client_id = "github-app-client-id"
client_secret = "github-app-client-secret"

[oauth.github.web]
client_id = "github-app-client-id"
client_secret = "github-app-client-secret"
redirect_uri = "https://myapp.example.com/callback"

# v0.4.0
[oauth.github.device]                    # OPTIONAL
client_id = "<v-api OAuthClient UUID>"   # Internal v-api client ID (TypedUuid)
remote_client_id = "github-app-client-id"
remote_client_secret = "github-app-client-secret"

[oauth.github.web]                       # OPTIONAL
remote_client_id = "github-app-client-id"
remote_client_secret = "github-app-client-secret"
# redirect_uri REMOVED (now derived from public_url)

[oauth.github.proxy_web]                 # NEW — for PKCE-only public clients
client_id = "<v-api OAuthClient UUID>"
redirect_uri = "http://localhost:PORT/callback"
proxy_port = 8910
```

A new **Zendesk** provider is also available.

### 4.6 Data model changes

**`OAuthAuthzCodeExchangeResponse`** — new fields:

```rust
pub struct OAuthAuthzCodeExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,              // NEW
    pub idp_token: Option<String>,  // NEW — upstream provider's access token
}
```

**`UserInfo`** — new field, no longer `Serialize`:

```rust
pub struct UserInfo {
    pub external_id: ExternalUserId,
    pub verified_emails: Vec<String>,
    pub display_name: Option<String>,
    pub idp_token: Option<SecretString>,  // NEW
}
```

**`LoginAttempt`** — `redirect_uri` is now `Option<String>`, new fields added:

```rust
pub redirect_uri: Option<String>,      // was String
pub grant_type: String,                // NEW
pub device_code: Option<String>,       // NEW
pub provider_device_code: Option<String>, // NEW
```

**`LoginAttempt::callback_url()`** return type changed:

```diff
- pub fn callback_url(&self) -> String
+ pub fn callback_url(&self) -> Result<Option<String>, url::ParseError>
```

This ensures that the `callback_url` is a well-formed url.

**`NewLoginAttempt::new()`** — new parameter, `redirect_uri` is now optional:

```diff
- pub fn new(provider, client_id, redirect_uri: String, scope) -> Result<Self, InvalidValueError>
+ pub fn new(provider, client_id, redirect_uri: Option<String>, scope, grant_type: String) -> Result<Self, InvalidValueError>
```

### 4.7 Context method changes

| v0.3.0 | v0.4.0 |
|---|---|
| `AuthContext::new(jwt, jwks, signers, verifiers)` | `AuthContext::new(jwt, jwks, signers, verifiers, registration_caller_additional_permissions: Vec<T>)` |
| `OAuthContext::create_oauth_client(&self, caller)` | `OAuthContext::create_oauth_client(&self, caller, id: TypedUuid<OAuthClientId>)` |
| `LoginContext::complete_login_attempt(&self, attempt)` | `LoginContext::claim_login_attempt(&self, attempt)` (renamed) |
| `LoginContext::fail_login_attempt(&self, attempt, error, provider_error)` | `LoginContext::fail_login_attempt(&self, attempt, expected_state: LoginAttemptState, error, provider_error)` |
| `LoginContext::get_login_attempt_for_code(&self, code)` | `LoginContext::get_login_attempt_for_code(&self, code, provider: &str)` |
| All `OAuthContext` methods return `StoreError` | All return `OAuthError` |

### 4.8 New enum variants

| Enum | New variant |
|---|---|
| `OAuthProviderName` | `Zendesk` |
| `ExternalUserId` | `Zendesk(String)` |
| `ClientType` | `WebPkce` |
| `VPermission` | `RetrieveRemoteAccessToken` |

---

## 5. API Key and Scope Refactoring

### 5.1 `permissions` → `permission_boundary` rename

The `permissions` field on API key types was renamed to `permission_boundary` to clarify
that it acts as an upper bound on what the key can do, not a direct grant.

Affected types: `ApiKey`, `ApiKeyModel`, `ApiKeyCreateParams`, `InitialApiKeyResponse`,
`ApiKeyResponse`.

**The database column name remains `permissions`** — the rename is Rust/JSON only. Update
your API request and response handling:

```diff
// JSON bodies
- { "permissions": [...] }
+ { "permission_boundary": [...] }
```

### 5.2 Default scope removed

In v0.3.0, omitting the `scope` parameter from an OAuth or magic link login silently
assigned `"user:info:r"`. In v0.4.0, **omitting scope yields zero permissions**.

If your clients relied on this default, explicitly pass the scope:

```
scope=user:info:r
```

### 5.3 `"full"` scope introduced

A new reserved scope value `"full"` means "all permissions" (`BasePermissions::Full`).
This replaces the old behavior where `None`/null scope meant full access.

| v0.3.0 | v0.4.0 |
|---|---|
| `scope: null` → full permissions | `scope: "full"` → full permissions |
| `scope: null` → full permissions | `scope: ""` → zero permissions |
| `scope: "user:info:r"` → specific | `scope: "user:info:r"` → specific (unchanged) |

**`"full"` cannot be combined with other scopes.** Sending `scope=full user:info:r` is
rejected with `PermissionError::FullScopeMustBeExclusive`.

### 5.4 JWT `scp` claim wire format change

**This is a wire-level breaking change.** The JWT `scp` claim changed from a JSON array
to a space-delimited string per [RFC 9068 §2.2.2](https://www.rfc-editor.org/rfc/rfc9068#section-2.2.2):

| | v0.3.0 | v0.4.0 |
|---|---|---|
| Rust type | `Option<Vec<String>>` | `Vec<String>` |
| Wire format | `null` or `["a","b"]` | `""` or `"a b"` or `"full"` |
| No permissions | `scp: null` | `scp: ""` |
| All permissions | `scp: null` | `scp: "full"` |

**Existing JWTs from v0.3.0 will fail to deserialize.** Users must re-authenticate after
upgrading.

### 5.5 `Claims::new` signature change

```diff
- pub fn new(..., scope: Option<Vec<String>>, ...) -> Self
+ pub fn new(..., scope: Vec<String>, ...) -> Self
```

Replace `None` with `vec!["full".to_string()]` for full access, or `vec![]` for no
permissions. Replace `Some(scopes)` with `scopes`.

### 5.6 `MagicLinkAttempt.scope` is now required

```diff
// Model
- pub scope: Option<String>
+ pub scope: String

// Function signature
- send_magic_link_attempt(..., scope: Option<&str>)
+ send_magic_link_attempt(..., scope: &str)
```

Pass `""` instead of `None` for no specific scope.

---

## 6. Preset Mappers

Preset mappers are a new type of mapper that lives **in memory** instead of the database.
They are defined at server startup and are ideal for bootstrapping (e.g. creating an
initial admin user on first login without database seeding).

### 6.1 Using preset mappers

```rust
use v_api::{VContextBuilder, PresetMapperConfig};
use serde_json::json;

let ctx = VContextBuilder::new()
    // ... existing config ...
    .with_mappers(vec![
        PresetMapperConfig {
            name: "bootstrap-admin".to_string(),
            rule: json!({
                "email": "admin@example.com",
                "groups": ["<admin-group-uuid>"]
            }),
        },
    ])
    .build()
    .await?;
```

Preset mapper IDs are deterministic (UUID v5 from the name), so they are stable across
restarts. They cannot be deleted via the API (returns `409 CONFLICT`). To remove one,
stop passing it to `with_mappers()`.

### 6.2 Breaking changes from preset mappers

**`VApiStorage` now requires `MapperEventStore`.** If you have a custom storage backend,
implement the new trait:

```rust
#[async_trait]
pub trait MapperEventStore {
    async fn record(&self, event: &NewMapperEvent) -> Result<MapperEvent, StoreError>;
    async fn list(
        &self,
        filter: MapperEventFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<MapperEvent>, StoreError>;
}
```

`PostgresStore` already implements this.

**`Mapper` struct has a new `source` field:**

```rust
pub struct Mapper {
    // ... existing fields ...
    pub source: MapperSource,  // Dynamic | Preset
}
```

Update any code that constructs or destructures `Mapper` directly.

**`MappingContext::get_mapped_fields()` has a new `user_id` parameter:**

```diff
- pub async fn get_mapped_fields(&self, caller, info) -> ...
+ pub async fn get_mapped_fields(&self, caller, info, user_id: TypedUuid<UserId>) -> ...
```

---

## 7. v-cli-sdk Introduction

A new `v-cli-sdk` crate provides reusable [clap](https://docs.rs/clap) commands and
supporting infrastructure for building CLI clients against a v-api service.

### What it provides

| Module | Purpose |
|---|---|
| `cmd::auth` | Prebuilt `auth login` subcommands for OAuth (device + PKCE code flows) and magic link. |
| `cmd::config` | `config get/set` subcommands for managing CLI configuration (host, token, format). |
| `printer` | JSON and tab-formatted output with styled error handling. |
| `err` | Error formatting for `progenitor_client::Error` responses. |

### Key traits to implement

| Trait | Purpose |
|---|---|
| `VCliContext<C, P>` | Central context — provides config, API client, printer, and adapter factories. |
| `CliOAuthAdapter` | Wire up provider discovery and code exchange to your generated API client. |
| `CliMagicLinkAdapter` | Wire up magic-link attempt creation and secret exchange. |
| `VCliConfig` | Persistent CLI configuration (host, token, format, etc.). |

### Adopting v-cli-sdk

1. Define a provider enum implementing `Into<LoginProvider> + Subcommand`.
2. Implement `VCliContext`, `CliOAuthAdapter`, and optionally `CliMagicLinkAdapter`.
3. Embed `Auth<MyProviders>` and `ConfigCmd` as clap subcommands.
4. Use `Printer` and `format_api_err` for consistent output.

This crate is additive — it does not require changes to your server code.

---

## 8. Other Breaking Changes

### 8.1 Saga feature gating

The `GetSagasAll` and `ManageSagasAll` permission variants are now conditionally compiled
behind `cfg!(feature = "sagas")`. If you reference these variants, ensure the `sagas`
feature is enabled on both `v-api` and `v-api-permission-derive`.

### 8.2 `uuid` v5 support

`v-api` now depends on `uuid` with the `"v5"` feature (for deterministic preset mapper
IDs). If you pin `uuid` features separately, add `"v5"` to your feature list.

### 8.3 `diesel_migrations` promotion

`diesel_migrations` is now a regular dependency of `v-model` (was a dev-dependency). If
you were pinning it separately, you can remove your pin.

### 8.4 `percent-encoding` removed

The `percent-encoding` dependency was removed from `v-api`. If you were relying on it
transitively, add it as a direct dependency.
