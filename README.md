# v-api (very small API)

Boilerplate for building an API on top of [dropshot](https://github.com/oxidecomputer/dropshot).

### Why?

Writing user and access code can be tedious. It would be nice if you could inject a batch of
routes in to an existing [dropshot](https://github.com/oxidecomputer/dropshot) server and get an
API for handling users and access groups out.

### Integration

The crate assumes that the hosting application is using a Postgres database or can provide a
connection to one. Want a different backend? Please contribute, it will be gladly welcome.

The `v-model` crate contains [diesel](https://diesel.rs/) migrations for initializing the necessary
tables in a database. `v-model` exposes embedded migrations via [diesel_migrations](https://docs.rs/diesel_migrations/latest/diesel_migrations/).

To add the endpoints in to the hosting server:

1. Derive the `v_api` permission traits for your Permission enum. You can use the built-in macro:

```rust
use v_api::permissions::VPermission;
use v_api_permission_derive::v_api;

#[v_api(From(VPermision))]
pub enum MyPermission {
  // ...
}
```

Or implement the `VAppPermission` trait yourself:

```rust
pub trait VAppPermission: Permission + From<VPermission> + AsScope + PermissionStorage {}
```

2. Implement the `ApiContext` trait for your server context. This trait is how you communicate to
`v-api` where your `VContext` struct can be located.

```rust
impl ApiContext for MyContext {
    type AppPermissions = MyPermission;
    fn v_ctx(&self) -> &VContext<Self::AppPermissions> {
        &self.v_context
    }
}
```

3. Use the injection macros to register the `v-api` endpoints. Note that these must both be used
within the same file.

```rust
use v_api::{inject_endpoints, v_system_endpoints};

let context = MyContext::new();
v_system_endpoints!(context);

/// ...

let mut api = ApiDescription::new().tag_config(/** ... **/);
inject_endpoints!(api);
```

### Endpoints

The following endpoints are injected by the `inject_endpoints` macro:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /oauth/client | View all OAuth clients |
| POST | /oauth/client | Create a new OAuth client |
| GET | /oauth/client/{client_id} | View an individual OAuth client |
| POST | /oauth/client/{client_id}/secret | Create a new secret for an OAuth client |
| DELETE | /oauth/client/{client_id}/secret/{secret_id} | Delete an existing secret from an OAuth client |
| POST | /oauth/client/{client_id}/redirect_uri | Add a redirect URI to an OAuth client |
| DELETE | /oauth/client/{client_id}/redirect_uri/{redirect_uri_id} | Delete an existing redirect URI from an OAuth client |
| GET | /magic/client | View all magic link clients |
| POST | /magic/client | Create a new magic link client |
| GET | /magic/client/{client_id} | View an individual magic link client |
| POST | /magic/client/{client_id}/secret | Create a new secret for a magic link client |
| DELETE | /magic/client/{client_id}/secret/{secret_id} | Delete an existing secret from a magic link client |
| POST | /magic/client/{client_id}/redirect_uri | Add a redirect URI to a magic link client |
| DELETE | /magic/client/{client_id}/redirect_uri/{redirect_uri_id} | Delete an existing redirect URI from a magic link client |
| GET | /login/oauth/{provider}/code/authorize | Start an OAuth authorization_code flow |
| GET | /login/oauth/{provider}/code/callback | Internal url for handling return calls from external OAuth providers |
| POST | /login/oauth/{provider}/code/token | Complete an authorization_code flow by exchanging an authorization code for an access token |
| GET | /login/oauth/{provider}/public-pkce | Retrieve provider metadata for a public PKCE authorization_code flow |
| GET | /login/oauth/{provider}/device | Retrieve provider metadata for a device_code flow |
| POST | /login/oauth/{provider}/device | Start an OAuth device_code flow |
| POST | /login/oauth/{provider}/device/exchange | Complete a device_code flow by exchanging a device code for an access token |
| POST | /login/magic/{channel}/send | Send a magic link to a recipient |
| POST | /login/magic/{channel}/exchange | Complete a magic link login by exchanging an access code for an access token |
| GET | /.well-known/openid-configuration | Retrieve OpenID configuration information. Specifically the jwks url |
| GET | /.well-known/jwks.json | Retrieve JWKS for verifying access tokens |
| GET | /self | View information about the calling user |
| GET | /api-user | View all users |
| POST | /api-user | Create a new user |
| GET | /api-user/{user_id} | View information about a specific user |
| POST | /api-user/{user_id} | Replace the permissions assigned to an existing user |
| GET | /api-user/{user_id}/session | View the existing sessions for a user |
| POST | /api-user/{user_id}/logout | Revoke all existing sessions for a user |
| POST | /api-user/{user_id}/permission | Add a single permission to an existing user |
| DELETE | /api-user/{user_id}/permission | Remove a single permission from an existing user |
| GET | /api-user/{user_id}/token | View all API tokens for an existing user |
| POST | /api-user/{user_id}/token | Create a new API token for an existing user |
| GET | /api-user/{user_id}/token/{api_key_id} | View an existing API token |
| DELETE | /api-user/{user_id}/token/{api_key_id} | Revoke an existing API token |
| PUT | /api-user/{user_id}/contact/email | Set the contact email for an existing user |
| POST | /api-user/{user_id}/group | Add an existing user to a group |
| DELETE | /api-user/{user_id}/group/{group_id} | Remove an existing user from a group |
| POST | /api-user/{user_id}/link | Link an existing login provider to an existing user |
| POST | /api-user-provider/{provider_id}/link-token | Create a token for linking a login provider to a different user |
| GET | /group | View all groups |
| POST | /group | Create a new group |
| PUT | /group/{group_id} | Update an existing group |
| DELETE | /group/{group_id} | Delete an existing group |
| GET | /group-membership/{group_id} | View the members of a group |
| GET | /mapper | View all mappers |
| POST | /mapper | Create a new mapper |
| DELETE | /mapper/{mapper_id} | Delete an existing mapper |

When the `local-dev` feature is enabled `inject_endpoints` also injects:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /login/local | Login as a local development user |

The `inject_v_saga_endpoints` macro, available with the `sagas` feature (enabled by default),
injects:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /saga | View all sagas |
| GET | /saga/{saga} | View a saga along with its events |

The `inject_v_metrics_endpoints` macro, available with the `metrics` feature, injects:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v/metrics | Report service metrics in the Prometheus exposition format |

## Contributing

We're open to PRs that improve these services, especially if they make the repo easier for others
to use and contribute to. However, we are a small company, and the primary goal of this repo is as
an internal tool for Oxide, so we can't guarantee that PRs will be integrated.

## License

Unless otherwise noted, all components are licensed under the
[Mozilla Public License Version 2.0](LICENSE).
