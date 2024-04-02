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
tables in a database. `v-model-installer` exposes embedded migrations via [diesel_migrations](https://docs.rs/diesel_migrations/latest/diesel_migrations/).

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
| GET | /oauth/client | Vliew all OAuth clients |
| POST | /oauth/client | Create a new OAuth client |
| GET | /oauth/client/{client_id} | View an individual OAuth client |
| POST | /oauth/client/{client_id}/secret | Create a new secret for an OAuth client |
| DELETE | /oauth/client/{client_id}/secret/{secret_id} | Delete an existing secret from an OAuth client |
| POST | /oauth/client/{client_id}/redirect_uri | Add a redirect URI to an OAuth cleint |
| DELETE | /oauth/client/{client_id}/redirect_uri/{redirect_uri_id} | Delete an existing redirect URI from an OAuth client |
| GET | /login/oauth/{provider}/code/authorize | Start an OAuth authorization_code flow |
| GET | /login/oauth/{provider}/code/callback | Internal url for handling return calls from external OAuth providers |
| POST | /login/oauth/{provider}/code/token | Complete an authorization_code flow by exchanging an authorization code for an access token |
| GET | /login/oauth/{provider}/device | Start an OAuth device_code flow |
| POST | /login/oauth/{provider}/device/exchange | Complete a device_code flow by exchanging a request for an access token |
| GET | /.well-known/openid-configuration | Retrive OpenID configuartion information. Specifically the jwks url |
| GET | /.well-known/jwks.json | Retrieve JWKS for verifying access tokens |
| GET | /self | View information about the calling user |
| GET | /api-user/{identifier} | View information about a specific user |
| POST | /api-user | Create a new user |
| POST | /api-user/{identifier} | Update information on an existing user |
| GET | /api-user/{identifier}/token | View all API tokens for an existing user |
| POST | /api-user/{identifier}/token | Create a new API token for an existing user |
| GET | /api-user/{identifier}/token/{token_identifier} | View an existing API token |
| DELETE | /api-user/{identifier}/token/{token_identifier} | Delete an existing API token |
| POST | /api-user/{identifier}/group | Add an existing user to a group |
| DELETE | /api-user/{identifier}/group/{group_id} | Remove an existing user from a group |
| POST | /api-user/{identifier}/link | TBD |
| POST | /api-user-provider/{identifier}/link-token | TBD |
| GET | /group | View all groups |
| POST | /group | Create a new group |
| PUT | /group/{group_id} | Update an existing group |
| DELETE | /group/{group_id} | Delete an existing group |
| GET | /mapper | View all mappers |
| POST | /mapper | Create a new mapper |
| DELETE | /mapper/{identifier} | Delete and existing mapper |

## Contributing

We're open to PRs that improve these services, especially if they make the repo easier for others
to use and contribute to. However, we are a small company, and the primary goal of this repo is as
an internal tool for Oxide, so we can't guarantee that PRs will be integrated.

## License

Unless otherwise noted, all components are licensed under the
[Mozilla Public License Version 2.0](LICENSE).