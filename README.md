# v-api (very small API)

Boilerplate for building an API on top of [dropshot](https://github.com/oxidecomputer/dropshot).

### Why?

Writing user and access code can be tedious. It would be nice if you could inject a batch of
routes in to an existing [dropshot](https://github.com/oxidecomputer/dropshot) server and get an
API for handling users and access groups out.

### Integration

The crate assumes that the hosting application is using a Postgres database or can provide a
connection to one.

The `v-model` crate contains [diesel](https://diesel.rs/) migrations for initializing the necessary
tables in a database.

To add the endpoints in to the hosting server:

1. Implement a the `From` trait for converting between `v-api` permissions and your permissions. If
you do not implement your own permission data, then the `ApiPermission` enum can be used directly.

```rust
pub enum MyPermission {
  // ...
}

impl From<ApiPermission> for MyPermission {
    fn from(value: ApiPermission) -> Self {
        // ...
    }
}
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

### Usage