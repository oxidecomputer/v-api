# v-api: REST API framework

## Cargo commands

- check: `cargo check --quiet --all-features --workspace --all-targets`
- test: `cargo test --quiet --all-features --workspace --all-targets`
- format: `cargo fmt`
- clippy: `cargo clippy --quiet --fix --allow-dirty --all-features --workspace --all-targets`

## Crates

- `v-api` - Dropshot endpoint, context, authentication, and authorization framework for the v-api service.
- `v-api-param` - Configuration parameter helpers for inline strings or file-backed secret values.
- `v-api-permission-derive` - Procedural macro for deriving v-api permission traits on application enums.
- `v-model` - Shared data models, Diesel schema, migrations, storage traits, and Postgres implementations.
- `xtask` - Workspace maintenance CLI for tasks such as bumping crate versions.
- `dropshot-authorization-header` - Dropshot extractors for Basic and Bearer Authorization headers.

## TypeScript packages

- `remix-auth-vapi` - Generic remix-auth (OAuth + magic link) strategies for v-api based services. Talks directly to v-api's generic endpoints (`/login/oauth/*`, `/login/magic/*`, `/self`). Run `npm test`/`npm run build` from within the package directory.
