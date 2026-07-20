# @oxide/remix-auth-vapi

Generic [remix-auth](https://github.com/sergiodxa/remix-auth) strategies for any
[v-api](https://github.com/oxidecomputer/v-api) based service.

Talks to the HTTP endpoints every v-api service exposes:

- `POST /login/magic/{channel}/send`
- `POST /login/magic/{channel}/exchange`
- `GET /login/oauth/{provider}/code/authorize` and `POST .../code/token` (via `remix-auth-oauth2`)
- `GET /self`

## Usage

```ts
import { VApiOAuthStrategy, VApiMagicLinkStrategy, getSelf } from '@oxide/remix-auth-vapi'
import type { GetUserResponse } from '@oxide/remix-auth-vapi'

const oauth = new VApiOAuthStrategy(
  {
    host: process.env.MY_SERVICE_HOST!,
    clientId: process.env.MY_SERVICE_CLIENT_ID!,
    clientSecret: process.env.MY_SERVICE_CLIENT_SECRET!,
    redirectURI: process.env.MY_SERVICE_REDIRECT_URL!,
    remoteProvider: 'google',
    scopes: ['user:info:r', 'group:info:r'],
  },
  async ({ tokens }) => {
    const user = await getSelf(process.env.MY_SERVICE_HOST!, tokens.accessToken())
    return toAppUser(user)
  },
)
```

`Permission` and `Scope` are generic type parameters on the strategies/helpers — pass
your service's own permission/scope string unions for full type safety, e.g.
`getSelf<MyServicePermission>(host, token)`.

### Preserving strategy names

Both strategies accept an optional `name`. If your app already hardcodes strategy
names elsewhere (e.g. `authenticator.authenticate('turnstile-google', request)`),
pass the existing name explicitly to avoid touching those call sites:

```ts
new VApiOAuthStrategy({ ..., name: 'turnstile-google' }, verify)
```

Otherwise strategies default to `v-api-{provider}` (OAuth) and `v-api-magic-link`
(magic link).
