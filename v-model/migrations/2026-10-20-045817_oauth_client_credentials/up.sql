-- The permissions an OAuth client holds when it acts as a service account through client
-- credentials. The id is the id of the client. A client without a row holds no permissions, so a
-- row is only written once a permission is first granted. The generation is incremented by every
-- write, and permission changes are only written when it still matches the value that was read.
CREATE TABLE service_account(
  id UUID PRIMARY KEY REFERENCES oauth_client (id),
  permissions JSONB NOT NULL,
  generation BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT diesel_manage_updated_at('service_account');

-- Access tokens issued to OAuth clients acting as service accounts. They are kept apart from the
-- access tokens issued to users so that a token can only ever be resolved to the kind of
-- principal it was issued for.
CREATE TABLE service_account_token(
  id UUID PRIMARY KEY,
  oauth_client_id UUID REFERENCES oauth_client (id) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT diesel_manage_updated_at('service_account_token');

CREATE INDEX service_account_token_oauth_client_id ON service_account_token (oauth_client_id);

-- Public keys for verifying client assertions with. The thumbprint is unique across every row,
-- including deleted ones. Once registered a key can never be used by another client, even it
-- has been removed.
CREATE TABLE oauth_client_key(
  id UUID PRIMARY KEY,
  oauth_client_id UUID REFERENCES oauth_client (id) NOT NULL,
  thumbprint VARCHAR NOT NULL UNIQUE,
  jwk JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);

-- Assertions that have been accepted. We keep assertions until their expiration has passed to
-- ensure they can not be replayed.
CREATE TABLE oauth_client_assertion(
  oauth_client_id UUID REFERENCES oauth_client (id) NOT NULL,
  jti VARCHAR NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (oauth_client_id, jti)
);

CREATE INDEX oauth_client_assertion_expires_at ON oauth_client_assertion (expires_at);
