-- The service user that a client acts as when it authenticates with client credentials. NULL means
-- client credentials are not enabled for the client. A client has exactly one user at most.
ALTER TABLE oauth_client ADD COLUMN api_user_id UUID UNIQUE REFERENCES api_user (id);

-- Public keys a client signs its assertions with. The thumbprint is unique across every row,
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
