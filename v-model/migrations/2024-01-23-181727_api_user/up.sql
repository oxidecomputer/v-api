CREATE TABLE api_user (
  id UUID PRIMARY KEY,
  permissions JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);
SELECT diesel_manage_updated_at('api_user');

CREATE TABLE api_key (
  id UUID PRIMARY KEY,
  api_user_id UUID REFERENCES api_user (id) NOT NULL,
  key_signature TEXT NOT NULL UNIQUE,
  permissions JSONB,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);
SELECT diesel_manage_updated_at('api_key');

CREATE TABLE api_user_provider (
  id UUID PRIMARY KEY,
  api_user_id UUID REFERENCES api_user (id) NOT NULL,
  provider VARCHAR NOT NULL,
  provider_id VARCHAR NOT NULL,
  emails TEXT[] NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);
SELECT diesel_manage_updated_at('api_user_provider');

CREATE UNIQUE INDEX api_user_provider_idx ON api_user_provider (provider, provider_id);

CREATE TABLE api_user_access_token (
  id UUID PRIMARY KEY,
  api_user_id UUID REFERENCES api_user (id) NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT diesel_manage_updated_at('api_user_access_token');
