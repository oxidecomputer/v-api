CREATE TABLE api_user_contact_email (
  id UUID PRIMARY KEY,
  api_user_id UUID REFERENCES api_user (id) NOT NULL,
  email VARCHAR NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);
SELECT diesel_manage_updated_at('api_user_contact_email');

CREATE UNIQUE INDEX api_user_idx ON api_user_contact_email (api_user_id);
