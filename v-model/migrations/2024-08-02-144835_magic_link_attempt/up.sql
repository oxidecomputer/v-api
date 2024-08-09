CREATE TYPE MLINK_ATTEMPT_STATE as ENUM('sent', 'failed', 'complete');

CREATE TABLE magic_link_attempt(
  id UUID PRIMARY KEY,
  attempt_state MLINK_ATTEMPT_STATE NOT NULL,
  magic_link_client_id UUID REFERENCES magic_link_client (id) NOT NULL,

  medium VARCHAR NOT NULL,
  recipient VARCHAR NOT NULL,
  redirect_uri VARCHAR NOT NULL,
  scope VARCHAR NOT NULL DEFAULT '',

  nonce_signature VARCHAR NOT NULL,
  expiration TIMESTAMPTZ NOT NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
