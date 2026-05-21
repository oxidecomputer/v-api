CREATE TABLE mapper_event (
  id UUID PRIMARY KEY,
  mapper_id UUID NOT NULL,
  mapper_name VARCHAR NOT NULL,
  user_id UUID NOT NULL,
  rule JSONB NOT NULL,
<<<<<<< HEAD
  ephemeral BOOLEAN NOT NULL DEFAULT false,
=======
>>>>>>> main
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
