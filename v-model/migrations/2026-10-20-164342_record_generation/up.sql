-- Add counters so that read then write updates can be performed without races
ALTER TABLE api_user ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE access_groups ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;
