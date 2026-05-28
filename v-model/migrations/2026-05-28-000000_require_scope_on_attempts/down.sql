ALTER TABLE magic_link_attempt ALTER COLUMN scope DROP NOT NULL;
ALTER TABLE magic_link_attempt ALTER COLUMN scope DROP DEFAULT;
