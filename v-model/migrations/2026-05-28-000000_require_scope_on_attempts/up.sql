UPDATE magic_link_attempt SET scope = '' WHERE scope IS NULL;
ALTER TABLE magic_link_attempt ALTER COLUMN scope SET DEFAULT '';
ALTER TABLE magic_link_attempt ALTER COLUMN scope SET NOT NULL;
