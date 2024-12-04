ALTER TABLE magic_link_attempt ALTER COLUMN scope SET DEFAULT '';
ALTER TABLE magic_link_attempt ALTER COLUMN scope SET NOT NULL;
