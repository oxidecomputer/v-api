UPDATE login_attempt SET scope = '' WHERE scope IS NULL;
ALTER TABLE login_attempt ALTER COLUMN scope SET DEFAULT '';
ALTER TABLE login_attempt ALTER COLUMN scope SET NOT NULL;

UPDATE magic_link_attempt SET scope = '' WHERE scope IS NULL;
ALTER TABLE magic_link_attempt ALTER COLUMN scope SET DEFAULT '';
ALTER TABLE magic_link_attempt ALTER COLUMN scope SET NOT NULL;
