UPDATE login_attempt SET scope = '' WHERE scope IS NULL;
ALTER TABLE login_attempt ALTER COLUMN scope SET NOT NULL;
