UPDATE login_attempt SET redirect_uri = '' WHERE redirect_uri IS NULL;
ALTER TABLE login_attempt ALTER COLUMN redirect_uri SET NOT NULL;
