ALTER TABLE login_attempt ADD COLUMN grant_type VARCHAR NOT NULL DEFAULT 'authorization_code';
ALTER TABLE login_attempt ADD COLUMN device_code VARCHAR;
ALTER TABLE login_attempt ADD COLUMN provider_device_code VARCHAR;
