-- FIXED: [A02-Lab5] Default Credentials - adds the flag that stops a seeded
-- factory password from being a permanent way in to the admin console.
--
-- V1__schema.sql already carries the column, but Flyway only runs each
-- migration once, so an existing database needs this ALTER to pick it up.
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- The seeded administrator keeps the flag; every other account is already fine.
UPDATE users SET must_change_password = TRUE WHERE username = 'admin';
