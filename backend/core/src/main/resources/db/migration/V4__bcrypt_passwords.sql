-- FIXED: [A04-Lab7] Cryptographic Failure - moves the stored passwords from
-- unsalted MD5 to bcrypt.
--
-- V1__schema.sql already carries the wider column, but Flyway only runs each
-- migration once, so an existing database needs this ALTER to pick it up.
ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255);

-- The MD5 digests are replaced with bcrypt hashes of the same passwords. The
-- plaintexts are the seeded ones, so the accounts keep working for the labs:
--   alice   -> password123
--   bob     -> qwerty
--   admin   -> admin
--   charlie -> charlie
--
-- Each bcrypt hash carries its own random salt, so every account has a
-- different stored value even where two accounts share a password.
UPDATE users SET password_hash = '$2a$12$rRbHhLMozsJ2kJQ/v0bBwO/x.IUWHplP8AojZ2YZXdHF4IFVcVVVW' WHERE username = 'alice';
UPDATE users SET password_hash = '$2a$12$.3TQGXOST0NkP8GgqaM66enor5XLhi4pzpG7spXwoSJhUQW7JiDwW' WHERE username = 'bob';
UPDATE users SET password_hash = '$2a$12$bYKrnmss.vgt6WKRqNNwhOQxHE6KgIdmrUNf57Mc0Cj6TFFJ/KuyS' WHERE username = 'admin';
UPDATE users SET password_hash = '$2a$12$gx0CF8X71VHBfmym7CN74uKosWoW0YMAtaGIaYlspZoOum.qqQseK' WHERE username = 'charlie';

-- Any account created after the seed still holds an MD5 digest, because the
-- admin API used to hash with MD5. Those are reset to a bcrypt hash of the
-- factory password, so no MD5 digest survives the migration.
UPDATE users SET password_hash = '$2a$12$bYKrnmss.vgt6WKRqNNwhOQxHE6KgIdmrUNf57Mc0Cj6TFFJ/KuyS'
 WHERE username <> 'alice' AND username <> 'bob' AND username <> 'charlie'
   AND password_hash NOT LIKE '$2a$%';
