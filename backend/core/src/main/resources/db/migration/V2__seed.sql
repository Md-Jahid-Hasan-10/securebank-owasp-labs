-- SecureBank Labs — seed data
--
-- FIXED: [A04-Lab7] Cryptographic Failure - the password hashes are no longer
-- unsalted MD5 digests. They are bcrypt hashes (cost 12), each with its own
-- random salt, so the same password hashes to a different stored value for every
-- account. The plaintext passwords are unchanged, so the seeded accounts still
-- work for the labs:
--   alice   -> password123
--   bob     -> qwerty
--   admin   -> admin
--   charlie -> charlie
--
-- FIXED: [A02-Lab5] Default Credentials - the administrator used to be seeded with
-- the factory password, so anyone who had read this file could log in as admin.
-- NOW: the seeded administrator is flagged must_change_password and cannot be used
--       until its password has been replaced.
INSERT INTO users (id, username, email, password_hash, role, full_name, sort_code, must_change_password) VALUES
                                                                                                             (1, 'alice',   'alice@bank.com',   '$2a$12$rRbHhLMozsJ2kJQ/v0bBwO/x.IUWHplP8AojZ2YZXdHF4IFVcVVVW', 'customer', 'Alice Morgan',   '20-00-00', FALSE),
                                                                                                             (2, 'bob',     'bob@bank.com',     '$2a$12$.3TQGXOST0NkP8GgqaM66enor5XLhi4pzpG7spXwoSJhUQW7JiDwW', 'customer', 'Bob Carter',    '20-00-00', FALSE),
                                                                                                             (3, 'admin',   'admin@bank.com',   '$2a$12$bYKrnmss.vgt6WKRqNNwhOQxHE6KgIdmrUNf57Mc0Cj6TFFJ/KuyS', 'admin',   'System Admin',  '20-00-00', TRUE),
                                                                                                             (4, 'charlie', 'charlie@bank.com', '$2a$12$gx0CF8X71VHBfmym7CN74uKosWoW0YMAtaGIaYlspZoOum.qqQseK', 'customer', 'Charlie Reid',  '20-00-00', FALSE);

INSERT INTO accounts (id, user_id, account_number, sort_code, balance, currency) VALUES
                                                                                     (1, 1, 'ACC-1001', '20-00-00',  4200.00, 'GBP'),
                                                                                     (2, 2, 'ACC-1002', '20-00-00', 12800.00, 'GBP'),
                                                                                     (3, 4, 'ACC-1003', '20-00-00',   750.00, 'GBP');

INSERT INTO transfers (id, from_account_id, to_account_id, amount, note, remark, created_at) VALUES
                                                                                                 (1, 1, 2, 250.00, 'Rent contribution',      NULL, now() - interval '5 days'),
                                                                                                 (2, 2, 1, 100.00, 'Refund - conference fee', NULL, now() - interval '3 days'),
                                                                                                 (3, 1, 2,  75.50, 'Shared utilities',        NULL, now() - interval '1 day'),
                                                                                                 (4, 2, 3, 300.00, 'Piano lessons',           NULL, now() - interval '12 hours');

INSERT INTO kyc_documents (user_id, original_name, stored_path) VALUES
    (1, 'passport-alice.jpg', '/uploads/passport-alice.jpg');

-- The seed inserts explicit ids, which leaves the BIGSERIAL sequences behind.
-- Without this the first INSERT after seeding fails with a duplicate key error.
SELECT setval(pg_get_serial_sequence('users', 'id'),       (SELECT MAX(id) FROM users));
SELECT setval(pg_get_serial_sequence('accounts', 'id'),     (SELECT MAX(id) FROM accounts));
SELECT setval(pg_get_serial_sequence('transfers', 'id'),    (SELECT MAX(id) FROM transfers));
SELECT setval(pg_get_serial_sequence('kyc_documents', 'id'), (SELECT MAX(id) FROM kyc_documents));