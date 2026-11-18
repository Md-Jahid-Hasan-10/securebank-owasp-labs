-- SecureBank Labs — seed data
-- Password hashes are unsalted MD5 (Lab 7). Verified values:
--   password123 -> 482c811da5d5b4bc6d497ffa98491e38
--   qwerty      -> d8578edf8458ce06fbc5bb76a58c5ca4
--   admin       -> 21232f297a57a5a743894a0e4a801fc3
--   charlie     -> bf779e0933a882808585d19455cd7937

INSERT INTO users (id, username, email, password_hash, role, full_name, sort_code) VALUES
    (1, 'alice',   'alice@bank.com',   '482c811da5d5b4bc6d497ffa98491e38', 'customer', 'Alice Morgan',   '20-00-00'),
    (2, 'bob',     'bob@bank.com',     'd8578edf8458ce06fbc5bb76a58c5ca4', 'customer', 'Bob Carter',    '20-00-00'),
    (3, 'admin',   'admin@bank.com',   '21232f297a57a5a743894a0e4a801fc3', 'admin',   'System Admin',  '20-00-00'),
    (4, 'charlie', 'charlie@bank.com', 'bf779e0933a882808585d19455cd7937', 'customer', 'Charlie Reid',  '20-00-00');

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
