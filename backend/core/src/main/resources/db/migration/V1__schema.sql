-- SecureBank Labs — schema
-- FIXED: [A04-Lab7] Passwords are stored as bcrypt hashes with a unique salt per
-- user. The column is 255 characters wide because a bcrypt hash is 60 characters.

CREATE TABLE users (
                       id              BIGSERIAL PRIMARY KEY,
                       username        VARCHAR(64)  NOT NULL UNIQUE,
                       email           VARCHAR(255) NOT NULL,
                       password_hash   VARCHAR(255) NOT NULL,   -- FIXED: [A04-Lab7] bcrypt hash
                       role            VARCHAR(32)  NOT NULL DEFAULT 'customer',
                       full_name       VARCHAR(255),
                       sort_code       VARCHAR(8),
    -- FIXED: [A02-Lab5] an account flagged here must replace its password before
    -- it can be used, so a seeded factory password is never a permanent way in.
                       must_change_password BOOLEAN     NOT NULL DEFAULT FALSE,
                       created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE accounts (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES users(id),
    account_number  VARCHAR(20)  NOT NULL UNIQUE,
    sort_code       VARCHAR(8)   NOT NULL,
    balance         NUMERIC(14,2) NOT NULL DEFAULT 0,
    currency        VARCHAR(3)   NOT NULL DEFAULT 'GBP',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE transfers (
    id              BIGSERIAL PRIMARY KEY,
    from_account_id BIGINT       NOT NULL REFERENCES accounts(id),
    to_account_id   BIGINT       NOT NULL REFERENCES accounts(id),
    amount          NUMERIC(14,2) NOT NULL,
    note            TEXT,                    -- VULN: [A05-Lab13] stored unsanitised, rendered as raw HTML
    remark          TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE kyc_documents (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT       REFERENCES users(id),
    original_name   VARCHAR(255) NOT NULL,
    stored_path     VARCHAR(512) NOT NULL,
    uploaded_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_accounts_user_id ON accounts(user_id);
CREATE INDEX idx_transfers_from ON transfers(from_account_id);
CREATE INDEX idx_transfers_to   ON transfers(to_account_id);
