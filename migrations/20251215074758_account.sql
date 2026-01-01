-- Add migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "moddatetime";

CREATE TABLE "account" (
    id                                      UUID        NOT NULL    PRIMARY KEY DEFAULT uuid_generate_v4 (),
    -- The UNIQUE constraint on email creates an index, which is relied upon for primary account lookups.
    email                                   TEXT        NOT NULL    UNIQUE,
    password_hash                           TEXT        NOT NULL,
    verified                                BOOLEAN     NOT NULL    DEFAULT FALSE,
    private_key_symmetric_key_salt          BYTEA       NOT NULL,
    private_key_encryption_nonce            BYTEA       NOT NULL,
    private_key_ciphertext                  BYTEA       NOT NULL,
    public_key                              BYTEA       NOT NULL,
    last_login_at                           TIMESTAMPTZ NULL,
    created_at                              TIMESTAMPTZ NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_at                              TIMESTAMPTZ NOT NULL    DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER update_account_moddatetime
BEFORE UPDATE ON "account"
FOR EACH ROW
EXECUTE FUNCTION moddatetime('updated_at');

CREATE TABLE IF NOT EXISTS "verification_ticket" (
    id              UUID                                NOT NULL    PRIMARY KEY DEFAULT uuid_generate_v4 (),
    account_id      UUID                                NOT NULL,
    token           TEXT                                NOT NULL,
    created_at      TIMESTAMPTZ                         NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMPTZ                         NOT NULL,
    cancelled_at    TIMESTAMPTZ                         NULL,
    used_at         TIMESTAMPTZ                         NULL,
    updated_at      TIMESTAMPTZ                         NOT NULL    DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER update_verification_ticket_moddatetime
BEFORE UPDATE ON "verification_ticket"
FOR EACH ROW
EXECUTE FUNCTION moddatetime('updated_at');

-- Constrain one active (not used, not cancelled, not expired) ticket per account.
CREATE UNIQUE INDEX IF NOT EXISTS unique_active_verification_ticket_per_account
ON "verification_ticket" (account_id)
WHERE used_at IS NULL AND cancelled_at IS NULL;
