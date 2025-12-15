-- Add migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "moddatetime";

CREATE TABLE "account" (
    id                          UUID        NOT NULL    PRIMARY KEY DEFAULT uuid_generate_v4 (),
    -- The UNIQUE constraint on email creates an index, which is relied upon for primary account lookups.
    email                       TEXT        NOT NULL    UNIQUE,
    password_hash               TEXT        NOT NULL,
    symmetric_key_salt          BYTEA       NOT NULL,
    encrypted_private_key_nonce BYTEA       NOT NULL,
    encrypted_private_key       TEXT        NOT NULL,
    public_key                  BYTEA       NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL    DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMPTZ NOT NULL    DEFAULT CURRENT_TIMESTAMP
);


CREATE TRIGGER update_account_moddatetime
BEFORE UPDATE ON "account"
FOR EACH ROW
EXECUTE FUNCTION moddatetime('updated_at');
