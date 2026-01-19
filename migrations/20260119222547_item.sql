-- Add migration script here

CREATE TABLE "item" (
    id                                      UUID        NOT NULL    PRIMARY KEY DEFAULT uuid_generate_v4 (),
    account_id                              UUID        NOT NULL,
    ciphertext                              BYTEA       NOT NULL,
    encryption_nonce                        BYTEA       NOT NULL,
    encrypted_symmetric_key                 BYTEA       NOT NULL,
    signature                               BYTEA       NOT NULL,
    created_at                              TIMESTAMPTZ NOT NULL   DEFAULT CURRENT_TIMESTAMP,
    updated_at                              TIMESTAMPTZ NOT NULL   DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER update_item_moddatetime
BEFORE UPDATE ON "item"
FOR EACH ROW
EXECUTE FUNCTION moddatetime('updated_at');
