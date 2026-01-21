// ###############################################
// ############### ITEM DEFINITION ###############
// ###############################################

use sqlx::prelude::FromRow;
use thiserror::Error;

use crate::{crypto::keypair::PublicKey, newtypes::Opaque};

#[derive(Debug, Clone, FromRow)]
pub struct Item {
    pub id: uuid::Uuid,
    pub account_id: uuid::Uuid,
    pub ciphertext: Opaque<Vec<u8>>,
    pub encryption_nonce: Opaque<[u8; 12]>,
    pub encrypted_symmetric_key: Opaque<Vec<u8>>,
    pub signature_r: Opaque<[u8; 32]>,
    pub signature_s: Opaque<[u8; 32]>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ###########################################
// ############### CREATE ITEM ###############
// ###########################################

pub struct CreateItemRequest {
    account_id: uuid::Uuid,
    ciphertext: Opaque<Vec<u8>>,
    encryption_nonce: Opaque<[u8; 12]>,
    encrypted_symmetric_key: Opaque<Vec<u8>>,
    signature_r: Opaque<[u8; 32]>,
    signature_s: Opaque<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum CreateItemRequestError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl CreateItemRequest {
    pub fn new(
        account_id: uuid::Uuid,
        account_public_key: Opaque<[u8; 32]>,
        ciphertext: Opaque<Vec<u8>>,
        encryption_nonce: Opaque<[u8; 12]>,
        encrypted_symmetric_key: Opaque<Vec<u8>>,
        signature_r: Opaque<[u8; 32]>,
        signature_s: Opaque<[u8; 32]>,
    ) -> Result<Self, CreateItemRequestError> {
        PublicKey::new(account_public_key)
            .verify_signature(&ciphertext, &signature_r, &signature_s)
            .map_err(|_| CreateItemRequestError::InvalidSignature)?;

        Ok(Self {
            account_id,
            ciphertext,
            encryption_nonce,
            encrypted_symmetric_key,
            signature_r,
            signature_s,
        })
    }

    pub fn account_id(&self) -> uuid::Uuid {
        self.account_id
    }

    pub fn ciphertext(&self) -> &Opaque<Vec<u8>> {
        &self.ciphertext
    }
    pub fn encryption_nonce(&self) -> &Opaque<[u8; 12]> {
        &self.encryption_nonce
    }
    pub fn encrypted_symmetric_key(&self) -> &Opaque<Vec<u8>> {
        &self.encrypted_symmetric_key
    }
    pub fn signature_r(&self) -> &Opaque<[u8; 32]> {
        &self.signature_r
    }
    pub fn signature_s(&self) -> &Opaque<[u8; 32]> {
        &self.signature_s
    }
}

#[derive(Debug, Error)]
pub enum CreateItemError {
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

// ##############################################
// ############### ITEM RETRIEVAL ###############
// ##############################################

#[derive(Debug, Error)]
pub enum FindItemsError {
    #[error("Account not found")]
    AccountNotFound,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use fake::rand;

    use crate::crypto::keypair::{PrivateKey, SymmetricKey};

    use super::*;

    // REMIND ME: duplicate
    struct EncryptedItem {
        ciphertext: Vec<u8>,
        encryption_nonce: [u8; 12],
        encrypted_symmetric_key: Vec<u8>,
        signature_r: [u8; 32],
        signature_s: [u8; 32],
    }
    impl EncryptedItem {
        fn new(private_key: &PrivateKey) -> Result<Self, anyhow::Error> {
            let plaintext: [u8; 32] = rand::random();
            let symmetric_key = SymmetricKey::generate();
            let encryption_nonce: [u8; 12] = rand::random();

            let ciphertext = symmetric_key
                .encrypt(&plaintext, &encryption_nonce)
                .map_err(|e| anyhow::anyhow!("{e}").context("failed to encrypt test plaintext"))?;
            let encrypted_symmetric_key = private_key
                .public_key()
                .encrypt(symmetric_key.to_bytes().unsafe_inner())
                .map_err(|e| {
                    anyhow::anyhow!("{e}").context("failed to encrypt symmetric key for test")
                })?;

            let (signature_r, signature_s) = private_key.sign(&ciphertext)?;

            Ok(Self {
                ciphertext,
                encryption_nonce,
                encrypted_symmetric_key,
                signature_r,
                signature_s,
            })
        }
    }

    #[test]
    fn test_invalid_create_item_request_signature() {
        let private_key = PrivateKey::generate();
        let account_public_key = private_key.public_key();
        let encrypted_item = EncryptedItem::new(&private_key).unwrap();

        // Flip a bit in signature_r to make it invalid
        let mut invalid_signature_r = encrypted_item.signature_r;
        invalid_signature_r[0] ^= 0x01;

        let result = CreateItemRequest::new(
            uuid::Uuid::new_v4(),
            account_public_key.to_bytes(),
            Opaque::new(encrypted_item.ciphertext),
            Opaque::new(encrypted_item.encryption_nonce),
            Opaque::new(encrypted_item.encrypted_symmetric_key),
            Opaque::new(invalid_signature_r),
            Opaque::new(encrypted_item.signature_s),
        );

        assert!(matches!(
            result,
            Err(CreateItemRequestError::InvalidSignature)
        ));
    }

    #[test]
    fn test_valid_create_item_request() {
        let private_key = PrivateKey::generate();
        let account_public_key = private_key.public_key();
        let encrypted_item = EncryptedItem::new(&private_key).unwrap();

        let result = CreateItemRequest::new(
            uuid::Uuid::new_v4(),
            account_public_key.to_bytes(),
            Opaque::new(encrypted_item.ciphertext.clone()),
            Opaque::new(encrypted_item.encryption_nonce),
            Opaque::new(encrypted_item.encrypted_symmetric_key.clone()),
            Opaque::new(encrypted_item.signature_r),
            Opaque::new(encrypted_item.signature_s),
        );

        assert!(result.is_ok());
        let create_item_request = result.unwrap();
        assert_eq!(
            create_item_request.ciphertext().unsafe_inner(),
            &encrypted_item.ciphertext
        );
        assert_eq!(
            create_item_request.encryption_nonce().unsafe_inner(),
            &encrypted_item.encryption_nonce
        );
        assert_eq!(
            create_item_request.encrypted_symmetric_key().unsafe_inner(),
            &encrypted_item.encrypted_symmetric_key
        );
        assert_eq!(
            create_item_request.signature_r().unsafe_inner(),
            &encrypted_item.signature_r
        );
        assert_eq!(
            create_item_request.signature_s().unsafe_inner(),
            &encrypted_item.signature_s
        );
    }
}
