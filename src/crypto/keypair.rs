use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use anyhow::anyhow;
use ed25519_dalek::{SigningKey, VerifyingKey};
use fake::rand;

use super::argon2instance;
use crate::newtypes::{Opaque, Password};

/// Represents an encrypted key pair, including the necessary metadata for decryption.
pub struct EncryptedKeyPair {
    /// Salt used to derive the symmetric encryption key
    pub symmetric_key_salt: Opaque<[u8; 16]>,
    /// Nonce used for the encryption
    pub encryption_nonce: Opaque<[u8; 12]>,
    /// Encrypted private key ciphertext
    pub ciphertext: Opaque<Vec<u8>>,
    /// Public key corresponding to the encrypted private key
    pub public_key: Opaque<[u8; 32]>,
}

impl EncryptedKeyPair {
    /// Creates a new encrypted key pair.
    /// The validity of the encrypted data is checked by attempting to decrypt it with the provided password.
    /// # Arguments
    /// * `symmetric_key_salt` - Salt used to derive the symmetric encryption key
    /// * `encryption_nonce` - Nonce used for the encryption
    /// * `ciphertext` - Encrypted private key ciphertext
    /// * `public_key` - Public key corresponding to the encrypted private key
    /// * `password` - Password used to derive the decryption key
    pub fn new(
        symmetric_key_salt: Opaque<[u8; 16]>,
        encryption_nonce: Opaque<[u8; 12]>,
        ciphertext: Opaque<Vec<u8>>,
        public_key: Opaque<[u8; 32]>,
        password: &Password,
    ) -> Result<Self, anyhow::Error> {
        let mut encryption_key_material = [0u8; 32];
        argon2instance::argon2_instance()
            .hash_password_into(
                password.unsafe_inner().as_bytes(),
                symmetric_key_salt.unsafe_inner(),
                &mut encryption_key_material,
            )
            .map_err(|e| anyhow!("{e}").context("Failed to generate encryption key material"))?;

        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&encryption_key_material);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let encryption_nonce_formatted =
            Nonce::<Aes256Gcm>::from_slice(encryption_nonce.unsafe_inner());

        let decrypted_private_key = cipher
            .decrypt(
                encryption_nonce_formatted,
                ciphertext.unsafe_inner().as_slice(),
            )
            .map_err(|e| anyhow!("{e}").context("Failed to decrypt private key"))?;

        if decrypted_private_key.len() != 32 {
            return Err(anyhow!("Invalid decrypted private key length"));
        }

        let decrypted_private_key: [u8; 32] = {
            let mut array = [0u8; 32];
            array.copy_from_slice(&decrypted_private_key);
            array
        };

        let ed25519_secret_key = SigningKey::from_bytes(&decrypted_private_key);
        let ed25519_public_key = ed25519_secret_key.verifying_key();

        if ed25519_public_key.to_bytes().as_slice() != public_key.unsafe_inner().as_slice() {
            return Err(anyhow!("Public key does not match decrypted private key"));
        }

        Ok(Self {
            symmetric_key_salt,
            encryption_nonce,
            ciphertext,
            public_key,
        })
    }
}

pub struct KeyPair {
    private_key: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let ed25519_secret_key: [u8; 32] = rand::random();

        Self {
            private_key: SigningKey::from_bytes(&ed25519_secret_key),
        }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.private_key.verifying_key()
    }

    /// Encrypts the key pair using the provided password.
    /// Returns an `EncryptedKeyPair` containing the encrypted private key and associated metadata.
    ///
    /// The encryption is performed using AES-256-GCM, with a symmetric key derived from the password using Argon2id.
    /// # Arguments
    /// * `password` - Password used to derive the encryption key
    pub fn encrypt(&self, password: &Password) -> Result<EncryptedKeyPair, anyhow::Error> {
        let symmetric_key_salt: [u8; 16] = rand::random();

        let mut symmetric_key_material = [0u8; 32];
        argon2instance::argon2_instance()
            .hash_password_into(
                password.unsafe_inner().as_bytes(),
                &symmetric_key_salt,
                &mut symmetric_key_material,
            )
            .map_err(|e| {
                anyhow!("{e}").context("failed to derive symmetric key from password and salt")
            })?;

        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&symmetric_key_material);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let encryption_nonce: [u8; 12] = rand::random();
        let encryption_nonce_formatted = Nonce::<Aes256Gcm>::from_slice(&encryption_nonce);
        let ciphertext = cipher
            .encrypt(
                encryption_nonce_formatted,
                self.private_key.to_bytes().as_slice(),
            )
            .map_err(|e| anyhow!("{e}").context("failed to encrypt private key"))?;

        Ok(EncryptedKeyPair {
            symmetric_key_salt: symmetric_key_salt.into(),
            encryption_nonce: encryption_nonce.into(),
            ciphertext: ciphertext.into(),
            public_key: self.public_key().to_bytes().into(),
        })
    }
}
