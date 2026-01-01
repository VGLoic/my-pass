use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use anyhow::anyhow;
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, Version,
    password_hash::{PasswordHasher, PasswordVerifier, Salt},
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use fake::rand;

use crate::newtypes::{Opaque, Password};

// REMIND ME: think about trait
/// Hash a password using the Argon2id algorithm. The returned string is a argon2-formatted hash.
///
/// # Arguments
/// * `password` - Password to verify
pub fn hash_password(password: &Password) -> Result<String, anyhow::Error> {
    let salt: [u8; 16] = rand::random();
    let base64_salt = BASE64_STANDARD_NO_PAD.encode(salt);
    let argon_salt = Salt::from_b64(&base64_salt)
        .map_err(|e| anyhow!(e).context("failed to build Salt struct from base64 salt string"))?;
    argon2_instance()
        .hash_password(password.unsafe_inner().as_bytes(), argon_salt)
        .map_err(|e| anyhow!(e).context("failed to hash password"))
        .map(|v| v.to_string())
}

// REMIND ME: think about trait
/// Verify a password validity against an Argon2id formatted key
///
/// # Arguments
/// * `hash` - Argon2id formatted hash to verify against
/// * `password` - Password to verify
pub fn verify_password(hash: &Opaque<String>, password: &Password) -> Result<(), anyhow::Error> {
    let parsed_hash = PasswordHash::new(hash.unsafe_inner())
        .map_err(|e| anyhow!(e).context("failed to parse stored password hash"))?;
    match argon2_instance().verify_password(password.unsafe_inner().as_bytes(), &parsed_hash) {
        Ok(_) => Ok(()),
        Err(argon2::password_hash::Error::Password) => Err(anyhow!("invalid password")),
        Err(e) => Err(anyhow!(e).context("failed to verify password")),
    }
}

// REMIND ME: think about exposition
pub struct EncryptedKeyMaterial {
    pub symmetric_key_salt: Opaque<[u8; 16]>,
    pub encryption_nonce: Opaque<[u8; 12]>,
    pub ciphertext: Opaque<Vec<u8>>,
}

impl EncryptedKeyMaterial {
    pub fn new(
        symmetric_key_salt: Opaque<[u8; 16]>,
        encryption_nonce: Opaque<[u8; 12]>,
        ciphertext: Opaque<Vec<u8>>,
    ) -> Self {
        Self {
            symmetric_key_salt,
            encryption_nonce,
            ciphertext,
        }
    }
}

pub struct KeyMaterial {
    private_key: SigningKey,
    pub encrypted: EncryptedKeyMaterial,
}

impl KeyMaterial {
    pub fn generate(password: &Password) -> Result<Self, anyhow::Error> {
        let ed25519_secret_key: [u8; 32] = rand::random();
        let symmetric_key_salt: [u8; 16] = rand::random();

        let mut symmetric_key_material = [0u8; 32];
        argon2_instance()
            .hash_password_into(
                password.unsafe_inner().as_bytes(),
                &symmetric_key_salt,
                &mut symmetric_key_material,
            )
            .map_err(|e| anyhow!("{e}").context("failed to derive AES key salt"))?;

        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&symmetric_key_material);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let encryption_nonce: [u8; 12] = rand::random();
        let encryption_nonce_formatted = Nonce::<Aes256Gcm>::from_slice(&encryption_nonce);
        let ciphertext = cipher
            .encrypt(encryption_nonce_formatted, ed25519_secret_key.as_ref())
            .map_err(|e| anyhow!("{e}").context("failed to encrypt private key"))?;

        Ok(Self {
            private_key: SigningKey::from_bytes(&ed25519_secret_key),
            encrypted: EncryptedKeyMaterial {
                symmetric_key_salt: symmetric_key_salt.into(),
                encryption_nonce: encryption_nonce.into(),
                ciphertext: ciphertext.into(),
            },
        })
    }

    pub fn verify(
        password: &Password,
        encrypted_key_material: &EncryptedKeyMaterial,
        expected_public_key: &[u8; 32],
    ) -> Result<(), anyhow::Error> {
        let mut encryption_key_material = [0u8; 32];
        argon2_instance()
            .hash_password_into(
                password.unsafe_inner().as_bytes(),
                encrypted_key_material.symmetric_key_salt.unsafe_inner(),
                &mut encryption_key_material,
            )
            .map_err(|e| anyhow!("{e}").context("Failed to generate encryption key material"))?;

        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&encryption_key_material);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let encryption_nonce =
            Nonce::<Aes256Gcm>::from_slice(encrypted_key_material.encryption_nonce.unsafe_inner());

        let decrypted_private_key = cipher
            .decrypt(
                encryption_nonce,
                encrypted_key_material.ciphertext.unsafe_inner().as_slice(),
            )
            .map_err(|e| anyhow!("{e}").context("Failed to decrypt private key"))?;

        if decrypted_private_key.len() != 32 {
            return Err(anyhow!("Invalid decrypted private key length"));
        }

        let decrypted_private_key: [u8; 32] = slice_to_array(&decrypted_private_key);

        let ed25519_secret_key = SigningKey::from_bytes(&decrypted_private_key);
        let ed25519_public_key = ed25519_secret_key.verifying_key();

        if ed25519_public_key.to_bytes().as_slice() != expected_public_key.as_slice() {
            return Err(anyhow!("Public key does not match decrypted private key"));
        }

        Ok(())
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.private_key.verifying_key()
    }
}

fn slice_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    array
}

const ARGON2_MEMORY_COST: u32 = Params::DEFAULT_M_COST;
const ARGON2_TIME_COST: u32 = Params::DEFAULT_T_COST;
const ARGON2_PARALLELISM: u32 = Params::DEFAULT_P_COST;

fn argon2_instance() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            None,
        )
        .expect("Invalid Argon2 parameters"),
    )
}
