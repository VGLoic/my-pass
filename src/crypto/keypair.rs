use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use anyhow::anyhow;
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use fake::rand;

use super::argon2instance;
use crate::newtypes::{Opaque, Password};

/// Represents an encrypted key pair, including the necessary metadata for decryption.
#[derive(Debug, Clone)]
pub struct EncryptedKeyPair {
    /// Password used for encryption/decryption
    password: Password,
    /// Salt used to derive the symmetric encryption key
    symmetric_key_salt: Opaque<[u8; 16]>,
    /// Nonce used for the encryption
    encryption_nonce: Opaque<[u8; 12]>,
    /// Encrypted private key ciphertext
    ciphertext: Opaque<Vec<u8>>,
    /// Public key corresponding to the encrypted private key
    public_key: Opaque<[u8; 32]>,
}

impl EncryptedKeyPair {
    /// Creates a new encrypted key pair.
    /// The validity of the encrypted data is checked by attempting to decrypt it with the provided password.
    /// # Arguments
    /// * `password` - Password used to derive the decryption key
    /// * `symmetric_key_salt` - Salt used to derive the symmetric encryption key
    /// * `encryption_nonce` - Nonce used for the encryption
    /// * `ciphertext` - Encrypted private key ciphertext
    /// * `public_key` - Public key corresponding to the encrypted private key
    pub fn new(
        password: Password,
        symmetric_key_salt: Opaque<[u8; 16]>,
        encryption_nonce: Opaque<[u8; 12]>,
        ciphertext: Opaque<Vec<u8>>,
        public_key: Opaque<[u8; 32]>,
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
            password,
            symmetric_key_salt,
            encryption_nonce,
            ciphertext,
            public_key,
        })
    }

    pub fn password(&self) -> &Password {
        &self.password
    }
    pub fn symmetric_key_salt(&self) -> &Opaque<[u8; 16]> {
        &self.symmetric_key_salt
    }
    pub fn encryption_nonce(&self) -> &Opaque<[u8; 12]> {
        &self.encryption_nonce
    }
    pub fn ciphertext(&self) -> &Opaque<Vec<u8>> {
        &self.ciphertext
    }
    pub fn public_key(&self) -> &Opaque<[u8; 32]> {
        &self.public_key
    }
}

pub struct PrivateKey {
    key: [u8; 32],
}

impl PrivateKey {
    pub fn generate() -> Self {
        let key: [u8; 32] = rand::random();
        Self { key }
    }

    pub fn public_key(&self) -> PublicKey {
        let signing_key = SigningKey::from_bytes(&self.key);
        let verifying_key = signing_key.verifying_key();
        PublicKey {
            key: verifying_key.to_bytes(),
        }
    }

    #[cfg(test)]
    pub fn encapsulation_public_key(&self) -> EncapsulationPublicKey {
        let private_secret = x25519_dalek::StaticSecret::from(self.key);
        let public_key = x25519_dalek::PublicKey::from(&private_secret);
        EncapsulationPublicKey::new(Opaque::new(public_key.to_bytes()))
    }

    /// Signs a message using the private key.
    /// # Arguments
    /// * `message` - The message to be signed
    /// # Returns
    /// Returns a tuple containing the 'r' and 's' components of the signature.
    #[cfg(test)]
    pub fn sign(&self, message: &[u8]) -> Result<([u8; 32], [u8; 32]), anyhow::Error> {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::from_bytes(&self.key);
        let signature = signing_key
            .try_sign(message)
            .map_err(|e| anyhow::Error::new(e).context("failed to sign message"))?;

        Ok((
            signature.r_bytes().to_owned(),
            signature.s_bytes().to_owned(),
        ))
    }

    /// Decapsulates an encapsulated symmetric key using the private key.
    /// # Arguments
    /// * `encapsulated_symmetric_key` - The encapsulated symmetric key to be decapsulated
    /// # Returns
    /// Returns the decapsulated symmetric key.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn decapsulate(
        &self,
        ephemeral_public_key: &EncapsulationPublicKey,
    ) -> Result<SymmetricKey, anyhow::Error> {
        let private_secret = x25519_dalek::StaticSecret::from(self.key);
        let ephemeral_public_key = x25519_dalek::PublicKey::from(ephemeral_public_key.key);
        let shared_secret = private_secret.diffie_hellman(&ephemeral_public_key);
        Ok(SymmetricKey::new(shared_secret.to_bytes()))
    }

    /// Encrypts the private key using the provided password.
    /// Returns an `EncryptedKeyPair` containing the encrypted private key and associated metadata.
    ///
    /// The encryption is performed using AES-256-GCM, with a symmetric key derived from the password using Argon2id.
    /// # Arguments
    /// * `password` - Password used to derive the encryption key
    pub fn encrypt_key_pair_with_password(
        &self,
        password: Password,
    ) -> Result<EncryptedKeyPair, anyhow::Error> {
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

        let symmetric_key = SymmetricKey::new(symmetric_key_material);
        let encryption_nonce: [u8; 12] = rand::random();
        let ciphertext = symmetric_key
            .encrypt(self.key.as_slice(), &encryption_nonce)
            .map_err(|e| e.context("failed to encrypt private key"))?;

        Ok(EncryptedKeyPair {
            password,
            symmetric_key_salt: symmetric_key_salt.into(),
            encryption_nonce: encryption_nonce.into(),
            ciphertext: ciphertext.into(),
            public_key: self.public_key().to_bytes(),
        })
    }
}

#[cfg(test)]
pub struct EncapsulationPublicKey {
    key: [u8; 32],
}

#[cfg(test)]
impl EncapsulationPublicKey {
    pub fn new(key: Opaque<[u8; 32]>) -> Self {
        Self {
            key: key.unsafe_inner().to_owned(),
        }
    }

    pub fn to_bytes(&self) -> Opaque<[u8; 32]> {
        Opaque::new(self.key)
    }
}

pub struct PublicKey {
    key: [u8; 32],
}

impl PublicKey {
    pub fn new(key: Opaque<[u8; 32]>) -> Self {
        Self {
            key: key.unsafe_inner().to_owned(),
        }
    }

    pub fn to_bytes(&self) -> Opaque<[u8; 32]> {
        Opaque::new(self.key)
    }

    /// Verifies a digital signature using the Ed25519 algorithm.
    /// # Arguments
    /// * `message` - The original message that was signed
    /// * `signature_r` - The 'r' component of the signature
    /// * `signature_s` - The 's' component of the signature
    pub fn verify_signature(
        &self,
        message: &Opaque<Vec<u8>>,
        signature_r: &Opaque<[u8; 32]>,
        signature_s: &Opaque<[u8; 32]>,
    ) -> Result<(), anyhow::Error> {
        let ed25519_public_key = VerifyingKey::from_bytes(&self.key).map_err(|e| {
            anyhow!("{e}").context("Failed to create verifying key from public key")
        })?;
        let ed25519_signature = ed25519_dalek::Signature::from_components(
            signature_r.unsafe_inner().to_owned(),
            signature_s.unsafe_inner().to_owned(),
        );
        ed25519_public_key
            .verify(message.unsafe_inner().as_slice(), &ed25519_signature)
            .map_err(|e| anyhow::Error::new(e).context("Failed to verify signature"))
    }
}

pub struct SymmetricKey {
    key: [u8; 32],
}

#[cfg(test)]
pub struct EncapsulatedSymmetricKey {
    shared_key: SymmetricKey,
    ephemeral_public_key: EncapsulationPublicKey,
}

#[cfg(test)]
impl EncapsulatedSymmetricKey {
    pub fn symmetric_key(&self) -> &SymmetricKey {
        &self.shared_key
    }
    pub fn ephemeral_public_key(&self) -> &EncapsulationPublicKey {
        &self.ephemeral_public_key
    }
}

impl SymmetricKey {
    #[cfg(test)]
    pub fn generate() -> Self {
        let key: [u8; 32] = rand::random();
        Self::new(key)
    }
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    #[cfg(test)]
    pub fn encapsulate(
        public_key: &EncapsulationPublicKey,
    ) -> Result<EncapsulatedSymmetricKey, anyhow::Error> {
        let ephemeral_secret = x25519_dalek::EphemeralSecret::random();
        let ephemeral_public_key = x25519_dalek::PublicKey::from(&ephemeral_secret);

        let recipient_public_key = x25519_dalek::PublicKey::from(public_key.key);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
        let shared_key = SymmetricKey::new(shared_secret.to_bytes());
        Ok(EncapsulatedSymmetricKey {
            shared_key,
            ephemeral_public_key: EncapsulationPublicKey::new(Opaque::new(
                ephemeral_public_key.to_bytes(),
            )),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, anyhow::Error> {
        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let encryption_nonce_formatted = Nonce::<Aes256Gcm>::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(encryption_nonce_formatted, plaintext)
            .map_err(|e| anyhow!("{e}").context("failed to encrypt data"))?;

        Ok(ciphertext)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, anyhow::Error> {
        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let encryption_nonce_formatted = Nonce::<Aes256Gcm>::from_slice(nonce);
        let plaintext = cipher
            .decrypt(encryption_nonce_formatted, ciphertext)
            .map_err(|e| anyhow!("{e}").context("failed to decrypt data"))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use fake::{Fake, Faker};

    use super::*;

    #[test]
    fn test_symmetric_key_encryption_decryption() {
        let symmetric_key = SymmetricKey::generate();
        let plaintext: [u8; 32] = rand::random();
        let nonce: [u8; 12] = rand::random();

        let ciphertext = symmetric_key.encrypt(&plaintext, &nonce).unwrap();
        let decrypted_plaintext = symmetric_key.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }

    #[test]
    fn test_key_pair_encryption_decryption() {
        let private_key = PrivateKey::generate();
        let password: Password = Faker.fake();
        let encrypted_key_pair = private_key
            .encrypt_key_pair_with_password(password.clone())
            .unwrap();
        assert!(
            EncryptedKeyPair::new(
                password,
                encrypted_key_pair.symmetric_key_salt().clone(),
                encrypted_key_pair.encryption_nonce().clone(),
                encrypted_key_pair.ciphertext().clone(),
                private_key.public_key().to_bytes(),
            )
            .is_ok()
        );
    }

    #[test]
    fn test_symmetric_key_encapsulation_decapsulation() {
        let private_key = PrivateKey::generate();
        let public_key = private_key.encapsulation_public_key();

        let encapsulated_symmetric_key =
            SymmetricKey::encapsulate(&public_key).expect("Failed to encapsulate symmetric key");
        let decapsulated_symmetric_key = private_key
            .decapsulate(encapsulated_symmetric_key.ephemeral_public_key())
            .expect("Failed to decapsulate symmetric key");
        assert_eq!(
            encapsulated_symmetric_key.shared_key.key, decapsulated_symmetric_key.key,
            "Decapsulated key should match the original symmetric key"
        );
    }
}
