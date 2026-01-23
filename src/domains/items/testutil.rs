#[cfg(test)]
use crate::crypto::keypair::PrivateKey;

#[cfg(test)]
pub struct EncryptedItem {
    pub ciphertext: Vec<u8>,
    pub encryption_nonce: [u8; 12],
    pub ephemeral_public_key: [u8; 32],
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],
}
#[cfg(test)]
impl EncryptedItem {
    pub fn new(plaintext: &[u8], private_key: &PrivateKey) -> Result<Self, anyhow::Error> {
        use fake::rand;

        use crate::crypto::keypair::SymmetricKey;

        let encapsulated_symmetric_key =
            SymmetricKey::encapsulate(&private_key.encapsulation_public_key()).map_err(|e| {
                anyhow::anyhow!("{e}").context("failed to encrypt symmetric key for test")
            })?;
        let encryption_nonce: [u8; 12] = rand::random();

        let ciphertext = encapsulated_symmetric_key
            .symmetric_key()
            .encrypt(plaintext, &encryption_nonce)
            .map_err(|e| anyhow::anyhow!("{e}").context("failed to encrypt test plaintext"))?;

        let (signature_r, signature_s) = private_key.sign(&ciphertext)?;

        Ok(Self {
            ciphertext,
            encryption_nonce,
            ephemeral_public_key: encapsulated_symmetric_key
                .ephemeral_public_key()
                .to_bytes()
                .unsafe_inner()
                .to_owned(),
            signature_r,
            signature_s,
        })
    }
}
