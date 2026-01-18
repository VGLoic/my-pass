#[cfg(test)]
use super::models::*;
#[cfg(test)]
use base64::prelude::BASE64_URL_SAFE;
#[cfg(test)]
use fake::{Fake, Faker};

/// Creates a fake Account for testing purposes.
/// The account is unverified by default with a randomly generated password hash.
#[cfg(test)]
pub fn fake_account() -> Account {
    use crate::{
        crypto::password::PasswordOps,
        newtypes::{Opaque, Password},
    };

    let password = Faker.fake::<Password>();
    Account {
        id: uuid::Uuid::new_v4(),
        email: Faker.fake(),
        password_hash: password.hash().unwrap().into(),
        verified: false,
        private_key_symmetric_key_salt: Opaque::new(Faker.fake::<[u8; 16]>()),
        private_key_encryption_nonce: Opaque::new(Faker.fake::<[u8; 12]>()),
        private_key_ciphertext: Opaque::new(vec![0u8; 64]),
        public_key: Opaque::new(Faker.fake::<[u8; 32]>()),
        last_login_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Creates a fake VerificationTicket for testing purposes.
/// The ticket is active (not used, not cancelled) and expires in 15 minutes.
#[cfg(test)]
pub fn fake_verification_ticket(account_id: uuid::Uuid) -> VerificationTicket {
    use base64::Engine;

    use crate::newtypes::Opaque;

    VerificationTicket {
        id: uuid::Uuid::new_v4(),
        account_id,
        token: Opaque::new(BASE64_URL_SAFE.encode(Faker.fake::<[u8; 32]>())),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(15),
        created_at: chrono::Utc::now(),
        cancelled_at: None,
        used_at: None,
        updated_at: chrono::Utc::now(),
    }
}
