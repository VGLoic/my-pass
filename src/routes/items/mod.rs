use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde::{Deserialize, Serialize};

use super::{ApiError, AppState, AuthorizedAccount};
use crate::{
    domains::{
        accounts::models::{Account, FindAccountError},
        items::models::{
            CreateItemError, CreateItemRequest, CreateItemRequestError, FindItemsError, Item,
        },
    },
    newtypes::Opaque,
};

pub fn items_router() -> Router<AppState> {
    Router::new().route("/", post(create_item).get(list_items))
}

// ###########################################
// ############### CREATE ITEM ###############
// ###########################################

async fn create_item(
    State(app_state): State<AppState>,
    authorized_account: AuthorizedAccount,
    Json(body): Json<CreateItemRequestHttpBody>,
) -> Result<(StatusCode, Json<ItemResponse>), ApiError> {
    let account = app_state
        .accounts_service
        .find_account_by_id(authorized_account.account_id)
        .await
        .map_err(|e| match e {
            FindAccountError::NotFound => ApiError::NotFound,
            FindAccountError::Unknown(e) => {
                ApiError::InternalServerError(e.context("failed to find account"))
            }
        })?;

    let request = body.try_into_domain(account).map_err(|e| match e {
        CreateItemRequestMappingError::CiphertextFormat(msg) => {
            ApiError::BadRequest(format!("invalid ciphertext format: {msg}"))
        }
        CreateItemRequestMappingError::EncryptionNonceFormat(msg) => {
            ApiError::BadRequest(format!("invalid encryption nonce format: {msg}"))
        }
        CreateItemRequestMappingError::EncryptedSymmetricKeyFormat(msg) => {
            ApiError::BadRequest(format!("invalid encrypted symmetric key format: {msg}"))
        }
        CreateItemRequestMappingError::SignatureFormat(msg) => {
            ApiError::BadRequest(format!("invalid signature format: {msg}"))
        }
        CreateItemRequestMappingError::Request(err) => match err {
            CreateItemRequestError::InvalidSignature => {
                ApiError::BadRequest("invalid signature".into())
            }
            CreateItemRequestError::Unknown(e) => {
                ApiError::InternalServerError(e.context("failed to create item request"))
            }
        },
    })?;

    let item = app_state
        .items_service
        .create_item(request)
        .await
        .map_err(|e| match e {
            CreateItemError::AccountNotFound => ApiError::NotFound,
            CreateItemError::Unknown(e) => {
                ApiError::InternalServerError(e.context("failed to create item"))
            }
        })?;

    Ok((StatusCode::CREATED, Json(ItemResponse::from(item))))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateItemRequestHttpBody {
    /// The encrypted item data - encoded in base64
    pub ciphertext: Opaque<String>,
    /// The nonce used for encryption - encoded in base64
    pub encryption_nonce: Opaque<String>,
    /// The encrypted symmetric key used for item encryption - encoded in base64
    pub encrypted_symmetric_key: Opaque<String>,
    /// The signature of the ciphertext - encoded in base64
    pub signature: Opaque<String>,
}

#[derive(Debug)]
enum CreateItemRequestMappingError {
    CiphertextFormat(String),
    EncryptionNonceFormat(String),
    EncryptedSymmetricKeyFormat(String),
    SignatureFormat(String),
    Request(CreateItemRequestError),
}

impl CreateItemRequestHttpBody {
    fn try_into_domain(
        self,
        account: Account,
    ) -> Result<CreateItemRequest, CreateItemRequestMappingError> {
        let ciphertext = BASE64_STANDARD
            .decode(self.ciphertext.unsafe_inner())
            .map_err(|e| {
                CreateItemRequestMappingError::CiphertextFormat(format!(
                    "Invalid base64 format: {e}"
                ))
            })?;

        let encryption_nonce = base64_to_array::<12>(self.encryption_nonce.unsafe_inner())
            .map_err(CreateItemRequestMappingError::EncryptionNonceFormat)?;

        let encrypted_symmetric_key = BASE64_STANDARD
            .decode(self.encrypted_symmetric_key.unsafe_inner())
            .map_err(|e| {
                CreateItemRequestMappingError::EncryptedSymmetricKeyFormat(format!(
                    "Invalid base64 format: {e}"
                ))
            })?;

        let full_signature = base64_to_array::<64>(self.signature.unsafe_inner())
            .map_err(CreateItemRequestMappingError::SignatureFormat)?;
        let (signature_r, signature_s) = {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&full_signature[0..32]);
            s.copy_from_slice(&full_signature[32..64]);
            (r, s)
        };

        CreateItemRequest::new(
            account.id,
            account.public_key,
            ciphertext.into(),
            encryption_nonce.into(),
            encrypted_symmetric_key.into(),
            signature_r.into(),
            signature_s.into(),
        )
        .map_err(CreateItemRequestMappingError::Request)
    }
}

fn base64_to_array<const N: usize>(base64_str: &str) -> Result<[u8; N], String> {
    let decoded = BASE64_STANDARD
        .decode(base64_str)
        .map_err(|e| format!("Invalid base64 format: {}", e))?;
    if decoded.len() != N {
        return Err(format!("Decoded data must be {} bytes long", N));
    }
    let array: [u8; N] = {
        let mut array = [0u8; N];
        array.copy_from_slice(&decoded);
        array
    };
    Ok(array)
}

// #########################################
// ############### GET ITEMS ###############
// #########################################

async fn list_items(
    State(app_state): State<AppState>,
    authorized_account: AuthorizedAccount,
) -> Result<Json<Vec<ItemResponse>>, ApiError> {
    let items = app_state
        .items_service
        .find_items_by_account_id(authorized_account.account_id)
        .await
        .map_err(|e| match e {
            FindItemsError::AccountNotFound => ApiError::NotFound,
            FindItemsError::Unknown(e) => {
                ApiError::InternalServerError(e.context("failed to list items"))
            }
        })?;
    Ok(Json(items.into_iter().map(ItemResponse::from).collect()))
}

// ######################################
// ############### COMMON ###############
// ######################################

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemResponse {
    pub id: uuid::Uuid,
    /// The encrypted item data - encoded in base64
    pub ciphertext: String,
    /// The nonce used for encryption - encoded in base64
    pub encryption_nonce: String,
    /// The encrypted symmetric key used for item encryption - encoded in base64
    pub encrypted_symmetric_key: String,
    /// The signature of the ciphertext - encoded in base64
    pub signature: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Item> for ItemResponse {
    fn from(item: Item) -> Self {
        let full_sig = [
            item.signature_r.unsafe_inner().as_slice(),
            item.signature_s.unsafe_inner().as_slice(),
        ]
        .concat();
        Self {
            id: item.id,
            ciphertext: BASE64_STANDARD.encode(item.ciphertext.unsafe_inner()),
            encryption_nonce: BASE64_STANDARD.encode(item.encryption_nonce.unsafe_inner()),
            encrypted_symmetric_key: BASE64_STANDARD
                .encode(item.encrypted_symmetric_key.unsafe_inner()),
            signature: BASE64_STANDARD.encode(&full_sig),
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::accounts::testutil::fake_account;
    use fake::rand;

    use crate::crypto::keypair::{PrivateKey, SymmetricKey};

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

    // ################ CREATE ITEM TESTS ################

    #[test]
    fn test_valid_create_item_request_mapping() {
        let private_key = PrivateKey::generate();
        let mut account = fake_account();
        account.public_key = private_key.public_key().to_bytes();

        let encrypted_item = EncryptedItem::new(&private_key).unwrap();
        let request_body = CreateItemRequestHttpBody {
            ciphertext: Opaque::new(BASE64_STANDARD.encode(encrypted_item.ciphertext)),
            encryption_nonce: Opaque::new(BASE64_STANDARD.encode(encrypted_item.encryption_nonce)),
            encrypted_symmetric_key: Opaque::new(
                BASE64_STANDARD.encode(encrypted_item.encrypted_symmetric_key),
            ),
            signature: Opaque::new(
                BASE64_STANDARD.encode(
                    [
                        &encrypted_item.signature_r[..],
                        &encrypted_item.signature_s[..],
                    ]
                    .concat(),
                ),
            ),
        };
        let result = request_body.try_into_domain(account);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_create_item_request_mapping_bad_ciphertext() {
        let private_key = PrivateKey::generate();
        let mut account = fake_account();
        account.public_key = private_key.public_key().to_bytes();

        let encrypted_item = EncryptedItem::new(&private_key).unwrap();
        let bad_ciphertext = "!!!invalid_base64!!!";
        let request_body = CreateItemRequestHttpBody {
            ciphertext: Opaque::new(bad_ciphertext.to_string()),
            encryption_nonce: Opaque::new(BASE64_STANDARD.encode(encrypted_item.encryption_nonce)),
            encrypted_symmetric_key: Opaque::new(
                BASE64_STANDARD.encode(encrypted_item.encrypted_symmetric_key),
            ),
            signature: Opaque::new(
                BASE64_STANDARD.encode(
                    [
                        &encrypted_item.signature_r[..],
                        &encrypted_item.signature_s[..],
                    ]
                    .concat(),
                ),
            ),
        };
        let result = request_body.try_into_domain(account);
        assert!(matches!(
            result,
            Err(CreateItemRequestMappingError::CiphertextFormat(_))
        ));
    }

    #[test]
    fn test_invalid_create_item_request_mapping_bad_encoding_encryption_nonce() {
        let private_key = PrivateKey::generate();
        let mut account = fake_account();
        account.public_key = private_key.public_key().to_bytes();
        let encrypted_item = EncryptedItem::new(&private_key).unwrap();
        let bad_encryption_nonce = "!!!invalid_base64!!!";
        let request_body = CreateItemRequestHttpBody {
            ciphertext: Opaque::new(BASE64_STANDARD.encode(encrypted_item.ciphertext)),
            encryption_nonce: Opaque::new(bad_encryption_nonce.to_string()),
            encrypted_symmetric_key: Opaque::new(
                BASE64_STANDARD.encode(encrypted_item.encrypted_symmetric_key),
            ),
            signature: Opaque::new(
                BASE64_STANDARD.encode(
                    [
                        &encrypted_item.signature_r[..],
                        &encrypted_item.signature_s[..],
                    ]
                    .concat(),
                ),
            ),
        };
        let result = request_body.try_into_domain(account);
        assert!(matches!(
            result,
            Err(CreateItemRequestMappingError::EncryptionNonceFormat(_))
        ));
    }

    #[test]
    fn test_invalid_create_item_request_mapping_bad_length_encryption_nonce() {
        let private_key = PrivateKey::generate();
        let mut account = fake_account();
        account.public_key = private_key.public_key().to_bytes();
        let encrypted_item = EncryptedItem::new(&private_key).unwrap();
        let bad_encryption_nonce = BASE64_STANDARD.encode([0u8; 10]); // should be 12 bytes
        let request_body = CreateItemRequestHttpBody {
            ciphertext: Opaque::new(BASE64_STANDARD.encode(encrypted_item.ciphertext)),
            encryption_nonce: Opaque::new(bad_encryption_nonce),
            encrypted_symmetric_key: Opaque::new(
                BASE64_STANDARD.encode(encrypted_item.encrypted_symmetric_key),
            ),
            signature: Opaque::new(
                BASE64_STANDARD.encode(
                    [
                        &encrypted_item.signature_r[..],
                        &encrypted_item.signature_s[..],
                    ]
                    .concat(),
                ),
            ),
        };
        let result = request_body.try_into_domain(account);
        assert!(matches!(
            result,
            Err(CreateItemRequestMappingError::EncryptionNonceFormat(_))
        ));
    }

    #[test]
    fn test_invalid_create_item_request_mapping_bad_encoding_symmetric_key() {
        let private_key = PrivateKey::generate();
        let mut account = fake_account();
        account.public_key = private_key.public_key().to_bytes();
        let encrypted_item = EncryptedItem::new(&private_key).unwrap();
        let bad_encrypted_symmetric_key = "!!!invalid_base64!!!";
        let request_body = CreateItemRequestHttpBody {
            ciphertext: Opaque::new(BASE64_STANDARD.encode(encrypted_item.ciphertext)),
            encryption_nonce: Opaque::new(BASE64_STANDARD.encode(encrypted_item.encryption_nonce)),
            encrypted_symmetric_key: Opaque::new(bad_encrypted_symmetric_key.to_string()),
            signature: Opaque::new(
                BASE64_STANDARD.encode(
                    [
                        &encrypted_item.signature_r[..],
                        &encrypted_item.signature_s[..],
                    ]
                    .concat(),
                ),
            ),
        };
        let result = request_body.try_into_domain(account);
        assert!(matches!(
            result,
            Err(CreateItemRequestMappingError::EncryptedSymmetricKeyFormat(
                _
            ))
        ));
    }

    #[test]
    fn test_invalid_create_item_request_mapping_bad_encoding_signature() {
        let private_key = PrivateKey::generate();
        let mut account = fake_account();
        account.public_key = private_key.public_key().to_bytes();
        let encrypted_item = EncryptedItem::new(&private_key).unwrap();
        let bad_signature = "!!!invalid_base64!!!";
        let request_body = CreateItemRequestHttpBody {
            ciphertext: Opaque::new(BASE64_STANDARD.encode(encrypted_item.ciphertext)),
            encryption_nonce: Opaque::new(BASE64_STANDARD.encode(encrypted_item.encryption_nonce)),
            encrypted_symmetric_key: Opaque::new(
                BASE64_STANDARD.encode(encrypted_item.encrypted_symmetric_key),
            ),
            signature: Opaque::new(bad_signature.to_string()),
        };
        let result = request_body.try_into_domain(account);
        assert!(matches!(
            result,
            Err(CreateItemRequestMappingError::SignatureFormat(_))
        ));
    }

    #[test]
    fn test_invalid_create_item_request_mapping_bad_signature_length() {
        let private_key = PrivateKey::generate();
        let mut account = fake_account();
        account.public_key = private_key.public_key().to_bytes();
        let encrypted_item = EncryptedItem::new(&private_key).unwrap();
        let bad_signature = BASE64_STANDARD.encode([0u8; 10]); // should be 64 bytes
        let request_body = CreateItemRequestHttpBody {
            ciphertext: Opaque::new(BASE64_STANDARD.encode(encrypted_item.ciphertext)),
            encryption_nonce: Opaque::new(BASE64_STANDARD.encode(encrypted_item.encryption_nonce)),
            encrypted_symmetric_key: Opaque::new(
                BASE64_STANDARD.encode(encrypted_item.encrypted_symmetric_key),
            ),
            signature: Opaque::new(bad_signature),
        };
        let result = request_body.try_into_domain(account);
        assert!(matches!(
            result,
            Err(CreateItemRequestMappingError::SignatureFormat(_))
        ));
    }
}
