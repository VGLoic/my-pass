use anyhow::anyhow;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::Salt};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use fake::{Dummy, Fake, faker, rand};
use serde::{Deserialize, Serialize};
use sqlx::{Database, Decode, Encode, Type};
use std::fmt::Debug;
use validator::ValidateEmail;

// #######################################################
// #################### OPAQUE STRING ####################
// #######################################################

/// This type is meant to be used to wrap sensitive strings.
/// It will prevent accidental logging or displaying of the inner value.
/// The inner value can still be accessed via the `unsafe_inner` method.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Opaque<T>(T)
where
    T: Clone + Serialize;

impl<T> Opaque<T>
where
    T: Clone + Serialize,
{
    pub fn new(v: T) -> Self {
        Self(v)
    }

    /// Reference the inner value
    /// Use it with caution
    pub fn unsafe_inner(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Opaque<T>
where
    T: Clone + Serialize,
{
    fn from(v: T) -> Self {
        Self::new(v)
    }
}

impl<T> std::fmt::Display for Opaque<T>
where
    T: Clone + Serialize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "*********")
    }
}

impl<T> Debug for Opaque<T>
where
    T: Clone + Serialize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "*********")
    }
}

impl<DB, T> Type<DB> for Opaque<T>
where
    DB: Database,
    String: Type<DB>,
    T: Clone + Serialize + Type<DB>,
{
    fn type_info() -> DB::TypeInfo {
        T::type_info()
    }
}

impl<'q, DB, T> Encode<'q, DB> for Opaque<T>
where
    DB: Database,
    String: Encode<'q, DB>,
    T: Clone + Serialize + Encode<'q, DB>,
{
    // Required method
    fn encode_by_ref(
        &self,
        buf: &mut <DB as Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        <T as Encode<'q, DB>>::encode_by_ref(self.unsafe_inner(), buf)
    }
}

impl<'r, DB: Database, T> Decode<'r, DB> for Opaque<T>
where
    // we want to delegate some of the work to string decoding so let's make sure strings
    // are supported by the database
    &'r str: Decode<'r, DB>,
    T: Clone + Serialize + Decode<'r, DB>,
{
    fn decode(
        value: <DB as Database>::ValueRef<'r>,
    ) -> Result<Opaque<T>, Box<dyn std::error::Error + 'static + Send + Sync>> {
        // the interface of ValueRef is largely unstable at the moment
        // so this is not directly implementable

        // however, you can delegate to a type that matches the format of the type you want
        // to decode (such as a UTF-8 string)

        let value = <T as Decode<DB>>::decode(value)?;

        Ok(Opaque(value))
    }
}

// ###############################################
// #################### EMAIL ####################
// ###############################################

/// This type is meant to be used internally and in outgoing IO responses
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Email(String);

#[derive(Debug)]
pub enum EmailError {
    Empty,
    InvalidFormat,
}
impl Email {
    /// Creates a new `Email` instance after validating the input string.
    ///
    /// # Arguments
    ///
    /// * `v` - A string slice that holds the email address to be validated and stored.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` if the input is a non-empty, valid email address (case-insensitive, stored in lowercase).
    /// * `Err(EmailError::Empty)` if the input is empty or only whitespace.
    /// * `Err(EmailError::InvalidFormat)` if the input does not match a valid email format.
    ///
    /// # Examples
    ///
    /// ```
    /// # use my_pass::newtypes::Email;
    /// let email = Email::new("user@example.com");
    /// assert!(email.is_ok());
    /// ```
    pub fn new(v: &str) -> Result<Self, EmailError> {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return Err(EmailError::Empty);
        }
        if !trimmed.validate_email() {
            return Err(EmailError::InvalidFormat);
        }
        Ok(Self(trimmed.to_lowercase()))
    }

    /// Creates a new `Email` instance without validating the input string.
    ///
    /// # Arguments
    ///
    /// * `v` - A string slice that holds the email address to be stored.
    ///
    /// # Safety
    ///
    /// This method does not perform any validation on the input. It is the caller's responsibility
    /// to ensure that the provided string is a valid email address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use my_pass::newtypes::Email;
    /// let email = Email::new_unchecked("user@example.com");
    /// ```
    pub fn new_unchecked(v: &str) -> Self {
        Self(v.to_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Email {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<DB> sqlx::Type<DB> for Email
where
    DB: Database,
    String: sqlx::Type<DB>,
{
    fn type_info() -> DB::TypeInfo {
        String::type_info()
    }
}

impl<'q, DB> Encode<'q, DB> for Email
where
    DB: Database,
    String: Encode<'q, DB>,
{
    // Required method
    fn encode_by_ref(
        &self,
        buf: &mut <DB as Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        <String as Encode<'q, DB>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r, DB: Database> Decode<'r, DB> for Email
where
    // we want to delegate some of the work to string decoding so let's make sure strings
    // are supported by the database
    &'r str: Decode<'r, DB>,
{
    fn decode(
        value: <DB as Database>::ValueRef<'r>,
    ) -> Result<Email, Box<dyn std::error::Error + 'static + Send + Sync>> {
        // the interface of ValueRef is largely unstable at the moment
        // so this is not directly implementable

        // however, you can delegate to a type that matches the format of the type you want
        // to decode (such as a UTF-8 string)

        let value = <&str as Decode<DB>>::decode(value)?;

        Ok(Email::new_unchecked(value))
    }
}

impl<T> Dummy<T> for Email {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        let email: String = faker::internet::en::SafeEmail().fake_with_rng(rng);
        Email::new(&email).unwrap()
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ##################################################
// #################### PASSWORD ####################
// ##################################################

/// This type is meant to be used internally and outgoing IO responses
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

#[derive(Debug)]
pub enum PasswordError {
    Empty,
    InvalidPassword(String),
}

impl Password {
    /// Creates a new `Password` instance after validating the provided string.
    ///
    /// # Arguments
    ///
    /// * `v` - A string slice representing the password to validate and wrap.
    ///
    /// # Validation Rules
    ///
    /// - Password must not be empty.
    /// - Password length must be at least 10 characters and at most 40 characters.
    /// - Password must contain at least two uppercase letters.
    /// - Password must contain at least two numbers.
    /// - Password must contain at least two special characters (characters that are not letters or numbers).
    ///
    /// # Errors
    ///
    /// Returns a `PasswordError` if any of the validation rules are not met:
    /// - `PasswordError::Empty` if the password is empty.
    /// - `PasswordError::InvalidPassword` with a descriptive message if any other rule is violated.
    pub fn new(v: &str) -> Result<Self, PasswordError> {
        if v.is_empty() {
            return Err(PasswordError::Empty);
        }
        // Password must be at least 10 characters long, at most 40 characters long
        let password_has_valid_length = v.len() >= 10 && v.len() <= 40;
        // Password must contain:
        //  - at least two capital letters,
        //  - at least two numbers,
        //  - at least two special characters (not number nor letter)
        let mut uppercase_count = 0;
        let mut number_count = 0;
        let mut special_count = 0;

        for c in v.chars() {
            if c.is_ascii_uppercase() {
                uppercase_count += 1;
            } else if c.is_ascii_digit() {
                number_count += 1;
            } else if !c.is_ascii_alphanumeric() {
                special_count += 1;
            }
        }

        // Check all conditions without early return to prevent timing attacks
        let has_uppercase = uppercase_count >= 2;
        let has_numbers = number_count >= 2;
        let has_special = special_count >= 2;

        if !password_has_valid_length {
            return Err(PasswordError::InvalidPassword(
                "password length must be at least 10 characters and at most 40 characters"
                    .to_string(),
            ));
        }

        if !has_uppercase {
            return Err(PasswordError::InvalidPassword(
                "password must contain at least two uppercase letters".to_string(),
            ));
        }
        if !has_numbers {
            return Err(PasswordError::InvalidPassword(
                "password must contain at least two numbers".to_string(),
            ));
        }
        if !has_special {
            return Err(PasswordError::InvalidPassword(
                "password must contain at least two special characters".to_string(),
            ));
        }

        Ok(Password(v.to_string()))
    }

    /// Hash a password using the Argon2id algorithm. The returned string is a argon2-formatted hash.
    ///
    /// # Arguments
    /// * `password` - Password to hash
    pub fn hash(&self) -> Result<String, anyhow::Error> {
        let salt: [u8; 16] = rand::random();
        let base64_salt = BASE64_STANDARD_NO_PAD.encode(salt);
        let argon_salt = Salt::from_b64(&base64_salt).map_err(|e| {
            anyhow!(e).context("failed to build Salt struct from base64 salt string")
        })?;
        Argon2::default()
            .hash_password(self.0.as_bytes(), argon_salt)
            .map_err(|e| anyhow!(e).context("failed to hash password"))
            .map(|v| v.to_string())
    }

    /// Verify a password validity against an Argon2id formatted key
    ///
    /// # Arguments
    /// * `password` - Password to hash
    /// * `password_hash` - Argon2id formatted hash to verify against
    pub fn verify(&self, password_hash: &str) -> Result<(), anyhow::Error> {
        let password_hash = PasswordHash::new(password_hash).map_err(|e| {
            anyhow!(e).context("failed to build PasswordHash struct from raw string")
        })?;
        Argon2::default()
            .verify_password(self.0.as_bytes(), &password_hash)
            .map_err(|e| anyhow!(e).context("failed to verify password"))
    }

    /// Reference the inner value
    /// Use it with caution
    pub fn unsafe_inner(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "******")
    }
}

impl Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "******")
    }
}

impl<T> Dummy<T> for Password {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        let mut password: String = faker::internet::en::Password(10..40).fake_with_rng(rng);

        // Ensure the password meets the criteria by replacing the first few characters
        password.replace_range(0..2, "AB"); // at least two uppercase letters
        password.replace_range(2..4, "12"); // at least two numbers
        password.replace_range(4..6, "!@"); // at least two special characters

        Password(password)
    }
}
