# Specifications for MyPass project

## Overview

MyPass is a password management application designed to securely store and manage user passwords or other sensitive information. This document outlines the specifications for the MyPass project, including features, requirements, and design considerations.

## User Stories

1. As a user, I want to sign up for an account with an email and a password, on successful signup I should receive a verification email.
2. As a signed up user, I want to verify my email address by clicking on a link in the verification email.
3. As a user, I want to log in to my account using my verified email and password.
4. As a logged in and non verified user, I want to ask for a new verification email if the previous one has expired.
5. As a logged in verified user, I want to manage my vault:
    - add new items,
    - edit existing items,
    - delete items,
    - view a list of all items in my vault.

## Constraints

- The application must use end-to-end encryption to ensure that user data is secure.


## Cryptography schemes

- Password and key derivation: Argon2id,
- Symmetric encryption (with authentication): AES-256-GCM,
- Message authentication: HMAC-SHA3-256,
- Asymmetric encryption: Ed25519 curve with EdDSA signature scheme.

## Implementation of the user stories

In each of the following sections, the implementation details for each user story are described. The description contains a client and server part. The client part describes the operations that are performed on the client side (e.g., in the browser or mobile app), while the server part describes the operations that are performed on the server side (e.g., in the backend API).

### 1. User Signup

**Client Side:**

- The user fills out a signup form with their email and password,
- The client generates a random salt and uses Argon2id to derive a Ed25519 key pair from the password and salt,
- The client generates a random salt for symmetric key derivation,
- The client uses Argon2id to derive a symmetric key from the password and the salt,
- The client symmetrically encrypts the private key using AES-256-GCM with the derived symmetric key,
- The client sends the email, password, the encrypted private key, the derivation key salt and the public key to the server using the endpoint described below.

**Server Side:**

Endpoint: `POST /api/signup` with request body:
```json
{
  "email": "<user_email>",
  "password": "<user_password>",
  "encryptedPrivateKey": "<user_encrypted_private_key>",
  "symmetricKeySalt": "<salt_for_symmetric_key_derivation>",
  "publicKey": "<user_public_key>",
}
```

Handler logic:
1. Validate the email, password, encrypted private key, salt, public key format,
2. Decrypts the private key using the password and the salt to verify the provided public key matches the derived public key,
3. Hashes the password using Argon2id,
4. Generates a random verification token, it is valid for 15 minutes,
5. Stores in database:
    - the account with email, hashed password, encrypted private key, salt for symmetric key derivation, public key,
    - the verification ticket containing the token, associated with the account,
6. Sends a verification email to the user with a link containing the verification token.

Remarks:
- The server never stores or logs the plaintext password or encrypted private key.

Response:
- On success: HTTP 201 Created,
- On failure: appropriate HTTP error code with message.

### 2. Email Verification

**Client Side:**
- The user clicks on the verification link in the email, which contains the verification token,
- The client sends a request to the server with the email and the token using the endpoint described below.

## Server Side:

Endpoint `POST /api/verification-tickets/verify` with request body:
```json
{
  "email": "<user_email>",
  "token": "<verification_token>"
}
```

Handler logic:
1. Validate the email and token format,
2. Retrieve the verification ticket and the account associated with the email from the database,
3. Check if the token is valid and not expired,
4. If valid, updates in database:
    - the account to mark the email as verified,
    - register the time of verification of the ticket,
5. If invalid, returns an error.

Remarks:
- The verification token is not logged.

Response:
- On success: HTTP 200 OK,
- On failure: appropriate HTTP error code with message.

### 3. User Login

**Client Side:**
- The user fills out a login form with their email and password,
- The client sends the email and password to the server using the endpoint described below,
- Upon receiving the response, the client receives:
    - the JWT access token,
    - the encrypted private key,
    - the salt for symmetric key derivation,
- The client uses the password and the salt to derive the symmetric key using Argon2id,
- The client decrypts the private key using the derived symmetric key,
- The private key and access token are stored in memory for the session.

**Server Side:**

Endpoint: `POST /api/login` with request body:
```json
{
  "email": "<user_email>",
  "password": "<user_password>"
}
```

Handler logic:
1. Validate the email and password format,
2. Retrieve the account associated with the email from the database,
3. Verify the password against the stored hashed password using Argon2id,
4. If the password is correct, generates a JWT access token with the following claims:
    - sub: account ID,
    - iat: issued at timestamp,
    - exp: expiration timestamp: 1 hour from issuance,
4. Signs the JWT access token using HMAC-SHA3-256 with a server-side secret key,
5. Returns to the client:
    - the JWT access token,
    - the encrypted private key,
    - the salt for symmetric key derivation.

Remarks:
- The server never stores or logs the plaintext password or encrypted private key.

Response:
- On success: HTTP 200 OK with response body:
```json
{
  "accessToken": "<jwt_access_token>",
  "encryptedPrivateKey": "<user_encrypted_private_key>",
  "symmetricKeySalt": "<salt_for_symmetric_key_derivation>"
}
```
- On failure: appropriate HTTP error code with message.


### 4. Resend Verification Email

**Client Side:**
- The user must be logged in but not verified,
- Using the access token, the client sends an authorized request to the server using the endpoint described below.

**Server Side:**
Endpoint: `POST /api/verification-tickets/resend` with Authorization header:
```Authorization: Bearer <jwt_access_token>```

Handler logic:
1. Validate the JWT access token,
2. Retrieve the account associated with the token from the database,
3. Retrieve the last verification ticket associated with the account,
4. Check if the account is not verified,
5. Check if the last ticket has not been sent less than 5 minutes ago,
6. Generate a new verification token, it is valid for 15 minutes,
7. In database:
    - if previous verification ticket exists and is still valid, update its invalidation timestamp,
    - creates a new verification ticket with the new token and the current timestamp,
8. Sends a verification email to the user with a link containing the new verification token.

Response:
- On success: HTTP 200 OK,
- On failure: appropriate HTTP error code with message.

### 5. Vault Management - Item creation

**Client Side:**
- The user must be logged in and verified,
- The client encrypts the item data before sending it to the server:
    1. Derives a shared using X25519 key exchange between an ephemeral key pair and the user's public key:
        1. Generates a random Ed25519 secret key,
        2. Generates the corresponding ephemeral public key,
        3. Computes the shared key as: shared key = secret * user's public key,
    2. Hashes the shared key `x` coordinate using SHA3-256,
    3. Generates a random key derivation salt,
    4. Uses Argon2id to derive a symmetric key from the hashed shared key and the salt,
    5. Symmetrically encrypts the item data using AES-256-GCM with the derived symmetric key,
- The client signes the ciphertext using the Ed25519 secret key,
- The client sends the signature, the cyphertext, ephemeral public key and key derivation salt to the server using the endpoint described below.

**Server Side:**
Endpoint: `POST /api/items` with Authorization header and request body:
```Authorization: Bearer <jwt_access_token>```
```json
{
  "ciphertext": "<item_ciphertext>",
  "ephemeralPublicKey": "<ephemeral_public_key>",
  "keyDerivationSalt": "<key_derivation_salt>",
  "signature": "<item_signature>"
}
```

Handler logic:
1. Validate the JWT access token,
2. Retrieve the account associated with the token from the database,
3. Validate the ciphertext, ephemeral public key and key derivation salt format,
3. Validate the signature using the account public key,
4. Store in database:
    - the item with ciphertext, ephemeral public key, key derivation salt, associated with the account.
