use std::env;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::http::StatusCode;
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, Verifier, VerifyingKey};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::errors::HttpError;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub fn hash(password: &[u8]) -> Result<String, HttpError> {
    let argon2 = Argon2::default();

    match argon2.hash_password(password, &SaltString::generate(&mut OsRng)) {
        Ok(hashed_password) => Ok(hashed_password.to_string()),
        Err(err) => Err(HttpError {
            message: format!("Could not hash device ID - {}", err.to_string()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: Some(50),
        }),
    }
}

pub fn verify(password: &[u8], hash: &str) -> Result<(), HttpError> {
    let argon2 = Argon2::default();

    let parsed_hash = PasswordHash::new(hash).map_err(|err| HttpError {
        message: format!("Could not parse hash - {}", err.to_string()),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    argon2
        .verify_password(password, &parsed_hash)
        .map_err(|err| HttpError {
            message: format!("Hash verification failed - {}", err.to_string()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: Some(50),
        })?;

    Ok(())
}

pub fn authenticate(
    armored_public_key: &str,
    signature_bytes: &[u8],
    message_bytes: &[u8],
) -> Result<bool, HttpError> {
    let public_key =
        VerifyingKey::from_public_key_pem(&armored_public_key).map_err(|err| HttpError {
            message: format!("Authentication failed - {}", err.to_string()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: Some(50),
        })?;

    let mut exact_signauture_bytes: [u8; 64] = [0u8; 64];

    for index in 0..64 {
        exact_signauture_bytes[index] =
            signature_bytes.to_vec().pop().ok_or_else(|| HttpError {
                message: format!("Signature could not be parsed"),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                error_code: Some(50),
            })?;
    }
    exact_signauture_bytes.reverse();

    let signature = Signature::from_bytes(&exact_signauture_bytes);

    Ok(public_key.verify(message_bytes, &signature).is_ok())
}

pub fn generate_jwt_token(user_id: &str) -> Result<String, HttpError> {
    // Set your secret key for signing the token
    let secret = env::var("JWT_SCRET").map_err(|err| HttpError {
        message: format!("Could not get jwt secret from ENV - {}", err.to_string()),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    // Set the claims for the token
    let claims = Claims {
        sub: user_id.to_owned(),
        exp: 1_000_000_000, // Set the expiration time (in seconds since the Unix epoch)
    };

    // Set the algorithm to be used for signing the token
    let algorithm = Algorithm::HS512;

    // Encode the token
    let token = encode(
        &Header::new(algorithm),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|err| HttpError {
        message: format!("Could not generate jwt token - {}", err.to_string()),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    Ok(token)
}

pub fn validate_jwt(token: &str) -> Result<String, HttpError> {
    // Set your secret key for verifying the token
    let secret = env::var("JWT_SCRET").map_err(|err| HttpError {
        message: format!("Could not get jwt secret from ENV - {}", err.to_string()),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    // Set the algorithm used for signing the token
    let algorithm = Algorithm::HS512;

    // Set the key used for verifying the token
    let decoding_key = DecodingKey::from_secret(secret.as_ref());

    // Set the validation parameters
    let mut validation = Validation::new(algorithm);
    validation.set_required_spec_claims(&["exp"]);

    // Decode and validate the token
    let claims = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|err| HttpError {
            message: format!("Could not decode jwt token - {}", err.to_string()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: Some(50),
        })?
        .claims;

    Ok(claims.sub)
}
