use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{types::chrono::Utc, PgPool, Row};
use uuid::Uuid;

use crate::{crypto::hash, errors::HttpError};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignupPayload {
    pub device_id: String,
    pub publickey: String,
}

pub async fn create_user(payload: &SignupPayload, pool: &PgPool) -> Result<String, HttpError> {
    let mut txn = pool.begin().await.map_err(|err| HttpError {
        message: format!(
            "Could not start DB Transaction for User creation - {}",
            err.to_string()
        ),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    let query_user = "INSERT INTO users(id, publickey, created) VALUES ($1, $2, $3)";
    let query_device = "INSERT INTO devices(id, userId, created) VALUES ($1, $2, $3)";

    let user_id = Uuid::new_v4().to_string();
    let hashed_device_id = hash(payload.device_id.as_bytes())?;
    let timespamp = Utc::now();

    sqlx::query(query_user)
        .bind(&user_id)
        .bind(&payload.publickey)
        .bind(timespamp)
        .execute(&mut *txn)
        .await
        .map_err(|err| HttpError {
            message: format!("Could not create user - {}", err.to_string()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: Some(50),
        })?;

    sqlx::query(query_device)
        .bind(&hashed_device_id)
        .bind(&user_id)
        .bind(timespamp)
        .execute(&mut *txn)
        .await
        .map_err(|err| HttpError {
            message: format!("Could not create device for user - {}", err.to_string()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: Some(50),
        })?;

    txn.commit().await.map_err(|err| HttpError {
        message: format!(
            "Could not commit DB Transaction for user creation - {}",
            err.to_string()
        ),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    Ok(user_id)
}

pub async fn get_publickey(id: &str, pool: &PgPool) -> Result<String, HttpError> {
    let mut txn = pool.begin().await.map_err(|err| HttpError {
        message: format!(
            "Could not start DB Transaction for get publickey - {}",
            err.to_string()
        ),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    let q = "SELECT publickey FROM users WHERE id=$1";

    let query = sqlx::query(q).bind(id);

    let row = query.fetch_one(&mut *txn).await.map_err(|err| HttpError {
        message: format!("Could not fetch public key - {}", err.to_string()),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    let publickey = row.get("publickey");

    txn.commit().await.map_err(|err| HttpError {
        message: format!(
            "Could not commit DB Transaction for get publickey - {}",
            err.to_string()
        ),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    Ok(publickey)
}

pub async fn get_user_devices(user_id: &str, pool: &PgPool) -> Result<Vec<String>, HttpError> {
    let mut txn = pool.begin().await.map_err(|err| HttpError {
        message: format!(
            "Could not start DB Transaction for get user devices - {}",
            err.to_string()
        ),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;
    let q = "SELECT id FROM devices WHERE userId=$1";

    let query = sqlx::query(q).bind(user_id);

    let rows = query.fetch_all(&mut *txn).await.map_err(|err| HttpError {
        message: format!("Could not fetch user devices - {}", err.to_string()),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    let user_devices: Vec<String> = rows.iter().map(|row| row.get("id")).collect();

    txn.commit().await.map_err(|err| HttpError {
        message: format!(
            "Could not commit DB Transaction for get user devices - {}",
            err.to_string()
        ),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: Some(50),
    })?;

    Ok(user_devices)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginPayload {
    pub user_id: String,
    pub device_id: String,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResponse {
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JWT {
    pub token: String,
}
