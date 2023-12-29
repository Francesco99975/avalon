use std::error::Error;

use serde::{Deserialize, Serialize};
use sqlx::{types::chrono::Utc, PgPool, Row};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignupPayload {
    pub user_id: String,
    pub device_id: String,
    pub publickey: String,
}

pub async fn create_user(payload: &SignupPayload, pool: &PgPool) -> Result<(), Box<dyn Error>> {
    let mut txn = pool.begin().await?;

    let query_user = "INSERT INTO users(id, publickey, created) VALUES ($1, $2, $3)";
    let query_device = "INSERT INTO devices(id, userId, created) VALUES ($1, $2, $3)";

    let timespamp = Utc::now();

    sqlx::query(query_user)
        .bind(&payload.user_id)
        .bind(&payload.publickey)
        .bind(timespamp)
        .execute(&mut *txn)
        .await?;

    sqlx::query(query_device)
        .bind(&payload.device_id)
        .bind(&payload.user_id)
        .bind(timespamp)
        .execute(&mut *txn)
        .await?;

    txn.commit().await?;

    Ok(())
}

pub async fn get_publickey(id: &str, pool: &PgPool) -> Result<String, Box<dyn Error>> {
    let mut txn = pool.begin().await?;

    let q = "SELECT publickey FROM users WHERE id=$1";

    let query = sqlx::query(q).bind(id);

    let row = query.fetch_one(&mut *txn).await?;

    let publickey = row.get("publickey");

    txn.commit().await?;

    Ok(publickey)
}

async fn get_user_devices(user_id: &str, pool: &PgPool) -> Result<Vec<String>, Box<dyn Error>> {
    let mut txn = pool.begin().await?;
    let q = "SELECT id FROM devices WHERE userId=$1";

    let query = sqlx::query(q).bind(user_id);

    let rows = query.fetch_all(&mut *txn).await?;

    let user_devices: Vec<String> = rows.iter().map(|row| row.get("id")).collect();

    txn.commit().await?;

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
pub struct BasicResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JWT {
    pub token: String,
}
