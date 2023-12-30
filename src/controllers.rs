use std::sync::Arc;

use axum::Extension;

use axum::extract::Json;
use axum::http::StatusCode;

use crate::crypto::{authenticate, generate_jwt_token, verify};
use crate::errors::HttpError;
use crate::models::{
    create_user, get_publickey, get_user_devices, LoginPayload, RegisterResponse, SignupPayload,
    JWT,
};
use crate::AvalonState;

pub async fn signup(
    Extension(state): Extension<Arc<AvalonState>>,
    Json(payload): Json<SignupPayload>,
) -> Result<Json<RegisterResponse>, HttpError> {
    tracing::debug!("Payload Signup: {:?}", payload);

    let pool = state.db.pool.clone();

    let user_id = create_user(&payload, &pool).await?;

    Ok(axum::Json(RegisterResponse { user_id }))
}

pub async fn login(
    Extension(state): Extension<Arc<AvalonState>>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<JWT>, HttpError> {
    tracing::debug!("Payload Login: {:?}", payload);

    let pool = state.db.pool.clone();

    let devices = get_user_devices(&payload.user_id, &pool).await?;

    let is_recognized = devices
        .iter()
        .any(|device| verify(payload.device_id.as_bytes(), &device).is_ok());

    if !is_recognized {
        return Err(HttpError {
            message: format!("Unauthorized Device"),
            status_code: StatusCode::UNAUTHORIZED,
            error_code: Some(41),
        });
    }

    let pubkey = get_publickey(&payload.user_id, &pool).await?;

    if !authenticate(&pubkey, &payload.signature, &payload.message)? {
        return Err(HttpError {
            message: format!("Unauthorized. Invalid Signature"),
            status_code: StatusCode::UNAUTHORIZED,
            error_code: Some(41),
        });
    }

    let token = generate_jwt_token(&payload.user_id)?;

    Ok(axum::Json(JWT { token }))
}
