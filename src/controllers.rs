use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;

use axum::extract::Json;

use crate::errors::HttpError;
use crate::models::{create_user, BasicResponse, SignupPayload};
use crate::AvalonState;

pub async fn signup(
    Extension(state): Extension<Arc<AvalonState>>,
    Json(payload): Json<SignupPayload>,
) -> Result<Json<BasicResponse>, HttpError> {
    let pool = state.db.pool.clone();

    create_user(&payload, &pool)
        .await
        .map_err(|err| HttpError {
            message: format!("Could not create user: {}", err.to_string()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_code: Some(50),
        })?;

    Ok(axum::Json(BasicResponse {
        message: format!("You did successfully signed up!"),
    }))
}
