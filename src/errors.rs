use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

#[derive(Debug)]
pub struct HttpError {
    pub message: String,
    pub status_code: StatusCode,
    pub error_code: Option<i8>,
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        let status_code = self.status_code;

        (
            status_code,
            [(header::CONTENT_TYPE, "application/json")],
            axum::Json(json!({
                "StatusCode": self.status_code.as_u16(),
                "ErrorCode": self.error_code,
                "Message": self.message
            })),
        )
            .into_response()
    }
}
