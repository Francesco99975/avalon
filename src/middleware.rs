use axum::{extract::Request, middleware::Next, response::Response};

use crate::errors::HttpError;

// pub async fn is_authenticated<T>(cookie_jar: CookieJar,mut req: Request<T>, next: Next) -> Result<Response, HttpError> {
//   let token = req.headers().typed_get()::<Authori>
// }
