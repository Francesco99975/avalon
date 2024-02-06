mod controllers;
mod crypto;
mod db;
mod errors;
mod middleware;
mod models;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    routing::{get, post},
    Extension, Router,
};

use tower_http::trace::{self, TraceLayer};
use tracing::Level;

use crate::{
    controllers::{login, signup},
    db::Database,
};

struct AvalonState {
    pub db: Database,
}

#[tokio::main]
async fn main() {
    let shared_state = Arc::new(AvalonState {
        db: Database::init().await,
    });

    tracing_subscriber::fmt().with_target(false).pretty().init();
    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/api/v1/signup", post(signup))
        .route("/api/v1/login", post(login))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(trace::DefaultOnResponse::new().level(Level::DEBUG)),
        )
        .layer(Extension(shared_state));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    tracing::info!("listening on {}", 3001);

    // run our app with hyper, listening globally on port 3001
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => match axum::serve(listener, app.into_make_service()).await {
            Ok(_) => println!("Exited Gracefully"),
            Err(err) => panic!("Server Error: {}", err.to_string()),
        },
        Err(err) => panic!("Tcp Error: {}", err.to_string()),
    };
}
