use dotenv::dotenv;
use std::{env, time::Duration};

use sqlx::{postgres::PgPoolOptions, PgPool};

#[derive(Debug)]
pub struct Database {
    pub pool: PgPool,
}

impl Database {
    pub async fn init() -> Self {
        dotenv().ok();
        let url = env::var("DATABASE_URL").expect("Could not fetch DB URL");
        let pool = Database::create_db_pool(&url).await;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Could not migrate Database");

        Database { pool }
    }

    pub async fn create_db_pool(url: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(3))
            .connect(url)
            .await
            .expect(format!("Can't connect to database - {}", url.to_string()).as_str())
    }
}
