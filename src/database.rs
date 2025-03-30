use mongodb::{Client, Database};

use std::env;

fn get_database_uri() -> String {
    env::var("MONGODB_URI").expect("MONGODB_URI não configurado")
}

pub async fn get() -> Database {
    let uri = get_database_uri();

    let client = Client::with_uri_str(&uri)
        .await
        .expect("Failed to initialize standalone client.");

    client.database("zaap")
}
