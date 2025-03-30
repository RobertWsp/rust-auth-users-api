use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, get};

mod auth;
mod database;
mod routes;
mod services;

use dotenvy::dotenv;
use routes::{auth::auth_scope, users::users_collection};

#[get("/")]
async fn hellow_world() -> impl Responder {
    HttpResponse::Ok().body("Hello World")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    println!("Starting HTTP server on 127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header(),
            )
            .service(auth_scope())
            .service(users_collection())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
