use actix_web::{post, web};
use serde::{Deserialize, Serialize};

use crate::database;
use mongodb::bson::doc;

use argon2::{
    Argon2,
    password_hash::{
        // PasswordHash,
        PasswordHasher,
        // PasswordVerifier,
        SaltString,
        rand_core::OsRng,
    },
};

#[derive(Deserialize, Serialize)]
struct User {
    username: String,
    password: String,
}

fn hash_password(password: &str) -> String {
    let bytes_password = password.as_bytes();

    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(bytes_password, &salt)
        .expect("Failed to hash password");

    password_hash.to_string()
}

#[post("/login")]
async fn login(user: web::Json<User>) -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().json(user.into_inner())
}

#[post("/register")]
async fn register(user: web::Json<User>) -> impl actix_web::Responder {
    let users_collection = database::get().await.collection("users");

    let user_data = user.into_inner();

    let existing_user = users_collection
        .find_one(doc! { "username": &user_data.username })
        .await
        .unwrap();

    if existing_user.is_some() {
        return actix_web::HttpResponse::Conflict().body("User already exists");
    }

    let result = users_collection
        .insert_one(doc! {
            "username": &user_data.username,
            "password": hash_password(&user_data.password),
        })
        .await
        .unwrap();

    if result.inserted_id == mongodb::bson::Bson::Null {
        return actix_web::HttpResponse::InternalServerError().body("Failed to register user");
    }

    actix_web::HttpResponse::Created().body("User registered successfully")
}

pub fn auth_scope() -> impl actix_web::dev::HttpServiceFactory {
    web::scope("/auth").service(login).service(register)
}
