use actix_web::{post, web};
use serde::{Deserialize, Serialize};

use crate::auth::jwt;
use crate::database;
use mongodb::bson::doc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
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
    let users_collection = database::get()
        .await
        .collection::<mongodb::bson::Document>("users");

    let user_password = user.password.clone();
    let user_data = user.into_inner();

    let user_find = users_collection
        .find_one(doc! {"username": &user_data.username})
        .await
        .unwrap();

    if user_find.is_none() {
        return actix_web::HttpResponse::NotFound().body(
            doc! {
                "message": "User doesn't exists or password is incorrect"
            }
            .to_string(),
        );
    }

    let user_document = user_find.unwrap();
    let password_hash = user_document.get_str("password").unwrap();

    let parsed_hash = PasswordHash::new(password_hash).expect("Invalid password hash format");

    if !Argon2::default()
        .verify_password(user_password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        return actix_web::HttpResponse::Forbidden().body(
            doc! {
                "message": "User doesn't exists or password is incorrect"
            }
            .to_string(),
        );
    }

    let username = user_document.get_str("username").unwrap();

    return actix_web::HttpResponse::Ok().body(
        doc! {
            "token": jwt::generate_token(username).unwrap(),
        }
        .to_string(),
    );
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
        return actix_web::HttpResponse::Conflict().body(
            doc! {
                "message": "User already exists"
            }
            .to_string(),
        );
    }

    let result = users_collection
        .insert_one(doc! {
            "username": &user_data.username,
            "password": hash_password(&user_data.password),
        })
        .await
        .unwrap();

    if result.inserted_id == mongodb::bson::Bson::Null {
        return actix_web::HttpResponse::InternalServerError().body(
            doc! {
                "message": "Failed to register user"
            }
            .to_string(),
        );
    }

    actix_web::HttpResponse::Created().body(
        doc! {
            "message": "User registered successfully"
        }
        .to_string(),
    )
}

pub fn auth_scope() -> impl actix_web::dev::HttpServiceFactory {
    web::scope("/auth").service(login).service(register)
}
