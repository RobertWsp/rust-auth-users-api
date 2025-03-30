use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{auth::jwt, database};

#[derive(Deserialize, Serialize, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
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

impl User {
    pub async fn create(username: String, password: String) -> actix_web::HttpResponse {
        let users_collection = database::get().await.collection("users");

        let existing_user = users_collection
            .find_one(doc! { "username": &username })
            .await
            .unwrap();

        if existing_user.is_some() {
            return actix_web::HttpResponse::Conflict().json(json! ({
                "message": "User already exists"
            }));
        }

        let result = users_collection
            .insert_one(doc! {
                "username": &username,
                "password": hash_password(&password),
            })
            .await
            .unwrap();

        if result.inserted_id == mongodb::bson::Bson::Null {
            return actix_web::HttpResponse::InternalServerError().json(json! ({
                "message": "Failed to register user"
            }));
        }

        return actix_web::HttpResponse::Created().json(json! ({
            "message": "User registered successfully"
        }));
    }

    pub async fn get_token_with_user_password(
        username: String,
        password: String,
    ) -> actix_web::HttpResponse {
        let users_collection = database::get()
            .await
            .collection::<mongodb::bson::Document>("users");

        let user_find = users_collection
            .find_one(doc! {"username": &username})
            .await
            .unwrap();

        if user_find.is_none() {
            return actix_web::HttpResponse::NotFound().json(json!({
                "message": "User doesn't exist or password is incorrect"
            }));
        }

        let user_document = user_find.unwrap();
        let password_hash = user_document.get_str("password").unwrap();

        let parsed_hash = PasswordHash::new(password_hash).expect("Invalid password hash format");

        if !Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            return actix_web::HttpResponse::Forbidden().json(json!({
                "message": "User doesn't exist or password is incorrect"
            }));
        }

        let username = user_document.get_str("username").unwrap();
        let scopes = user_document
            .get_array("scopes")
            .map(|scopes_array| {
                scopes_array
                    .iter()
                    .map(|scope| scope.as_str().unwrap().to_string())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(|_| vec![]);

        return actix_web::HttpResponse::Ok().json(json! ({
            "token": jwt::generate_token(username, scopes).unwrap(),
        }));
    }

    pub async fn authenticate(
        token: &str,
        required_scopes: Vec<String>,
    ) -> Result<Self, actix_web::HttpResponse> {
        let claims = jwt::validate_token(token);

        if claims.is_err() {
            return Err(actix_web::HttpResponse::Unauthorized().json(json!({
                "message": "Invalid token"
            })));
        }

        let claims = claims.unwrap();

        let users_collection = database::get()
            .await
            .collection::<mongodb::bson::Document>("users");

        let user_find = users_collection
            .find_one(doc! {"username": &claims.sub})
            .await
            .unwrap();

        let scopes = claims.scopes;

        if let Some(user_document) = user_find {
            let user_scopes = user_document
                .get_array("scopes")
                .map(|scopes_array| {
                    scopes_array
                        .iter()
                        .map(|scope| scope.as_str().unwrap().to_string())
                        .collect::<Vec<String>>()
                })
                .unwrap_or_else(|_| vec![]);

            if !required_scopes
                .iter()
                .all(|scope| user_scopes.contains(scope) && scopes.contains(scope))
            {
                return Err(actix_web::HttpResponse::Forbidden().json(json!({
                    "message": "Insufficient permissions"
                })));
            }

            Ok(Self {
                username: user_document.get_str("username").unwrap().to_string(),
                password: user_document.get_str("password").unwrap().to_string(),
            })
        } else {
            Err(actix_web::HttpResponse::NotFound().json(json!({
                "message": "User not found"
            })))
        }
    }
}
