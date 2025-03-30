use crate::services::users::User;
use actix_web::{get, web};
use futures::StreamExt;
use mongodb::bson::doc;
use serde_json::json;

#[get("/")]
async fn get_users(req: actix_web::HttpRequest) -> impl actix_web::Responder {
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(token) = auth_header.to_str() {
            let scopes: Vec<String> = Vec::new();

            let auth = User::authenticate(token, scopes).await;

            if auth.is_ok() {
                let users_collection = crate::database::get()
                    .await
                    .collection::<mongodb::bson::Document>("users");

                let user_find_result = users_collection.find(doc! {}).await;

                let mut users = Vec::new();

                if let Ok(mut user_find) = user_find_result {
                    while let Some(user_document) = user_find.next().await {
                        if let Ok(user_document) = user_document {
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

                            users.push(json!({
                                "username": username,
                                "scopes": scopes,
                            }))
                        }
                    }
                }

                return actix_web::HttpResponse::Ok().json(json!({
                    "users": users,
                }));
            }
        }
    }

    actix_web::HttpResponse::Unauthorized().json(json!({
        "message": "Unauthorized"
    }))
}

pub fn users_collection() -> impl actix_web::dev::HttpServiceFactory {
    web::scope("/users").service(get_users)
}
