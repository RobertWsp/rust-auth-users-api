use actix_web::{post, web};

use crate::services::users::User;

#[post("/login")]
async fn login(user: web::Json<User>) -> impl actix_web::Responder {
    let user_data = user.into_inner();

    let auth_token_resp =
        User::get_token_with_user_password(user_data.username, user_data.password).await;

    return auth_token_resp;
}

#[post("/register")]
async fn register(user: web::Json<User>) -> impl actix_web::Responder {
    return User::create(user.username.clone(), user.password.clone()).await;
}

pub fn auth_scope() -> impl actix_web::dev::HttpServiceFactory {
    web::scope("/auth").service(login).service(register)
}
