use ed25519_dalek::VerifyingKey;

use serde::{Deserialize, Serialize};

use crate::request;

crate::db_id!(UserID);
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateUser {
    pub key: VerifyingKey,
    pub level: AuthLevel,
    pub username: String,
    pub all_tag: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
pub enum AuthLevel {
    Build,
    Admin,
    Osquery,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub id: UserID,
    pub username: String,
    pub level: AuthLevel,
    /// These are not tags associated with the user but rather tags that the user has access to
    pub tags: Vec<crate::tag::Tag>,
}

request! (
    create_user(create_user: CreateUser),
    post("/user/create") -> UserID,
    body: &create_user
);

request! (
    list_users(),
    get("/user") -> Vec<User>
);

request! (
    rename_user(user: UserID, name: &str),
    put("/user/{user}/rename/{name}") -> StatusCode
);
