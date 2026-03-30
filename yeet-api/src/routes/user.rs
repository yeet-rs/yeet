use std::fmt::Display;

use colored::Colorize as _;
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

impl std::fmt::Display for AuthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let colored = match self {
            AuthLevel::Admin => "Admin".red(),
            AuthLevel::Build => "Build".yellow(),
            AuthLevel::Osquery => "Osquery".blue(),
        };
        write!(f, "{colored}")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub id: UserID,
    pub key: VerifyingKey,
    pub username: String,
    pub level: AuthLevel,
    pub all_tag: bool,
    /// These are not tags associated with the user but rather tags that the user has access to
    pub tags: Vec<crate::tag::Tag>,
}
impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}): ", self.username, crate::hash_hex(self.key))?;
        write!(f, "{}", self.level)?;

        if self.all_tag {
            write!(f, "{}", " (ALL TAG)".red().bold())
        } else {
            let tags = {
                let tags = self.tags.iter().map(|tag| tag.name.as_str());
                if tags.len() == 0 {
                    "<no tags>".italic()
                } else {
                    tags.fold(String::new(), |acc, x| format!("{acc}#{x} "))
                        .italic()
                }
            };

            write!(f, " {tags}")
        }
    }
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
