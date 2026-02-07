use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddSecretRequest {
    pub name: String,
    pub secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RenameSecretRequest {
    pub current_name: String,
    pub new_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoveSecretRequest {
    pub secret_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AclSecretRequest {
    AllowHost { secret: String, host: String },
    RemoveHost { secret: String, host: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AclBySecretRequest {
    pub secret: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetSecretRequest {
    pub recipient: String,
    pub secret: String,
}
