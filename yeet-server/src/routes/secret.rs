use std::{collections::HashMap, sync::Arc};

use axum::{Json, extract::State, http::StatusCode};
use parking_lot::RwLock;

use crate::{
    httpsig::{HttpSig, VerifiedJson},
    state::{AppState, StateError},
};

pub async fn add_secret(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::AddSecretRequest { name, secret }): VerifiedJson<api::AddSecretRequest>,
) -> Result<StatusCode, StateError> {
    let mut state = state.write_arc();
    state.auth_admin(&key)?;
    state.add_secret(name, secret)?;
    Ok(StatusCode::OK)
}

pub async fn rename_secret(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::RenameSecretRequest {
        current_name,
        new_name,
    }): VerifiedJson<api::RenameSecretRequest>,
) -> Result<StatusCode, StateError> {
    let mut state = state.write_arc();
    state.auth_admin(&key)?;
    state.rename_secret(current_name, new_name);
    Ok(StatusCode::OK)
}

pub async fn remove_secret(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::RemoveSecretRequest { secret_name }): VerifiedJson<api::RemoveSecretRequest>,
) -> Result<StatusCode, StateError> {
    let mut state = state.write_arc();
    state.auth_admin(&key)?;
    state.remove_secret(secret_name);
    Ok(StatusCode::OK)
}

pub async fn set_acl(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(acl): VerifiedJson<api::AclSecretRequest>,
) -> Result<StatusCode, StateError> {
    let mut state = state.write_arc();
    state.auth_admin(&key)?;
    match acl {
        api::AclSecretRequest::AllowHost { secret, host } => {
            state.secret_add_access_for(secret, host);
        }
        api::AclSecretRequest::RemoveHost { secret, host } => {
            state.secret_remove_access_for(secret, host);
        }
    }
    Ok(StatusCode::OK)
}

pub async fn get_all_acl(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
) -> Result<Json<HashMap<String, Vec<String>>>, StateError> {
    let state = state.read_arc();
    state.auth_admin(&key)?;
    Ok(Json(state.get_all_acl()))
}

pub async fn get_acl_by_secret(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::AclBySecretRequest { secret }): VerifiedJson<api::AclBySecretRequest>,
) -> Result<Json<Vec<String>>, StateError> {
    let state = state.read_arc();
    state.auth_admin(&key)?;
    Ok(Json(state.get_acl_by_secret(secret)))
}

pub async fn list(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
) -> Result<Json<Vec<String>>, StateError> {
    let state = state.read_arc();
    state.auth_admin(&key)?;
    Ok(Json(state.list_secrets()))
}

pub async fn get_server_recipient(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(_key): HttpSig,
) -> Result<Json<String>, StateError> {
    let state = state.read_arc();
    Ok(Json(state.get_server_recipient()?))
}

pub async fn get_secret(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::GetSecretRequest { secret, recipient }): VerifiedJson<api::GetSecretRequest>,
) -> Result<Json<Option<Vec<u8>>>, StateError> {
    let state = state.read_arc();
    Ok(Json(state.get_secret(secret, recipient, &key)?))
}
