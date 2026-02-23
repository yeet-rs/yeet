use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use parking_lot::RwLock;

use crate::{
    httpsig::{HttpSig, VerifiedJson},
    state::{AppState, StateError},
};

/// Inquire if you (current system) are allowed to detach your own system
/// If you are an admin and want to see if hosts are allowed to detach, use the hosts api
pub async fn is_detach_allowed(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
) -> Result<Json<bool>, StateError> {
    let state = state.read_arc();
    Ok(Json(state.is_detach_allowed(&key)?))
}

pub async fn is_detach_global_allowed(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
) -> Result<Json<bool>, StateError> {
    let state = state.read_arc();
    state.auth_admin(&key)?;
    Ok(Json(state.get_global_detach_permission()))
}

/// Set the detach permission either Global or PerHost. PerHost will always take over the global setting
pub async fn set_detach_permission(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(set_detach): VerifiedJson<api::SetDetachPermission>,
) -> Result<StatusCode, StateError> {
    let mut state = state.write_arc();
    state.auth_admin(&key)?;

    match set_detach {
        api::SetDetachPermission::Global(allowed) => state.set_global_detach_permission(allowed),
        api::SetDetachPermission::PerHost(items) => state.set_detach_permissions(items),
    }

    Ok(StatusCode::OK)
}

/// Detach either self or another host(requires admin)
pub async fn detach_host(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(key): HttpSig,
    VerifiedJson(detach): VerifiedJson<api::DetachAction>,
) -> Result<StatusCode, StateError> {
    let mut state = state.write_arc();

    match detach {
        api::DetachAction::DetachSelf => state.detach_self(&key)?,
        // api::DetachAction::DetachHost(hostname) => state.detach_host(&hostname)?,
        api::DetachAction::AttachSelf => state.attach_self(&key)?,
        api::DetachAction::AttachHost(hostname) => state.attach_host(&hostname)?,
    }

    Ok(StatusCode::OK)
}
