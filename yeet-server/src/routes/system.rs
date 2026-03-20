use axum::{Json, extract::State, http::StatusCode};

use crate::{
    YeetState, db,
    error::InternalError as _,
    httpsig::{HttpSig, VerifiedJson},
};

/// This is the "ping" command every client should send in a specific interval.
/// Based on the provision state and the last known version this function takes different parts
///
/// `host.latest_store_path()`
/// `host.provision_state`
///
/// `host.last_ping` = `Zoned::now`
///
/// ====== if `host.provision_state` == Provisioned
///
/// # this is the path when the client did the update
/// # if "host version is behind but sent version and provision version match"
/// if `host.latest_store_path()` != `store_path` and `store_path` == `host.provision_state`
///     `host.version_history.insert(store_path`, `Zoned::now`)
///     -> Nothing
///
/// # this is the path when the client gets notified of an update
/// # if "host AND sent version is behind but server version is different"
/// but because there could be a race condition e.g. Update1(v1) -> client does update1 in this time server gets Update2
/// therefore we need to check if sent version is behind server version
/// if `host.latest_store_path()` == `store_path` && `host.latest_store_path()` != `host.provision_state`
///     -> `SwitchTo(host.provision_state)`
///
/// # Lastly if all 3 are the same do nothing
/// -> Nothing
///
/// ====== if `host.provision_state` == Detached
///
/// # check if `store_path` is the same as `host.latest_store_path()` if not the update `host.latest_store_path()`
/// -> Detach
///
/// ====== if `host.provision_state` == `NotSet`
/// -> Nothing
pub async fn system_check(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::VersionRequest { store_path }): VerifiedJson<api::VersionRequest>,
) -> Result<Json<api::AgentAction>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };

    db::hosts::ping(&mut conn, host).await.internal_server()?;

    let state = db::hosts::fetch_provision_state(&mut conn, host)
        .await
        .internal_server()?;

    let action = match state {
        api::ProvisionState::NotSet => api::AgentAction::Nothing,
        // Host is detached -> only updated the latest version
        api::ProvisionState::Detached => {
            db::hosts::update_current_version(&mut conn, host, store_path)
                .await
                .internal_server()?;
            api::AgentAction::Detach
        }

        api::ProvisionState::Provisioned => {
            // first update the current version that is stored for the host
            db::hosts::update_current_version(&mut conn, host, store_path)
                .await
                .internal_server()?;

            // let see if there is still an update available
            let update = db::hosts::fetch_available_update(&mut conn, host)
                .await
                .internal_server()?;

            match update {
                Some(update) => api::AgentAction::SwitchTo(update),
                None => api::AgentAction::Nothing,
            }
        }
    };

    Ok(Json(action))
}

// TODO: currently there are no detach permissions
// all hosts are allowed to detach
// /// Inquire if you (current system) are allowed to detach your own system
// /// If you are an admin and want to see if hosts are allowed to detach, use the hosts api
// pub async fn is_detach_allowed(
//     State(state): State<Arc<RwLock<AppState>>>,
//     HttpSig(key): HttpSig,
// ) -> Result<Json<bool>, StateError> {
//     let state = state.read_arc();
//     Ok(Json(state.is_detach_allowed(&key)?))
// }

// /// Set the detach permission either Global or PerHost. PerHost will always take over the global setting
// pub async fn set_detach_permission(
//     State(state): State<Arc<RwLock<AppState>>>,
//     HttpSig(key): HttpSig,
//     VerifiedJson(set_detach): VerifiedJson<api::SetDetachPermission>,
// ) -> Result<StatusCode, StateError> {
//     let mut state = state.write_arc();
//     state.auth_admin(&key)?;

//     match set_detach {
//         api::SetDetachPermission::Global(allowed) => state.set_global_detach_permission(allowed),
//         api::SetDetachPermission::PerHost(items) => state.set_detach_permissions(items),
//     }

//     Ok(StatusCode::OK)
// }

/// Detach self
pub async fn detach(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };
    db::hosts::set_provision_state(&mut conn, host, api::ProvisionState::Detached)
        .await
        .internal_server()?;

    Ok(StatusCode::OK)
}
/// Attach self
pub async fn attach(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };
    db::hosts::set_provision_state(&mut conn, host, api::ProvisionState::Provisioned)
        .await
        .internal_server()?;

    Ok(StatusCode::OK)
}
