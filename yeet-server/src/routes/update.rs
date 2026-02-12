use std::sync::Arc;

use axum::{extract::State, http::StatusCode};
use parking_lot::RwLock;

use crate::{
    AppState,
    httpsig::{HttpSig, VerifiedJson},
    state::StateError,
};

/// Endpoint to set a new version for a host.
/// The whole request needs to be signed by a build machine.
/// The update consist of a simple `key` -> `version` and a `substitutor` which is where the agent should get its update
/// This means that for each origin e.g. cachix, you need to call update seperately
pub async fn update_hosts(
    State(state): State<Arc<RwLock<AppState>>>,
    HttpSig(http_key): HttpSig,

    VerifiedJson(api::HostUpdateRequest {
        hosts,
        public_key,
        substitutor,
        netrc,
    }): VerifiedJson<api::HostUpdateRequest>,
) -> Result<StatusCode, StateError> {
    let mut state = state.write_arc();

    state.auth_build(&http_key)?;

    state.update_hosts(hosts, public_key, substitutor, netrc);

    Ok(StatusCode::CREATED)
}
