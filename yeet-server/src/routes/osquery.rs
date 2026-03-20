use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode};

use crate::{YeetState, db, error::InternalError as _};

pub async fn enroll(
    State(state): State<YeetState>,
    Json(request): Json<osquery_tls::EnrollmentRequest>,
) -> Json<osquery_tls::EnrollmentResponse> {
    let Ok(mut conn) = state.pool.acquire().await.internal_server() else {
        return Json(node_failure());
    };

    let Ok(node_key) = db::osquery::enroll_node(&mut conn, &*state.age_key, request).await else {
        return Json(node_failure());
    };

    Json(osquery_tls::EnrollmentResponse {
        node_key: Some(node_key.to_string()),
        node_invalid: None,
    })
}

fn node_failure() -> osquery_tls::EnrollmentResponse {
    osquery_tls::EnrollmentResponse {
        node_key: None,
        node_invalid: Some(true),
    }
}

pub async fn query_read(
    State(state): State<YeetState>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<osquery_tls::DistributedReadResponse>, (StatusCode, String)> {
    // let mut conn = state.pool.acquire().await.internal_server()?;
    // db::keys::auth_admin(&mut conn, key).await?;
    println!("dread: {request:#?}");
    Ok(Json(osquery_tls::DistributedReadResponse {
        queries: HashMap::from([("id1".into(), "SELECT * FROM sudoers;".into())]),
        node_invalid: None,
    }))
}

pub async fn query_write(
    State(state): State<YeetState>,
    Json(request): Json<serde_json::Value>,
) -> Result<StatusCode, (StatusCode, String)> {
    // let mut conn = state.pool.acquire().await.internal_server()?;
    // db::keys::auth_admin(&mut conn, key).await?;
    println!("dwrite: {request:#?}");
    Ok(StatusCode::OK)
}
