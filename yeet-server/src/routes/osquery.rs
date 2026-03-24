use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState, db,
    error::InternalError as _,
    httpsig::{HttpSig, VerifiedJson},
};

pub async fn list_nodes(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<Json<Vec<api::Node>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    Ok(Json(
        db::osquery::list_nodes(&mut conn).await.internal_server()?,
    ))
}

pub async fn create_query(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    VerifiedJson(query): VerifiedJson<api::CreateQuery>,
) -> Result<Json<api::QueryID>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    Ok(Json(
        db::osquery::create_query(&mut conn, key, query.sql)
            .await
            .internal_server()?,
    ))
}

pub async fn query_response_all(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    Path(query): Path<api::QueryID>,
) -> Result<Json<api::QueryFulfillment>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    Ok(Json(
        db::osquery::get_query_response_all(&mut conn, query)
            .await
            .internal_server()?,
    ))
}

pub async fn enroll(
    State(state): State<YeetState>,
    Json(request): Json<osquery_tls::EnrollmentRequest>,
) -> Json<osquery_tls::EnrollmentResponse> {
    let Ok(mut conn) = state.pool.acquire().await.internal_server() else {
        return Json(enroll_failure());
    };

    let Ok(node_key) = db::osquery::enroll_node(&mut conn, &*state.age_key, request).await else {
        return Json(enroll_failure());
    };

    Json(osquery_tls::EnrollmentResponse {
        node_key: Some(node_key.to_string()),
        node_invalid: None,
    })
}

fn enroll_failure() -> osquery_tls::EnrollmentResponse {
    osquery_tls::EnrollmentResponse {
        node_key: None,
        node_invalid: Some(true),
    }
}

pub async fn query_read(
    State(state): State<YeetState>,
    Json(request): Json<osquery_tls::DistributedReadRequest>,
) -> Json<osquery_tls::DistributedReadResponse> {
    let Ok(mut conn) = state.pool.acquire().await else {
        return Json(query_read_failure());
    };
    let node_key = {
        let node_key = request.node_key.and_then(|key| key.parse().ok());
        let Some(node_key) = node_key else {
            return Json(query_read_failure());
        };
        node_key
    };

    let Ok(response) = db::osquery::dqueries_for_node(&mut conn, &node_key).await else {
        return Json(query_read_failure());
    };
    Json(response)
}

fn query_read_failure() -> osquery_tls::DistributedReadResponse {
    osquery_tls::DistributedReadResponse {
        queries: HashMap::new(),
        node_invalid: Some(true),
    }
}

pub async fn query_write(
    State(state): State<YeetState>,
    Json(request): Json<osquery_tls::DistributedWriteRequest>,
) -> Json<osquery_tls::DistributedWriteResponse> {
    let Ok(mut conn) = state.pool.acquire().await else {
        return Json(query_write_failure());
    };
    let node_key = {
        let node_key = request.node_key.and_then(|key| key.parse().ok());
        let Some(node_key) = node_key else {
            return Json(query_write_failure());
        };
        node_key
    };

    let Ok(response) = db::osquery::write_dquery_response(
        &mut conn,
        &node_key,
        &request.queries,
        &request.statuses,
    )
    .await
    else {
        return Json(query_write_failure());
    };
    Json(response)
}

fn query_write_failure() -> osquery_tls::DistributedWriteResponse {
    osquery_tls::DistributedWriteResponse {
        node_invalid: Some(true),
    }
}
