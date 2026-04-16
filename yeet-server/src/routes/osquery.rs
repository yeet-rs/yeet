use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode};
use indexmap::IndexMap;

use osquery_tls::EmptyResponse;
use uuid::Uuid;

use crate::{
    YeetState, db,
    error::InternalError as _,
    httpsig::{User, VerifiedJson},
};

pub async fn list_nodes(
    State(state): State<YeetState>,
    User(user): User,
) -> Result<Json<Vec<api::Node>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_osquery(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;

    Ok(Json(
        db::osquery::list_nodes(&mut conn).await.internal_server()?,
    ))
}

pub async fn create_query(
    State(state): State<YeetState>,
    User(user): User,
    VerifiedJson(query): VerifiedJson<api::CreateQuery>,
) -> Result<Json<api::QueryID>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_osquery(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    let query_id = db::osquery::create_query(&mut conn, user, query.sql, query.nodes)
        .await
        .internal_server()?;

    crate::wake_splunk(state.sender.as_ref()).await;

    Ok(Json(query_id))
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
    Json(request): Json<osquery_tls::NodeKey>,
) -> Json<osquery_tls::DistributedReadResponse> {
    let Ok(mut conn) = state.pool.acquire().await else {
        return Json(query_read_failure());
    };
    let Some(node_key) = get_node_key(request.node_key) else {
        return Json(query_read_failure());
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
) -> Json<osquery_tls::EmptyResponse> {
    let Ok(mut conn) = state.pool.acquire().await else {
        return Json(osquery_tls::EmptyResponse::invalid());
    };
    let Some(node_key) = get_node_key(request.node_key) else {
        return Json(osquery_tls::EmptyResponse::invalid());
    };

    // transform from row to column based
    let queries = {
        let mut queries = HashMap::new();
        for (query_id, query) in request.queries {
            queries.insert(query_id, row_to_column(query));
        }
        queries
    };

    let Ok(response) =
        db::osquery::write_dquery_response(&mut conn, &node_key, &queries, &request.statuses).await
    else {
        return Json(osquery_tls::EmptyResponse::invalid());
    };

    crate::wake_splunk(state.sender.as_ref()).await;
    Json(response)
}

pub async fn config(
    State(state): State<YeetState>,
    Json(request): Json<osquery_tls::NodeKey>,
) -> Json<serde_json::Value> {
    let empty_response = Json(
        serde_json::to_value(osquery_tls::EmptyResponse::invalid())
            .expect("EmptyResponse can be serialized"),
    );

    let Ok(mut conn) = state.pool.acquire().await else {
        return empty_response;
    };

    let Some(node_key) = get_node_key(request.node_key) else {
        return empty_response;
    };

    // we are a bit special here because we only check if it is a valid node
    let Ok(_node_id) = sqlx::query_scalar!(
        r#"SELECT id FROM osquery_nodes WHERE node_key = $1"#,
        node_key
    )
    .fetch_one(&mut *conn)
    .await
    else {
        log::warn!("Unknown node: {node_key}");
        return empty_response;
    };

    Json(serde_json::json!({
        "packs": state.osquery_packs
    }))
}

pub async fn log(
    State(state): State<YeetState>,
    Json(request): Json<serde_json::Value>,
) -> Json<osquery_tls::EmptyResponse> {
    let remote_log = serde_json::from_value::<osquery_tls::RemoteLoggingRequest>(request.clone());

    let remote_log = match remote_log {
        Ok(remote_log) => remote_log,
        Err(err) => {
            log::error!(
                "Could not deserialize RemoteLog:\n{}\nreceived:\n{}",
                err,
                serde_json::to_string_pretty(&request).unwrap()
            );
            return Json(EmptyResponse::invalid());
        }
    };

    let Ok(mut conn) = state.pool.acquire().await else {
        return Json(EmptyResponse::invalid());
    };

    let Some(node_key) = get_node_key(remote_log.node_key) else {
        return Json(EmptyResponse::invalid());
    };

    if let Err(err) = db::osquery::store_remote_log(&mut conn, &node_key, &remote_log.data).await {
        log::error!(
            "Unable to store remote_log {err}:\n {}",
            serde_json::to_string_pretty(&request).unwrap()
        );
        return Json(EmptyResponse::invalid());
    }

    crate::wake_splunk(state.sender.as_ref()).await;
    Json(osquery_tls::EmptyResponse::valid())
}

// by row: `Vec<IndexMap<String, String>>` e.g. [{"clm1": "val1", "clm2":"val1"},{"clm1": "val2", "clm2":"val2"}]
// by column: `IndexMap<String, Vec<String>>` e.g. {"clm1": ["val1","val2"],"clm2": ["val1","val2"]}

pub(crate) fn row_to_column(rows: Vec<IndexMap<String, String>>) -> IndexMap<String, Vec<String>> {
    let mut columns: IndexMap<String, Vec<String>> = IndexMap::new();

    for row in rows {
        for (column_name, value) in row {
            columns.entry(column_name).or_default().push(value);
        }
    }
    columns
}

fn get_node_key(key: Option<String>) -> Option<Uuid> {
    let node_key = key.and_then(|key| key.parse().ok());
    let Some(node_key) = node_key else {
        log::warn!("Did not send a node_key in a request that requires a node key");
        return None;
    };
    Some(node_key)
}

pub(crate) fn column_to_row(
    columns: &IndexMap<String, Vec<String>>,
) -> Vec<IndexMap<String, String>> {
    let mut rows: Vec<IndexMap<String, String>> = Vec::new();

    let max_rows = columns.values().map(std::vec::Vec::len).max().unwrap_or(0);

    for row_idx in 0..max_rows {
        let mut row: IndexMap<String, String> = IndexMap::new();
        for (column_name, values) in columns {
            if let Some(value) = values.get(row_idx) {
                row.insert(column_name.clone(), value.clone());
            }
        }
        rows.push(row);
    }

    rows
}

#[cfg(test)]
mod tests {
    use indexmap::indexmap;

    use super::*;

    #[test]
    fn table_conversion() {
        let rows = vec![
            indexmap! { "id".to_string() => "1".to_string(), "name".to_string() => "Alice".to_string() },
            indexmap! { "id".to_string() => "2".to_string(), "name".to_string() => "Bob".to_string() },
        ];

        let columns = row_to_column(rows.clone());
        let rows_converted = column_to_row(&columns);
        assert_eq!(rows, rows_converted);
    }
}
