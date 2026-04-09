use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode};
use indexmap::IndexMap;

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
        return Json(query_write_failure());
    };

    crate::wake_splunk(state.sender.as_ref()).await;
    Json(response)
}

fn query_write_failure() -> osquery_tls::DistributedWriteResponse {
    osquery_tls::DistributedWriteResponse {
        node_invalid: Some(true),
    }
}
// by row: `Vec<IndexMap<String, String>>` e.g. [{"clm1": "val1", "clm2":"val1"},{"clm1": "val2", "clm2":"val2"}]
// by column: `IndexMap<String, Vec<String>>` e.g. {"clm1": ["val1","val2"],"clm2": ["val1","val2"]}

pub(crate) fn row_to_column(rows: Vec<IndexMap<String, String>>) -> IndexMap<String, Vec<String>> {
    let mut columns: IndexMap<String, Vec<String>> = IndexMap::new();

    for row in rows.into_iter() {
        for (column_name, value) in row {
            columns.entry(column_name).or_default().push(value);
        }
    }
    columns
}

pub(crate) fn column_to_row(
    columns: IndexMap<String, Vec<String>>,
) -> Vec<IndexMap<String, String>> {
    let mut rows: Vec<IndexMap<String, String>> = Vec::new();

    let max_rows = columns.values().map(|v| v.len()).max().unwrap_or(0);

    for row_idx in 0..max_rows {
        let mut row: IndexMap<String, String> = IndexMap::new();
        for (column_name, values) in &columns {
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
    use super::*;
    use indexmap::indexmap;

    #[test]
    fn table_conversion() {
        let rows = vec![
            indexmap! { "id".to_string() => "1".to_string(), "name".to_string() => "Alice".to_string() },
            indexmap! { "id".to_string() => "2".to_string(), "name".to_string() => "Bob".to_string() },
        ];

        let columns = row_to_column(rows.clone());
        let rows_converted = column_to_row(columns);
        assert_eq!(rows, rows_converted);
    }
}
