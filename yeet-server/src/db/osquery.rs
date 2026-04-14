use std::collections::HashMap;

use indexmap::IndexMap;
use jiff_sqlx::ToSqlx as _;
use sqlx::{Acquire as _, types::Json};
use uuid::Uuid;

error_set::error_set! {
    EnrollError := {
        #[display("Enroll secret not set or does not match")]
        SecretMismatch,
        #[display("Enroll secret is not yet set")]
        SecretNotSet,
        Decrypt(age::DecryptError),
        SQLXE(sqlx::Error),
    }
}

pub async fn list_nodes(conn: &mut sqlx::SqliteConnection) -> Result<Vec<api::Node>, sqlx::Error> {
    let nodes = sqlx::query!(r#"
        SELECT id, host_identifier, host_details as "host_details: Json<osquery_tls::EnrollmentHostDetails>"
        FROM osquery_nodes"#)
        .map(|row| api::Node {
            id: api::NodeID::new(row.id),
            host_identifier: row.host_identifier,
            host_details: row.host_details.0,
        })
        .fetch_all(&mut *conn)
        .await?;

    Ok(nodes)
}

pub async fn create_query(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
    query: String,
    filter: Vec<api::NodeID>,
) -> Result<api::QueryID, sqlx::Error> {
    let mut tx = conn.begin().await?;

    let now = jiff::Timestamp::now().to_sqlx();
    let query_id = sqlx::query!(
        r#"INSERT INTO osquery_dq_queries (query,user_id,splunk_status,creation_time) VALUES ($1,$2,$3,$4)"#,
        query,
        user,
        crate::splunk_sender::SplunkStatus::NotSent,
        now
    )
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();

    // TODO: no loop
    // TODO: what if no nodes

    let mut nodes = sqlx::query_scalar!(r#"SELECT id as "id: api::NodeID" FROM osquery_nodes"#)
        .fetch_all(&mut *tx)
        .await?;

    nodes.retain(|id| filter.contains(id));

    for node in nodes {
        sqlx::query!(
            r#"INSERT INTO osquery_dq_requests (query_id,node_id) VALUES ($1,$2)"#,
            query_id,
            node
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(api::QueryID::new(query_id))
}

/// The node needs to provide the same content as the `osquery-enroll` secret
/// As a response the ode receives an unique `UUIDv7` this is the nodes `node_key`
pub async fn enroll_node<I: age::Identity>(
    conn: &mut sqlx::SqliteConnection,
    store_key: &I,
    enroll_request: osquery_tls::EnrollmentRequest,
) -> Result<Uuid, EnrollError> {
    // we hardcode the name of the enroll secret
    let Some(enroll_secret) =
        sqlx::query_scalar!(r#"SELECT secret FROM secrets WHERE name = "osquery-enroll""#)
            .fetch_optional(&mut *conn)
            .await?
    else {
        return Err(EnrollError::SecretNotSet);
    };

    let enroll_secret = age::decrypt(store_key, &enroll_secret)?;

    if Some(String::from_utf8_lossy(&enroll_secret).to_string()) != enroll_request.enroll_secret {
        return Err(EnrollError::SecretMismatch);
    }
    let node_key = uuid::Uuid::now_v7();
    let details = Json::from(enroll_request.host_details);

    sqlx::query!(
        r#"INSERT INTO osquery_nodes (node_key, host_identifier, platform_type, host_details)
           VALUES ($1,$2,$3,$4)"#,
        node_key,
        enroll_request.host_identifier,
        enroll_request.platform_type,
        details
    )
    .execute(conn)
    .await?;

    Ok(node_key)
}

error_set::error_set! {
    DQueryError := {
        SQLXE(sqlx::Error),
    }
}

/// Return all queries that a node has to still execute
pub async fn dqueries_for_node(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
) -> Result<osquery_tls::DistributedReadResponse, DQueryError> {
    let node_id = sqlx::query_scalar!(r#"SELECT id FROM osquery_nodes WHERE node_key = $1"#, node)
        .fetch_one(&mut *conn)
        .await?;

    let queries = sqlx::query!(
        r#"
        SELECT id as "id: String", query
        FROM osquery_dq_requests as odr
        JOIN osquery_dq_queries as oq on oq.id = odr.query_id
        WHERE node_id = $1"#,
        node_id
    )
    .map(|row| (row.id, row.query))
    .fetch_all(&mut *conn)
    .await?;

    Ok(osquery_tls::DistributedReadResponse {
        queries: queries.into_iter().collect(),
        node_invalid: None,
    })
}

error_set::error_set! {
    DWriteError := {
        SQLXE(sqlx::Error),
    }
}

/// Store the result of a query (from the node)
pub async fn write_dquery_response(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
    queries: &HashMap<String, IndexMap<String, Vec<String>>>,
    statuses: &HashMap<String, u32>,
) -> Result<osquery_tls::DistributedWriteResponse, DWriteError> {
    let mut tx = conn.begin().await?;

    let node_id = sqlx::query_scalar!(r#"SELECT id FROM osquery_nodes WHERE node_key = $1"#, node)
        .fetch_one(&mut *tx)
        .await?;

    // TODO: sqlx in operator
    for (query_id, response) in queries {
        sqlx::query!(
            r#"DELETE FROM osquery_dq_requests WHERE node_id = $1 AND query_id = $2"#,
            node_id,
            query_id
        )
        .execute(&mut *tx)
        .await?;

        let status = statuses.get(query_id).copied().unwrap_or(0);
        let response = serde_json::to_string(response).expect("Could not serialize a json");
        let now = jiff::Timestamp::now().to_sqlx();
        sqlx::query!(
            r#"INSERT INTO osquery_dq_responses (query_id, node_id, response, status, splunk_status, response_time)
            VALUES ($1,$2,$3,$4,$5,$6)"#,
            query_id,
            node_id,
            response,
            status,
            crate::splunk_sender::SplunkStatus::NotSent,
            now
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(osquery_tls::DistributedWriteResponse { node_invalid: None })
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::db;

    #[sqlx::test]
    async fn enroll_new_node(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        let store_key = age::x25519::Identity::generate();

        let encrypted = age::encrypt(&store_key.to_public(), b"my-secret-enroll-secret").unwrap();

        let _enroll_secret =
            db::secrets::add_secret(&mut conn, "osquery-enroll", encrypted, &store_key)
                .await
                .unwrap();

        db::osquery::enroll_node(
            &mut conn,
            &store_key,
            osquery_tls::EnrollmentRequest {
                enroll_secret: Some("my-secret-enroll-secret".to_owned()),
                host_identifier: "unique-host".into(),
                host_details: osquery_tls::EnrollmentHostDetails {
                    os_version: HashMap::new(),
                    osquery_info: HashMap::new(),
                    system_info: HashMap::new(),
                    platform_info: HashMap::new(),
                },
                platform_type: "9".into(),
            },
        )
        .await
        .unwrap();
    }
}
