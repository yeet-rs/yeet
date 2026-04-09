use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
pub enum SplunkStatus {
    /// The message has not yet been sent
    NotSent,
    /// The message delivery has been successfull
    Sent,
    /// This message will never be sent to splunk
    Internal,
}

// TODO: what do we want to do if this thread errors
pub async fn run(
    config: splunk_hec::SplunkConfig,
    mut receiver: tokio::sync::mpsc::Receiver<()>,
    pool: sqlx::SqlitePool,
) -> Result<(), sqlx::Error> {
    log::info!("Waiting for splunk ping");
    while let Some(()) = receiver.recv().await {
        log::info!("Sending logs to splunk");
        let mut conn = pool.acquire().await?;

        send_queries(&mut conn, &config).await?;
        send_responses(&mut conn, &config).await?;
        // TODO: delete non persistent which were sent
    }
    Ok(())
}

/// Send all `osquery_dq_responses` with state `SplunkStatus::NotSent` to splunk
async fn send_responses(
    conn: &mut sqlx::SqliteConnection,
    config: &splunk_hec::SplunkConfig,
) -> Result<(), sqlx::Error> {
    let unsent_dq_responses = sqlx::query!(
        r#"
        SELECT
            odr.id,
            odr.query_id,
            odr.status,
            osn.host_identifier,
            odr.response_time as "response_time: jiff_sqlx::Timestamp",
            odr.response

        FROM osquery_dq_responses odr
        JOIN osquery_nodes osn on odr.node_id = osn.id
        WHERE odr.splunk_status = $1"#,
        SplunkStatus::NotSent
    )
    .fetch_all(&mut *conn)
    .await?;

    log::info!("Sending {} responses", unsent_dq_responses.len());

    for node_response in unsent_dq_responses {
        let rows = {
            let columns: IndexMap<String, Vec<String>> =
                serde_json::from_str(&node_response.response).unwrap_or_default();
            crate::routes::osquery::column_to_row(columns)
        };

        let mut query_rows = Vec::new();

        for row in rows {
            let row = splunk_hec::SplunkMessageType::QueryRow {
                osquery_sid: node_response.query_id,
                osquery_hostname: node_response.host_identifier.clone(),
                row,
                osquery_status: node_response.status,
            };
            query_rows.push(row);
        }

        let response = config
            .send_msgs(query_rows, node_response.response_time.to_jiff())
            .await;

        // only update that it was sent if it was sent successfull
        if response.is_ok() {
            sqlx::query!(
                r#"UPDATE osquery_dq_responses
                SET splunk_status = $1
                WHERE id = $2"#,
                SplunkStatus::Sent,
                node_response.id
            )
            .execute(&mut *conn)
            .await?;
        } else {
            log::error!("Failed to send splunk logs: {}", response.unwrap_err())
        }
    }
    Ok(())
}

/// Send all `osquery_dq_queries` with state `SplunkStatus::NotSent` to splunk
async fn send_queries(
    conn: &mut sqlx::SqliteConnection,
    config: &splunk_hec::SplunkConfig,
) -> Result<(), sqlx::Error> {
    let unsent_dq_queries = sqlx::query!(
        r#"
        SELECT
            q.id,
            q.query,
            u.username,
            q.creation_time as "creation_time: jiff_sqlx::Timestamp",
            json_group_array(
                osn.host_identifier
            ) as "nodes!: Json<Vec<String>>"
        FROM osquery_dq_queries q
        JOIN users u on q.user_id = u.id
        LEFT JOIN osquery_dq_requests odreq on odreq.query_id = q.id -- these nodes have not yet responded
        LEFT JOIN osquery_dq_responses odr on odr.query_id = q.id -- these nodes have already responded
        JOIN osquery_nodes osn on odr.node_id = osn.id or odreq.node_id = osn.id
        WHERE q.splunk_status = $1
        GROUP BY q.id, u.username"#,
        SplunkStatus::NotSent
    )
    .fetch_all(&mut *conn)
    .await?;

    log::info!("Sending {} queries", unsent_dq_queries.len());

    for query in unsent_dq_queries {
        let response = config
            .send_msgs(
                vec![splunk_hec::SplunkMessageType::QueryJob {
                    sid: query.id,
                    query: query.query,
                    nodes: query.nodes.0,
                    user: query.username,
                }],
                query.creation_time.to_jiff(),
            )
            .await;

        // only update that it was sent if it was sent successfull
        if response.is_ok() {
            sqlx::query!(
                r#"UPDATE osquery_dq_queries
                SET splunk_status = $1
                WHERE id = $2"#,
                SplunkStatus::Sent,
                query.id
            )
            .execute(&mut *conn)
            .await?;
        } else {
            log::error!("Failed to send splunk logs: {}", response.unwrap_err())
        }
    }
    Ok(())
}
