use std::collections::HashMap;

use indexmap::IndexMap;
use jiff_sqlx::ToSqlx as _;
use osquery_tls::LogType;
use sqlx::Acquire as _;
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
    let nodes = sqlx::query!(
        r#"
        SELECT
            id,
            host_identifier,
            platform_name,
            osquery_version,
            os_version,
            cpu_arch,
            platform,
            hardware_serial,
            last_ping AS "last_ping!: jiff_sqlx::Timestamp"
        FROM osquery_nodes"#
    )
    .map(|row| api::Node {
        id: api::NodeID::new(row.id),
        host_identifier: row.host_identifier,
        platform_name: row.platform_name,
        osquery_version: row.osquery_version,
        os_version: row.os_version,
        cpu_arch: row.cpu_arch,
        platform: row.platform,
        hardware_serial: row.hardware_serial,
        last_ping: row.last_ping.to_jiff(),
    })
    .fetch_all(&mut *conn)
    .await?;

    Ok(nodes)
}

error_set::error_set! {
    CreateQueryError := {
        #[display("Nodes can't be empty")]
        EmptyNodes,
        SQLXE(sqlx::Error),
    }
}

pub async fn create_query(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
    query: String,
    filter: Vec<api::NodeID>,
) -> Result<api::QueryID, CreateQueryError> {
    if filter.is_empty() {
        return Err(CreateQueryError::EmptyNodes);
    }

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
    let Some(enroll_secret) = &enroll_request.enroll_secret else {
        return Err(EnrollError::SecretMismatch);
    };

    {
        // all secrets that begin with `osquery-enroll` are tested
        let enroll_secrets =
            sqlx::query_scalar!(r#"SELECT secret FROM secrets WHERE name like "osquery-enroll%""#)
                .fetch_all(&mut *conn)
                .await?;

        if enroll_secrets.is_empty() {
            log::warn!(
                "A Node tried to enroll with a empty node_key:\n{:#?}",
                enroll_request
            );
            return Err(EnrollError::SecretNotSet);
        }

        let mut secret_match = false;
        for secret in enroll_secrets {
            let server_secret = age::decrypt(store_key, &secret)?;
            // if the secrets match we found our match and can continue
            if String::from_utf8_lossy(&server_secret).to_string().trim() == enroll_secret.trim() {
                secret_match = true;
            }
        }
        // if we have not found a match we need to exit
        if !secret_match {
            log::warn!("No matching secrets found for node:\n{:#?}", enroll_request);
            return Err(EnrollError::SecretMismatch);
        }
    }

    let existing_key = sqlx::query_scalar!(
        r#"SELECT node_key as "node_key: uuid::Uuid" FROM osquery_nodes WHERE host_identifier = $1"#,
        enroll_request.host_identifier
            )
    .fetch_optional(&mut *conn).await?;

    if let Some(key) = existing_key {
        return Ok(key);
    }

    let node_key = uuid::Uuid::now_v7();
    let now = jiff::Timestamp::now().to_sqlx();

    sqlx::query!(
        r#"INSERT INTO osquery_nodes (node_key, host_identifier, platform_type, last_ping)
           VALUES ($1,$2,$3,$4)"#,
        node_key,
        enroll_request.host_identifier,
        enroll_request.platform_type,
        now
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

pub async fn ping(conn: &mut sqlx::SqliteConnection, id: api::NodeID) -> Result<(), sqlx::Error> {
    let now = jiff::Timestamp::now().to_sqlx();
    sqlx::query!(
        r#"
        UPDATE osquery_nodes
        SET last_ping = $1
        WHERE id = $2"#,
        now,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Return all queries that a node has to still execute
pub async fn dqueries_for_node(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
) -> Result<osquery_tls::DistributedReadResponse, DQueryError> {
    let node_id = sqlx::query_scalar!(r#"SELECT id FROM osquery_nodes WHERE node_key = $1"#, node)
        .fetch_one(&mut *conn)
        .await?;

    ping(conn, api::NodeID::new(node_id)).await?;

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

/// Store the result of a query (from the node)
pub async fn write_dquery_response(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
    queries: &HashMap<String, IndexMap<String, Vec<String>>>,
    statuses: &HashMap<String, u32>,
) -> Result<osquery_tls::EmptyResponse, sqlx::Error> {
    let mut tx = conn.begin().await?;

    let node_id = sqlx::query_scalar!(r#"SELECT id FROM osquery_nodes WHERE node_key = $1"#, node)
        .fetch_one(&mut *tx)
        .await?;

    ping(&mut *tx, api::NodeID::new(node_id)).await?;

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
    Ok(osquery_tls::EmptyResponse::valid())
}

pub async fn store_remote_log(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
    log: &osquery_tls::LogType,
) -> Result<(), sqlx::Error> {
    match log {
        LogType::Result(result_logs) => store_result_log(conn, node, result_logs).await,
        LogType::Status(status_logs) => store_status_log(conn, node, status_logs).await,
    }
}

async fn store_status_log(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
    statuses: &Vec<osquery_tls::StatusLog>,
) -> Result<(), sqlx::Error> {
    let node_id = sqlx::query_scalar!(r#"SELECT id FROM osquery_nodes WHERE node_key = $1"#, node)
        .fetch_one(&mut *conn)
        .await?;

    ping(conn, api::NodeID::new(node_id)).await?;

    // TODO: sqlx in operator
    for status in statuses {
        let now = jiff::Timestamp::now().to_sqlx();
        sqlx::query!(
            r#"INSERT INTO osquery_status_log
                (node_id, splunk_status, calendar_time, received_time, unix_time, filename, line, message, severity, version)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
            node_id,
            crate::splunk_sender::SplunkStatus::NotSent,
            status.calendar_time,
            now,
            status.unix_time,
            status.filename,
            status.line,
            status.message,
            status.severity,
            status.version
        )
        .execute(&mut *conn)
        .await?;
    }

    Ok(())
}

async fn store_result_log(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
    results: &Vec<osquery_tls::ResultLog>,
) -> Result<(), sqlx::Error> {
    let node_id = sqlx::query_scalar!(r#"SELECT id FROM osquery_nodes WHERE node_key = $1"#, node)
        .fetch_one(&mut *conn)
        .await?;

    ping(conn, api::NodeID::new(node_id)).await?;

    // TODO: sqlx in operator
    for result in results {
        // this is an internal pack - we do not send this to splunk
        if result.name == "pack_yeet_internal_node_info" {
            update_node_info(&mut *conn, node, result).await?;
            continue;
        }

        let log = serde_json::to_string(&result.action).expect("Could not serialize a json");
        let now = jiff::Timestamp::now().to_sqlx();
        sqlx::query!(
            r#"INSERT INTO osquery_result_log
                (node_id, splunk_status, calendar_time, received_time, unix_time, numerics, epoch, pack_name, log, counter)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
            node_id,
            crate::splunk_sender::SplunkStatus::NotSent,
            result.calendar_time,
            now,
            result.unix_time,
            result.numerics,
            result.epoch,
            result.name,
            log,
            result.counter
        )
        .execute(&mut *conn)
        .await?;
    }

    Ok(())
}

async fn update_node_info(
    conn: &mut sqlx::SqliteConnection,
    node: &uuid::Uuid,
    result: &osquery_tls::ResultLog,
) -> Result<(), sqlx::Error> {
    let osquery_tls::EventLogAction::Snapshot { snapshot } = &result.action else {
        log::error!(
            "yeet_node_info is not of type snapshot:\n{:#?}",
            result.action
        );
        return Ok(());
    };
    let Some(info) = snapshot.last() else {
        log::error!("yeet_node_info snapshot was empty");
        return Ok(());
    };

    let Some(platform_name) = info.get("name") else {
        log::error!("yeet_node_info did not contain platform_name");
        return Ok(());
    };

    let Some(os_version) = info.get("os_version") else {
        log::error!("yeet_node_info did not contain os_version");
        return Ok(());
    };

    let Some(cpu_arch) = info.get("arch") else {
        log::error!("yeet_node_info did not contain cpu_arch");
        return Ok(());
    };

    let Some(platform) = info.get("platform") else {
        log::error!("yeet_node_info did not contain platform");
        return Ok(());
    };

    let Some(hardware_serial) = info.get("hardware_serial") else {
        log::error!("yeet_node_info did not contain hardware_serial");
        return Ok(());
    };

    let Some(osquery_version) = info.get("version") else {
        log::error!("yeet_node_info did not contain osquery_version");
        return Ok(());
    };

    sqlx::query!(
        r#"
        UPDATE osquery_nodes
        SET platform_name = $1,
            osquery_version = $2,
            os_version = $3,
            cpu_arch = $4,
            platform = $5,
            hardware_serial = $6
        WHERE node_key = $7
        "#,
        platform_name,
        osquery_version,
        os_version,
        cpu_arch,
        platform,
        hardware_serial,
        node
    )
    .execute(conn)
    .await?;

    Ok(())
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

    #[sqlx::test]
    async fn enroll_new_node_multiple_secrets(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        let store_key = age::x25519::Identity::generate();

        let encrypted = age::encrypt(&store_key.to_public(), b"my-secret-enroll-secret").unwrap();

        let _enroll_secret =
            db::secrets::add_secret(&mut conn, "osquery-enroll", encrypted, &store_key)
                .await
                .unwrap();

        let encrypted =
            age::encrypt(&store_key.to_public(), b"my-true-secret-enroll-secret").unwrap();

        let _enroll_secret =
            db::secrets::add_secret(&mut conn, "osquery-enroll-second", encrypted, &store_key)
                .await
                .unwrap();

        db::osquery::enroll_node(
            &mut conn,
            &store_key,
            osquery_tls::EnrollmentRequest {
                enroll_secret: Some("my-true-secret-enroll-secret".to_owned()),
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

        let error = db::osquery::enroll_node(
            &mut conn,
            &store_key,
            osquery_tls::EnrollmentRequest {
                enroll_secret: Some("my-wrong-secret".to_owned()),
                host_identifier: "unique-host2".into(),
                host_details: osquery_tls::EnrollmentHostDetails {
                    os_version: HashMap::new(),
                    osquery_info: HashMap::new(),
                    system_info: HashMap::new(),
                    platform_info: HashMap::new(),
                },
                platform_type: "9".into(),
            },
        )
        .await;
        assert!(error.is_err())
    }

    #[sqlx::test]
    async fn enroll_new_node_weird_formatting(pool: sqlx::SqlitePool) {
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
                enroll_secret: Some("my-secret-enroll-secret\n".to_owned()),
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
