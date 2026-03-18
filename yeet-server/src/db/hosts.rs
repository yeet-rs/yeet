use api::ProvisionState;
use ed25519_dalek::VerifyingKey;
use jiff_sqlx::ToSqlx;

use sqlx::Acquire;

use crate::db;

pub async fn fetch_provision_state(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
) -> Result<api::ProvisionState, sqlx::Error> {
    Ok(sqlx::query_scalar!(
        r#"
        SELECT state AS "state: api::ProvisionState" FROM state_history WHERE host_id = $1 ORDER BY update_time DESC LIMIT 1"#,
        host
    )
    .fetch_optional(conn)
    .await?
    .unwrap_or(api::ProvisionState::NotSet))
}

pub async fn set_provision_state(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
    state: api::ProvisionState,
) -> Result<(), sqlx::Error> {
    let current_state = fetch_provision_state(conn, host).await?;

    if current_state == state {
        return Ok(());
    }
    let now = jiff::Timestamp::now().to_sqlx();

    sqlx::query!(
        r#"
        INSERT INTO state_history (host_id, state, update_time) VALUES ($1,$2,$3) "#,
        host,
        state,
        now
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn fetch_current_version(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
) -> Result<Option<api::StorePath>, sqlx::Error> {
    Ok(sqlx::query_scalar!(
        r#"
        SELECT store_path FROM version_history WHERE host_id = $1 ORDER BY update_time DESC LIMIT 1"#,
        host
    )
    .fetch_optional(conn)
    .await?)
}

/// Fetch the latest update ignoring if the host has already applied it
async fn fetch_latest_update(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
) -> Result<Option<api::RemoteStorePath>, sqlx::Error> {
    Ok(sqlx::query_as!(
        api::RemoteStorePath,
        r#"
        SELECT store_path,public_key,substitutor FROM update_request_history
        JOIN nix_remotes ON update_request_history.remote = nix_remotes.id
        WHERE host_id = $1
        ORDER BY update_time DESC LIMIT 1"#,
        host
    )
    .fetch_optional(conn)
    .await?)
}

/// When the host completed an update
pub async fn update_current_version(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
    version: api::StorePath,
) -> Result<(), sqlx::Error> {
    let latest = fetch_current_version(conn, host).await?;

    // we already are on the latest
    if Some(&version) == latest.as_ref() {
        return Ok(());
    }
    let now = jiff::Timestamp::now().to_sqlx();

    sqlx::query!(
        r#"
        INSERT INTO version_history (host_id, store_path, update_time)
        VALUES ($1,$2,$3)"#,
        host,
        version,
        now
    )
    .execute(conn)
    .await?;

    Ok(())
}

/// Returns an update only if the host is not currently on the update
/// Does not check if the host is detached
pub async fn fetch_available_update(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
) -> Result<Option<api::RemoteStorePath>, sqlx::Error> {
    let latest = fetch_current_version(conn, host).await?;
    let Some(latest_update) = fetch_latest_update(conn, host).await? else {
        return Ok(None);
    };

    // we already are on the latest
    if Some(&latest_update.store_path) == latest.as_ref() {
        Ok(None)
    } else {
        Ok(Some(latest_update))
    }
}

error_set::error_set! {
    HostUpdateError := {
        #[display("Host `{host}` does not exist")]
        HostNotFound{host: String},
        SQLXError(sqlx::Error),
    }
}

// TODO: make this more db friendly by using hostIDs and move to created remotes
/// Create a new remote update for the host
/// Does set the host to provisioned if he is not set yet
pub async fn update(
    conn: &mut sqlx::SqliteConnection,
    hosts: impl Iterator<Item = (&String, &api::StorePath)>,
    public_key: String,
    substitutor: String,
) -> Result<(), HostUpdateError> {
    let mut tx = conn.begin().await?;

    // Ensure that there is a remote
    let remote = sqlx::query!(
        r#"
        INSERT INTO nix_remotes (public_key, substitutor)
        VALUES ($1, $2)
        ON CONFLICT(public_key) DO UPDATE SET public_key = excluded.public_key
        RETURNING id"#,
        public_key,
        substitutor
    )
    .fetch_one(&mut *tx)
    .await?;

    // TODO: hehe maybe not a loop
    for (host, store_path) in hosts {
        let Some(host) = host_by_hostname(&mut *tx, host).await? else {
            return Err(HostUpdateError::HostNotFound { host: host.clone() });
        };
        let now = jiff::Timestamp::now().to_sqlx();
        sqlx::query!(
            r#"
        INSERT INTO update_request_history (host_id, store_path, remote, update_time)
        SELECT id, $1, $2, $3
        FROM hosts
        WHERE id = $4"#,
            store_path,
            remote.id,
            now,
            host
        )
        .execute(&mut *tx)
        .await?;

        let state = fetch_provision_state(&mut *tx, host).await?;
        if state != ProvisionState::Detached {
            set_provision_state(&mut *tx, host, api::ProvisionState::Provisioned).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

pub async fn list(conn: &mut sqlx::SqliteConnection) -> Result<Vec<api::host::Host>, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
        WITH current_state AS (
            SELECT host_id, state, update_time,
                   ROW_NUMBER() OVER(PARTITION BY host_id ORDER BY update_time DESC) as rn
            FROM state_history
        ),
        current_version AS (
            SELECT host_id, store_path, update_time,
                   ROW_NUMBER() OVER(PARTITION BY host_id ORDER BY update_time DESC) as rn
            FROM version_history
        ),
        latest_update_request AS (
            SELECT host_id, store_path, update_time,
                   ROW_NUMBER() OVER(PARTITION BY host_id ORDER BY update_time DESC) as rn
            FROM update_request_history
        )
        SELECT
            h.id AS "id!",
            h.hostname AS "hostname!",
            k.verifying_key AS "verifying_key!",
            h.last_ping AS "last_ping!: jiff_sqlx::Timestamp",
            ls.state AS "state: api::ProvisionState",
            lv.store_path AS "current_version",
            lur.store_path AS "latest_update"
        FROM hosts h
        JOIN keys k ON h.key_id = k.id
        LEFT JOIN current_state ls ON ls.host_id = h.id AND ls.rn = 1
        LEFT JOIN current_version lv ON lv.host_id = h.id AND lv.rn = 1
        LEFT JOIN latest_update_request lur ON lur.host_id = h.id AND lur.rn = 1;
        "#
    )
    .map(|r| api::host::Host {
        id: api::HostID::new(r.id),
        hostname: r.hostname,
        key: VerifyingKey::from_bytes(
            &r.verifying_key
                .try_into()
                .expect("We only store valid keys"),
        )
        .expect("We only store valid keys"),

        state: r.state.unwrap_or_default(),
        last_ping: r.last_ping.to_jiff(),
        version: r.current_version,
        latest_update: r.latest_update,
    })
    .fetch_all(conn)
    .await?)
}

pub async fn rename(
    conn: &mut sqlx::SqliteConnection,
    id: api::HostID,
    new: String,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE hosts
        SET hostname = $1
        WHERE id = $2"#,
        new,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn ping(conn: &mut sqlx::SqliteConnection, id: api::HostID) -> Result<(), sqlx::Error> {
    let now = jiff::Timestamp::now().to_sqlx();
    sqlx::query!(
        r#"
        UPDATE hosts
        SET last_ping = $1
        WHERE id = $2"#,
        now,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn host_by_verify_key(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<Option<api::HostID>, sqlx::Error> {
    let key = &key.as_bytes()[..];
    Ok(sqlx::query_scalar!(
        r#"
        SELECT hosts.id as "id: api::HostID" FROM hosts
        LEFT JOIN keys on hosts.key_id = keys.id
        WHERE verifying_key = $1"#,
        key
    )
    .fetch_optional(conn)
    .await?)
}

pub async fn host_by_hostname(
    conn: &mut sqlx::SqliteConnection,
    hostname: &str,
) -> Result<Option<api::HostID>, sqlx::Error> {
    Ok(sqlx::query_scalar!(
        r#"
        SELECT hosts.id as "id: api::HostID" FROM hosts
        WHERE hostname = $1"#,
        hostname
    )
    .fetch_optional(conn)
    .await?)
}

pub async fn add_host(
    conn: &mut sqlx::SqliteConnection,
    keyid: String,
    key: VerifyingKey,
    hostname: String,
) -> Result<api::HostID, sqlx::Error> {
    let mut tx = conn.begin().await?;
    let now = jiff::Timestamp::now().to_sqlx();

    let key = db::keys::add_key(&mut *tx, keyid, key).await?;

    let host = sqlx::query!(
        r#"
        INSERT INTO hosts (hostname, last_ping, key_id)
        VALUES ($1, $2, $3)"#,
        hostname,
        now,
        key
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(api::HostID::new(host.last_insert_rowid()))
}

// pub async fn add_version(conn: &mut sqlx::SqliteConnection, host: HostID,store_path) -> Result<()> {
//     sqlx::query!(r#"DELETE FROM hosts WHERE id = $1"#, host)
//         .execute(conn)
//         .await?;
//     Ok(())
// }
