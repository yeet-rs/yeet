use ed25519_dalek::VerifyingKey;
use jiff_sqlx::ToSqlx as _;
use rand::RngExt as _;

use crate::db;

error_set::error_set! {
    AddVerificationError := {
        #[display("Key already in an verification attempt")]
        KeyPendingVerification,
        #[display("Provided key is already verified")]
        KeyAlreadyInUse,
        #[display("Too many attempts. Try again later")]
        TooManyAttempts,

        SQLXError(sqlx::Error),
    }
}

/// Add a new verification attempt from an unknown host (Agent)
/// This can be approved by an admin with `approve_attempt`
///
/// The return value is a six digit number. This number should be displayed on the agent
/// There is no other way to get to this value than reading it from the agent.
/// This ensures that the agent that attempt the verification is actually the agent you are trying to setup
/// The traffic is susceptible to MITM attack. The agent should use certificate pinning (TODO)
///
/// # Security
/// This is the only method that is done without any form of authentication.
/// It may be advised to but this behind a firewall
/// However no DDoS can come from this because the attempt count is hard limited at 10
pub async fn add_verification_attempt(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
    nixos_facter: Option<String>,
) -> Result<i64, AddVerificationError> {
    // delete old attemps to give room for new ones
    delete_old_attempts(conn).await?;

    // If the client has an attempt already we abort
    if key_exists(conn, key).await? {
        return Err(AddVerificationError::KeyPendingVerification);
    }

    // check if key already is in registered keys
    if db::hosts::host_by_verify_key(conn, key).await?.is_some() {
        return Err(AddVerificationError::KeyAlreadyInUse);
    }

    // limit concurrent attempts
    if count_attempts(conn).await? >= 10 {
        return Err(AddVerificationError::TooManyAttempts);
    }

    let id = rand::rng().random_range(100_000..=999_999);

    let now = jiff::Timestamp::now().to_sqlx();
    let key = &key.as_bytes()[..];
    let row_id = sqlx::query!(
        r#"
        INSERT INTO verification_attempts (id, verifying_key, timestamp, nixos_facter)
        VALUES ( $1, $2, $3, $4)
        "#,
        id,
        key,
        now,
        nixos_facter
    )
    .execute(conn)
    .await?
    .last_insert_rowid();

    assert_eq!(id, row_id);

    Ok(id)
}

/// Approve an request
/// If available returns the nixos-facter content
pub async fn accept_attempt(
    conn: &mut sqlx::SqliteConnection,
    code: i64,
    hostname: String,
) -> Result<Option<String>, sqlx::Error> {
    // delete old attemps to give room for new ones
    delete_old_attempts(conn).await?;

    // TODO: what happens if you approve a key that does not exist
    let approved = sqlx::query!(
        r#"DELETE FROM verification_attempts WHERE id = $1 RETURNING nixos_facter,verifying_key"#,
        code,
    )
    .fetch_one(&mut *conn)
    .await?;

    let key = VerifyingKey::from_bytes(
        &approved
            .verifying_key
            .try_into()
            .expect("We never store anything else than verifying keys"),
    )
    .expect("We never store anything else than verifying keys");

    db::hosts::add_host(conn, key, hostname).await?;

    Ok(approved.nixos_facter)
}

async fn count_attempts(conn: &mut sqlx::SqliteConnection) -> Result<i64, sqlx::Error> {
    Ok(
        sqlx::query_scalar!(r#"SELECT COUNT(*) FROM verification_attempts"#)
            .fetch_one(conn)
            .await?,
    )
}

async fn key_exists(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<bool, sqlx::Error> {
    let key = &key.as_bytes()[..];
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM verification_attempts WHERE verifying_key = $1) AS 'exists!: bool'"#,
        key
    )
    .fetch_one(conn)
    .await?)
}

async fn delete_old_attempts(conn: &mut sqlx::SqliteConnection) -> Result<u64, sqlx::Error> {
    // threshold: 2min
    let cutoff = (jiff::Timestamp::now() - jiff::Span::new().minutes(2)).to_sqlx();

    let result = sqlx::query!(
        "DELETE FROM verification_attempts WHERE timestamp < $1",
        cutoff
    )
    .execute(conn)
    .await?;

    // Return the number of rows deleted
    Ok(result.rows_affected())
}

#[cfg(test)]
mod test_verification {

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use jiff_sqlx::ToSqlx as _;
    use rand::RngExt as _;

    use crate::db::{self, verification::AddVerificationError};

    #[sqlx::test]
    async fn add_verification(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        db::verification::add_verification_attempt(&mut conn, VerifyingKey::default(), None)
            .await
            .unwrap();
    }

    #[sqlx::test]
    async fn add_verification_and_accept(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        let code =
            db::verification::add_verification_attempt(&mut conn, VerifyingKey::default(), None)
                .await
                .unwrap();

        db::verification::accept_attempt(&mut conn, code, "somehost".to_owned())
            .await
            .unwrap();
    }

    #[sqlx::test]
    async fn accept_nonexistent(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        let err = db::verification::accept_attempt(&mut conn, 0, "somehost".to_owned()).await;
        assert!(err.is_err())
    }

    #[sqlx::test]
    async fn key_already_requestd(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        db::verification::add_verification_attempt(&mut conn, VerifyingKey::default(), None)
            .await
            .unwrap();

        let err =
            db::verification::add_verification_attempt(&mut conn, VerifyingKey::default(), None)
                .await;
        match err {
            Err(AddVerificationError::KeyPendingVerification) => {}
            _ => panic!(),
        }
    }

    #[sqlx::test]
    async fn key_already_in_use(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        db::hosts::add_host(&mut conn, VerifyingKey::default(), "hostname".to_owned())
            .await
            .unwrap();

        let err =
            db::verification::add_verification_attempt(&mut conn, VerifyingKey::default(), None)
                .await;

        match err {
            Err(AddVerificationError::KeyAlreadyInUse) => {}
            _ => panic!(),
        }
    }

    #[sqlx::test]
    async fn no_more_than_10(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        for _ in 0..10 {
            db::verification::add_verification_attempt(
                &mut conn,
                SigningKey::from_bytes(&rand::random()).verifying_key(),
                None,
            )
            .await
            .unwrap();
        }

        let err =
            db::verification::add_verification_attempt(&mut conn, VerifyingKey::default(), None)
                .await;

        match err {
            Err(AddVerificationError::TooManyAttempts) => {}
            _ => panic!(),
        }
    }

    #[sqlx::test]
    async fn delete_old_attempts(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        let id = rand::rng().random_range(100_000..=999_999);

        let before = (jiff::Timestamp::now() - jiff::Span::new().minutes(3)).to_sqlx();
        let key = &[0; 32][..];
        sqlx::query!(
            r#"
            INSERT INTO verification_attempts (id, verifying_key, timestamp,  nixos_facter)
            VALUES ( $1, $2, $3, $4)
            "#,
            id,
            key,
            before,
            None::<String>
        )
        .execute(&mut *conn)
        .await
        .unwrap()
        .last_insert_rowid();

        db::verification::add_verification_attempt(
            &mut conn,
            SigningKey::from_bytes(&rand::random()).verifying_key(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            db::verification::count_attempts(&mut conn).await.unwrap(),
            1 // two were added but only one is still valid
        )
    }
}
