use std::str::FromStr as _;

use ed25519_dalek::SigningKey;
use httpsig_hyper::prelude::{AlgorithmName, SecretKey};
use yeet_api as api;

/// Register a host through the real enrollment flow and return its key and id
#[expect(
    clippy::unwrap_used,
    reason = "test helper: a failed setup should panic"
)]
async fn enroll(
    url: &url::Url,
    admin: &SecretKey,
    seed: u8,
    hostname: &str,
) -> (SecretKey, api::HostID) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[seed; 32]).unwrap();

    let code = api::add_verification_attempt(
        url,
        &key,
        api::VerificationAttempt {
            key: signing.verifying_key(),
            nixos_facter: None,
        },
    )
    .await
    .unwrap();
    api::accept_attempt(url, admin, code as u32, hostname)
        .await
        .unwrap();

    let id = api::list_hosts(url, admin)
        .await
        .unwrap()
        .into_iter()
        .find(|host| host.hostname == hostname)
        .unwrap()
        .id;
    (key, id)
}

/// HTTP status of a failed request
#[expect(
    clippy::panic,
    clippy::rest_pattern_accessible_field,
    clippy::wildcard_enum_match_arm,
    reason = "test helper: anything but a server error means the test setup is broken"
)]
fn status_code(err: api::ResponseError) -> http::StatusCode {
    match err {
        api::ResponseError::ServerError { code, .. } => code,
        other => panic!("expected a server error, got {other}"),
    }
}

fn report(state: api::TaskState, message: Option<&str>) -> api::TaskReport {
    api::TaskReport {
        state,
        message: message.map(ToOwned::to_owned),
    }
}

#[sqlx::test]
#[expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate"
)]
async fn tasks_e2e(pool: sqlx::SqlitePool) {
    let _handle = yeetd::launch(yeetd::Config {
        addr: "[::1]:4340".parse().unwrap(),
        pool,
        age_key: age::x25519::Identity::generate(),
        tls: None,
        splunk: None,
        osquery_packs: indexmap::IndexMap::default(),
    })
    .await;
    let url = url::Url::from_str("http://localhost:4340").unwrap();

    // bootstrap, the first user can be created without credentials
    let admin = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[4; 32]).unwrap();
    api::create_user(
        &url,
        &admin,
        api::CreateUser {
            key: SigningKey::from_bytes(&[4; 32]).verifying_key(),
            level: api::AuthLevel::Admin,
            username: "admin".into(),
            all_tag: true,
        },
    )
    .await
    .unwrap();

    let (host_a, host_a_id) = enroll(&url, &admin, 3, "host-a").await;

    // === task types the server doesn't know are rejected right away
    let err = api::create_task(&url, &admin, host_a_id, &api::HostTask::Unknown)
        .await
        .unwrap_err();
    assert_eq!(status_code(err), http::StatusCode::BAD_REQUEST);

    // === nothing queued, nothing to fetch
    assert_eq!(api::get_tasks(&url, &host_a).await.unwrap(), []);

    // === authorization
    // a host must not create tasks
    let err = api::create_task(&url, &host_a, host_a_id, &api::HostTask::Unknown)
        .await
        .unwrap_err();
    assert_eq!(status_code(err), http::StatusCode::FORBIDDEN);

    // an admin is not a host and must not fetch task payloads
    let err = api::get_tasks(&url, &admin).await.unwrap_err();
    assert_eq!(status_code(err), http::StatusCode::FORBIDDEN);

    // a leaked CI key (Build) must not be able to queue anything
    api::create_user(
        &url,
        &admin,
        api::CreateUser {
            key: SigningKey::from_bytes(&[6; 32]).verifying_key(),
            level: api::AuthLevel::Build,
            username: "ci".into(),
            all_tag: true,
        },
    )
    .await
    .unwrap();
    let build = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[6; 32]).unwrap();
    let err = api::create_task(&url, &build, host_a_id, &api::HostTask::Unknown)
        .await
        .unwrap_err();
    assert_eq!(status_code(err), http::StatusCode::FORBIDDEN);

    // === tasks that don't exist. TaskID::new needs the hazard feature which we
    // get for free through the yeetd dev dependency
    let missing = api::TaskID::new(9999);
    let err = api::task_status(&url, &admin, missing).await.unwrap_err();
    assert_eq!(status_code(err), http::StatusCode::NOT_FOUND);
    let err = api::report_task(&url, &host_a, missing, report(api::TaskState::Done, None))
        .await
        .unwrap_err();
    assert_eq!(status_code(err), http::StatusCode::NOT_FOUND);

    // === hosts may only report a final state
    let err = api::report_task(
        &url,
        &host_a,
        missing,
        report(api::TaskState::Pending, None),
    )
    .await
    .unwrap_err();
    assert_eq!(status_code(err), http::StatusCode::BAD_REQUEST);
}
