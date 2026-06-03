use std::str::FromStr as _;

use ed25519_dalek::SigningKey;
use httpsig_hyper::prelude::{AlgorithmName, SecretKey};
use yeet_api::{self as api};

#[sqlx::test]
async fn artifacts(pool: sqlx::SqlitePool) {
    let _handle = yeetd::launch(yeetd::Config {
        addr: "[::1]:4334".parse().unwrap(),
        pool,
        age_key: age::x25519::Identity::generate(),
        tls: None,
        splunk: None,
        osquery_packs: indexmap::IndexMap::default(),
        defectdojo: None,
    })
    .await;

    let url = url::Url::from_str("http://localhost:4334").unwrap();

    // first we need to add our admin credentials.
    // The api will allow us to add it when no credentials are specified yet

    let admin_key = SigningKey::from_bytes(&[4; 32]);
    let key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[4; 32]).unwrap();

    api::create_user(
        &url,
        &key,
        api::CreateUser {
            key: admin_key.verifying_key(),
            level: api::AuthLevel::Admin,
            username: "mysuperadmin".into(),
            all_tag: true,
        },
    )
    .await
    .unwrap();

    // The first thing a new host does is to create a verification attempt
    let new_host = SigningKey::from_bytes(&[3; 32]);
    let client_key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[3; 32]).unwrap();

    let code = api::add_verification_attempt(
        &url,
        &client_key,
        api::VerificationAttempt {
            key: new_host.verifying_key(),
            nixos_facter: Some("Just some facts about a host".into()),
        },
    )
    .await
    .unwrap();

    assert!((100_000..=999_999).contains(&code));

    // The next thing is for an admin to approve this request
    let facter = api::accept_attempt(&url, &key, code as u32, "mysuperhostname")
        .await
        .unwrap();

    assert_eq!(facter, Some("Just some facts about a host".into()));

    // now the host may want to store an artifact
    api::store_artifact(&url, &client_key, "luks-key", b"my-luks-key")
        .await
        .unwrap();

    // we can list this artifact
    let artifacts = api::list_artifacts(&url, &key).await.unwrap();

    assert_eq!(artifacts.first().unwrap().name, "luks-key".to_owned());

    // and retrive the content
    let content = api::get_artifact_by_id(&url, &key, artifacts.first().unwrap().id)
        .await
        .unwrap();

    assert_eq!(content, b"my-luks-key");

    // the client can retrieve it via its name
    let content = api::get_artifact_by_name(&url, &client_key, "luks-key".into())
        .await
        .unwrap();

    assert_eq!(content, Some(b"my-luks-key".into()));

    // rewrite is also possible
    api::store_artifact(&url, &client_key, "luks-key", b"my-new-luks-key")
        .await
        .unwrap();

    // by name will give the new result
    let content = api::get_artifact_by_name(&url, &client_key, "luks-key".into())
        .await
        .unwrap();

    assert_eq!(content, Some(b"my-new-luks-key".into()));

    // list will show both
    let artifacts = api::list_artifacts(&url, &key).await.unwrap();
    assert_eq!(artifacts.len(), 2);
}
