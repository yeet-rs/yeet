use std::{collections::HashMap, str::FromStr as _};

use ed25519_dalek::SigningKey;
use httpsig_hyper::prelude::{AlgorithmName, SecretKey};
use yeet_api::{self as api};

#[sqlx::test]
fn api_e2e_with_credentials(pool: sqlx::SqlitePool) {
    let _handle = yeetd::launch(
        4337,
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        pool,
        age::x25519::Identity::generate(),
        None,
        None,
    )
    .await;

    let url = url::Url::from_str("http://localhost:4337").unwrap();

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

    // Now that we have a host we may want to list it
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().hostname,
        "mysuperhostname".to_owned()
    );
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::NotSet);
    assert_eq!(hosts.first().unwrap().version, None);
    assert_eq!(hosts.first().unwrap().latest_update, None);

    // lets push an update to the host
    api::update_hosts(
        &url,
        &key,
        api::HostUpdateRequest {
            hosts: HashMap::from([("mysuperhostname".into(), "mysuperversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        },
    )
    .await
    .unwrap();
    // Now it should be provisioned and have an latest_update. no latest_version tough
    let hosts = api::list_hosts(&url, &key).await.unwrap();

    assert_eq!(
        hosts.first().unwrap().state,
        api::ProvisionState::Provisioned
    );
    assert_eq!(hosts.first().unwrap().version, None);
    assert_eq!(
        hosts.first().unwrap().latest_update,
        Some("mysuperversion".into())
    );

    // We simulate that the hosts now has pinged the system but provided an old version
    // Yeet now tasks the agent to update
    let action = api::check_system(
        &url,
        &client_key,
        api::VersionRequest {
            store_path: "myoldversion".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        action,
        api::AgentAction::SwitchTo(api::RemoteStorePath {
            public_key: "mypublickey".into(),
            store_path: "mysuperversion".into(),
            substitutor: "mycache".into()
        })
    );

    // If we do not udpate yet but look at the host we see that he has now an latest version
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().version, Some("myoldversion".into()));

    // The agent now signals the server that he has done the update
    let action = api::check_system(
        &url,
        &client_key,
        api::VersionRequest {
            store_path: "mysuperversion".into(),
        },
    )
    .await
    .unwrap();
    // The server is satisfied and does not require the agent to do anything
    assert_eq!(action, api::AgentAction::Nothing);

    // The server reflects the update
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().version,
        Some("mysuperversion".into())
    );

    // Kinda bored of `mysuperhostname` lets rename it
    api::rename_host(&url, &key, hosts.first().unwrap().id, "mynewname")
        .await
        .unwrap();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().hostname, "mynewname".to_owned());

    // The agent now decide he no longer wants to listen to the server and detaches

    api::detach_self(&url, &client_key).await.unwrap();

    // This is shown as state: Detach
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::Detached);

    // And as `AgentAction::Detach`
    let action = api::check_system(
        &url,
        &client_key,
        api::VersionRequest {
            store_path: "mydetachedversion".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(action, api::AgentAction::Detach);

    // But the version information is still logged
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().version,
        Some("mydetachedversion".into())
    );

    // even if we push an update the agent stays detached
    api::update_hosts(
        &url,
        &key,
        api::HostUpdateRequest {
            hosts: HashMap::from([("mynewname".into(), "mynewversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        },
    )
    .await
    .unwrap();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::Detached);

    // Ok but now stop fooling around and attach again
    api::attach_self(&url, &client_key).await.unwrap();

    // The agent is managed again
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().state,
        api::ProvisionState::Provisioned
    );

    // And forced to switch to the new version
    let action = api::check_system(
        &url,
        &client_key,
        api::VersionRequest {
            store_path: "mydetachedversion".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        action,
        api::AgentAction::SwitchTo(api::RemoteStorePath {
            public_key: "mypublickey".into(),
            store_path: "mynewversion".into(),
            substitutor: "mycache".into()
        })
    );
    // lets be nice and do the update
    let action = api::check_system(
        &url,
        &client_key,
        api::VersionRequest {
            store_path: "mynewversion".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(action, api::AgentAction::Nothing);
    // make sure the server tells the same story
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().version, Some("mynewversion".into()));

    // Ok now maybe we want to create a secret for the host
    // first we have to get the encryption key of the server
    let server_key = api::server_age_key(&url, &key).await.unwrap();
    let server_key = age::x25519::Recipient::from_str(&server_key).unwrap();
    let _ups = api::create_secret(
        &url,
        &key,
        "mysecret",
        &age::encrypt(&server_key, b"secretstuff").unwrap(),
    )
    .await
    .unwrap();

    // the client tries to get the secret but fails because he is not authorized
    // but first the client needs to generate a recipient key

    let secret = api::get_secret(&url, &client_key, "mysecret".into())
        .await
        .unwrap();
    assert!(secret.is_none());

    // so lets give the client permission. but oh wait i forgor the note the secretid and hostid
    // lets list all secrets
    let secrets = api::list_secrets(&url, &key).await.unwrap();
    let secret = secrets.first().unwrap();
    assert_eq!(secret.name, "mysecret".to_owned());

    // and hosts
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    let host = hosts.first().unwrap();
    assert_eq!(host.hostname, "mynewname".to_owned());

    // now allow the host
    api::allow_host(&url, &key, secret.id, host.id)
        .await
        .unwrap();

    // the client can now get the secret
    let secret = api::get_secret(&url, &client_key, "mysecret".into())
        .await
        .unwrap();
    assert_eq!(secret, Some(b"secretstuff".to_vec()));
}

#[sqlx::test]
fn api_e2e_with_non_superuser(pool: sqlx::SqlitePool) {
    let _handle = yeetd::launch(
        4338,
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        pool,
        age::x25519::Identity::generate(),
        None,
        None,
    )
    .await;

    let url = url::Url::from_str("http://localhost:4338").unwrap();

    // first we need to add our admin credentials.
    // The api will allow us to add it when no credentials are specified yet

    let admin_signing_key = SigningKey::from_bytes(&[4; 32]);
    let admin_key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[4; 32]).unwrap();

    api::create_user(
        &url,
        &admin_key,
        api::CreateUser {
            key: admin_signing_key.verifying_key(),
            level: api::AuthLevel::Admin,
            username: "mysuperadmin".into(),
            all_tag: true,
        },
    )
    .await
    .unwrap();

    // To test the scoping of tags we want to create a new user that does not see all tags
    let signing_key = SigningKey::from_bytes(&[5; 32]);
    let key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[5; 32]).unwrap();

    let normal_admin = api::create_user(
        &url,
        &admin_key, // the admin user thas to create the key
        api::CreateUser {
            key: signing_key.verifying_key(),
            level: api::AuthLevel::Admin, // he es still an admin e.g. can modify stuff - just not an suepr admin
            username: "mynormaladmin".into(),
            all_tag: false,
        },
    )
    .await
    .unwrap();

    // The first thing a new host does is to create a verification attempt
    let new_host = SigningKey::from_bytes(&[3; 32]);

    let code = api::add_verification_attempt(
        &url,
        &key,
        api::VerificationAttempt {
            key: new_host.verifying_key(),
            nixos_facter: Some("Just some facts about a host".into()),
        },
    )
    .await
    .unwrap();

    assert!((100_000..=999_999).contains(&code));

    // A normal admin is not allowed to accept verify requests
    let _err = api::accept_attempt(&url, &key, code as u32, "mysuperhostname")
        .await
        .unwrap_err();

    // but our admin can
    let facter = api::accept_attempt(&url, &admin_key, code as u32, "mysuperhostname")
        .await
        .unwrap();

    assert_eq!(facter, Some("Just some facts about a host".into()));

    // our admin can see the host
    let hosts = api::list_hosts(&url, &admin_key).await.unwrap();
    assert!(hosts.len() == 1);

    // our normal admin can't
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 0);

    // our normal admin can't push updates on hosts he does not own
    api::update_hosts(
        &url,
        &key,
        api::HostUpdateRequest {
            hosts: HashMap::from([("mysuperhostname".into(), "mysuperversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        },
    )
    .await
    .unwrap_err();

    // or rename even if does know the id
    let hosts = api::list_hosts(&url, &admin_key).await.unwrap();
    api::rename_host(&url, &key, hosts.first().unwrap().id, "mynewname")
        .await
        .unwrap_err();

    api::delete_key(&url, &key, hosts.first().unwrap().key)
        .await
        .unwrap_err();

    // most importantly he has no permission to create new users
    let never_key = SigningKey::from_bytes(&[6; 32]);

    api::create_user(
        &url,
        &key,
        api::CreateUser {
            key: never_key.verifying_key(),
            level: api::AuthLevel::Admin,
            username: "never".into(),
            all_tag: false,
        },
    )
    .await
    .unwrap_err();

    // But we can give him access to some resources with tags
    // our normal admin can't create tags
    api::tag::create_tag(&url, &key, "mytag").await.unwrap_err();

    let tag = api::tag::create_tag(&url, &admin_key, "mytag")
        .await
        .unwrap();

    // Even if he knows the tag he can't give him access to resources
    let hosts = api::list_hosts(&url, &admin_key).await.unwrap();
    api::tag::tag_resource(
        &url,
        &key,
        api::tag::ResourceTag {
            resource: hosts.first().unwrap().id.into(),
            tag,
        },
    )
    .await
    .unwrap_err();

    api::tag::tag_resource(
        &url,
        &admin_key,
        api::tag::ResourceTag {
            resource: hosts.first().unwrap().id.into(),
            tag,
        },
    )
    .await
    .unwrap();
    let hosts = api::list_hosts(&url, &admin_key).await.unwrap();

    assert_eq!(
        hosts.first().unwrap().tags.first().unwrap().name,
        "mytag".to_owned()
    );

    // but this is still not visisble to my normal admin
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 0);

    // because we first have to create an policy so that our user is able to
    // view `mytag`
    api::tag::tag_allow_user(&url, &key, tag, normal_admin)
        .await
        .unwrap_err();
    api::tag::tag_allow_user(&url, &admin_key, tag, normal_admin)
        .await
        .unwrap();

    // now he can see the host
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 1);

    // and also modify it
    api::rename_host(&url, &key, hosts.first().unwrap().id, "mynewname")
        .await
        .unwrap();

    // even push updates
    api::update_hosts(
        &url,
        &key,
        api::HostUpdateRequest {
            hosts: HashMap::from([("mynewname".into(), "mysuperversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        },
    )
    .await
    .unwrap();

    // even if we rename the tag
    // he can't rename the tag
    api::tag::rename_tag(&url, &key, tag, "newname")
        .await
        .unwrap_err();

    api::tag::rename_tag(&url, &admin_key, tag, "newname")
        .await
        .unwrap();

    let _tags = api::tag::list_tags(&url, &key).await.unwrap_err();
    let tags = api::tag::list_tags(&url, &admin_key).await.unwrap();
    assert_eq!(tags.first().unwrap().name, "newname");

    // or the user
    api::rename_user(&url, &key, normal_admin, "newname")
        .await
        .unwrap_err();

    api::rename_user(&url, &admin_key, normal_admin, "newname")
        .await
        .unwrap();

    let users = api::list_users(&url, &admin_key).await.unwrap();
    assert_eq!(users.get(1).unwrap().username, "newname");

    // the host is still visible
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 1);

    // lets create a new tag that he has no access
    api::tag::create_tag(&url, &admin_key, "mysupertag")
        .await
        .unwrap();

    // if we look at the users he does only have one tag
    let users = api::list_users(&url, &admin_key).await.unwrap();
    assert_eq!(users.get(1).unwrap().tags.len(), 1);

    // if we remove the tag from the resource he will no longer be able to see but still have access to the tag
    let rtag = api::tag::ResourceTag {
        resource: hosts.first().unwrap().id.into(),
        tag,
    };
    api::tag::delete_resource_from_tag(&url, &key, rtag)
        .await
        .unwrap_err();

    api::tag::delete_resource_from_tag(&url, &admin_key, rtag)
        .await
        .unwrap();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 0);

    let users = api::list_users(&url, &admin_key).await.unwrap();
    assert_eq!(users.get(1).unwrap().tags.len(), 1);

    // so if a new resource gets this tag he will inherit access to the resource
    api::tag::tag_resource(&url, &admin_key, rtag)
        .await
        .unwrap();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 1);

    // we can't tag a resoruce twice
    api::tag::tag_resource(&url, &admin_key, rtag)
        .await
        .unwrap_err();

    // the other way is to let the tag stay and instead remove the user
    api::tag::tag_remove_user(&url, &key, tag, normal_admin)
        .await
        .unwrap_err();

    api::tag::tag_remove_user(&url, &admin_key, tag, normal_admin)
        .await
        .unwrap();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 0);

    // allow him again
    api::tag::tag_allow_user(&url, &admin_key, tag, normal_admin)
        .await
        .unwrap();
    // can't do it twice tough
    api::tag::tag_allow_user(&url, &admin_key, tag, normal_admin)
        .await
        .unwrap_err();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 1);

    // lets delete the tag so that he loses access
    api::tag::delete_tag(&url, &key, tag).await.unwrap_err();

    api::tag::delete_tag(&url, &admin_key, tag).await.unwrap();

    // the host is no longer
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert!(hosts.len() == 0);

    // lets delete the admin but het tries to delete us
    api::delete_key(&url, &key, admin_signing_key.verifying_key())
        .await
        .unwrap_err();

    api::delete_key(&url, &admin_key, signing_key.verifying_key())
        .await
        .unwrap();

    let users = api::list_users(&url, &admin_key).await.unwrap();

    assert_eq!(users.len(), 1);
}

#[sqlx::test]
fn api_secrets_with_tags(pool: sqlx::SqlitePool) {
    let _handle = yeetd::launch(
        4339,
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        pool,
        age::x25519::Identity::generate(),
        None,
        None,
    )
    .await;

    let url = url::Url::from_str("http://localhost:4339").unwrap();

    // first we need to add our admin credentials.
    // The api will allow us to add it when no credentials are specified yet

    let admin_signing_key = SigningKey::from_bytes(&[4; 32]);
    let admin_key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[4; 32]).unwrap();

    api::create_user(
        &url,
        &admin_key,
        api::CreateUser {
            key: admin_signing_key.verifying_key(),
            level: api::AuthLevel::Admin,
            username: "mysuperadmin".into(),
            all_tag: true,
        },
    )
    .await
    .unwrap();

    // To test the scoping of tags we want to create a new user that does not see all tags
    let signing_key = SigningKey::from_bytes(&[5; 32]);
    let key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[5; 32]).unwrap();

    let normal_admin = api::create_user(
        &url,
        &admin_key, // the admin user thas to create the key
        api::CreateUser {
            key: signing_key.verifying_key(),
            level: api::AuthLevel::Admin, // he es still an admin e.g. can modify stuff - just not an suepr admin
            username: "mynormaladmin".into(),
            all_tag: false,
        },
    )
    .await
    .unwrap();

    // The first thing a new host does is to create a verification attempt
    let new_host = SigningKey::from_bytes(&[3; 32]);

    let code = api::add_verification_attempt(
        &url,
        &key,
        api::VerificationAttempt {
            key: new_host.verifying_key(),
            nixos_facter: Some("Just some facts about a host".into()),
        },
    )
    .await
    .unwrap();

    assert!((100_000..=999_999).contains(&code));

    // A normal admin is not allowed to accept verify requests
    // but our admin can
    let facter = api::accept_attempt(&url, &admin_key, code as u32, "mysuperhostname")
        .await
        .unwrap();

    assert_eq!(facter, Some("Just some facts about a host".into()));

    // our admin can see the host
    let hosts = api::list_hosts(&url, &admin_key).await.unwrap();
    assert!(hosts.len() == 1);

    // our normal_admin can't create new secrets
    let server_key = api::server_age_key(&url, &key).await.unwrap();
    let server_key = age::x25519::Recipient::from_str(&server_key).unwrap();
    let encrypted = age::encrypt(&server_key, b"secret").unwrap();

    api::create_secret(&url, &key, "supersecret", &encrypted)
        .await
        .unwrap_err();

    // so we have to create it for him
    let secret = api::create_secret(&url, &admin_key, "supersecret", &encrypted)
        .await
        .unwrap();

    // but he can't see it yet
    let secrets = api::list_secrets(&url, &key).await.unwrap();
    assert!(secrets.is_empty());

    // so we create a tag on the secret
    let mytag = api::tag::create_tag(&url, &admin_key, "mytag")
        .await
        .unwrap();

    api::tag::tag_resource(
        &url,
        &admin_key,
        api::tag::ResourceTag {
            resource: secret.id.into(),
            tag: mytag,
        },
    )
    .await
    .unwrap();

    // and now give him access
    api::tag::tag_allow_user(&url, &admin_key, mytag, normal_admin)
        .await
        .unwrap();

    // now he can see the secret
    let secrets = api::list_secrets(&url, &key).await.unwrap();
    assert!(secrets.len() == 1);

    // but if we create a second tag that the user does not see he will still se the secret but not the second tag
    let newtag = api::tag::create_tag(&url, &admin_key, "newtag")
        .await
        .unwrap();

    api::tag::tag_resource(
        &url,
        &admin_key,
        api::tag::ResourceTag {
            resource: secret.id.into(),
            tag: newtag,
        },
    )
    .await
    .unwrap();

    // he only sees his own tag
    let secrets = api::list_secrets(&url, &key).await.unwrap();
    assert!(secrets.first().unwrap().tags.len() == 1);

    // we see all tags
    let secrets = api::list_secrets(&url, &admin_key).await.unwrap();
    assert!(secrets.first().unwrap().tags.len() == 2);

    // and if we allow a host to access this secret our normal admin wont see it

    let hosts = api::list_hosts(&url, &admin_key).await.unwrap();
    let host = hosts.first().unwrap();

    // he can't allow the host even if he owns the secret
    api::allow_host(&url, &key, secret.id, host.id)
        .await
        .unwrap_err();

    api::allow_host(&url, &admin_key, secret.id, host.id)
        .await
        .unwrap();

    let secrets = api::list_secrets(&url, &key).await.unwrap();
    assert!(secrets.first().unwrap().hosts.is_empty());

    // but we can give the host the same `mytag` which normal_admin has access to
    assert!(api::list_hosts(&url, &key).await.unwrap().is_empty());
    api::tag::tag_resource(
        &url,
        &key,
        api::tag::ResourceTag {
            resource: host.id.into(),
            tag: mytag,
        },
    )
    .await
    .unwrap_err();

    api::tag::tag_resource(
        &url,
        &admin_key,
        api::tag::ResourceTag {
            resource: host.id.into(),
            tag: mytag,
        },
    )
    .await
    .unwrap();

    // now he can see the host
    let secrets = api::list_secrets(&url, &key).await.unwrap();
    assert!(secrets.first().unwrap().hosts.len() == 1);

    assert!(api::list_hosts(&url, &key).await.unwrap().len() == 1);

    // since he has now permission for both the host AND the secret he can modify the acl
    api::block_host(&url, &key, secret.id, host.id)
        .await
        .unwrap();

    let secrets = api::list_secrets(&url, &key).await.unwrap();
    assert!(secrets.first().unwrap().hosts.len() == 0);

    // or add the host
    api::allow_host(&url, &key, secret.id, host.id)
        .await
        .unwrap();

    let secrets = api::list_secrets(&url, &key).await.unwrap();
    assert!(secrets.first().unwrap().hosts.len() == 1);

    // he can even rename or delete the secret
    api::rename_secret(&url, &key, secret.id, "new_secret_name")
        .await
        .unwrap();
    api::delete_secret(&url, &key, secret.id).await.unwrap();
}
