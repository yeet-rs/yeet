use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState, db,
    error::{BadRequest as _, InternalError as _},
    httpsig::{User, VerifiedJson},
};

pub async fn list_hosts(
    State(state): State<YeetState>,
    User(user): User,
) -> Result<Json<Vec<api::Host>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;

    // get all hosts
    let hosts = db::hosts::list_hosts(&mut conn, user)
        .await
        .internal_server()?;

    // // filter them by tags
    // let all_tag = db::tag::is_all_tag(&mut *conn, user)
    //     .await
    //     .internal_server()?;
    // let mut tags =
    //     db::tag::tags_of_resource_by_user(&mut *conn, user, api::tag::ResourceType::Host)
    //         .await
    //         .internal_server()?;
    // if all_tag {
    //     for host in hosts.iter_mut() {
    //         if let Some(tags) = tags.remove(&api::tag::Resource::from(host.id)) {
    //             host.tags = tags;
    //         }
    //     }
    // } else {
    //     let all_hosts = hosts;
    //     hosts = Vec::new();
    //     for mut host in all_hosts {
    //         if let Some(tags) = tags.remove(&api::tag::Resource::from(host.id)) {
    //             host.tags = tags;
    //             hosts.push(host);
    //         }
    //     }
    // }

    Ok(Json(hosts))
}

pub async fn rename_host(
    State(state): State<YeetState>,
    Path((id, name)): Path<(api::HostID, String)>,
    User(user): User,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_tag(&mut conn, user, id.into()).await?;
    db::hosts::rename(&mut conn, id, name)
        .await
        .internal_server()?;
    Ok(StatusCode::OK)
}

/// Endpoint to set a new version for a host.
/// The whole request needs to be signed by a build machine.
/// The update consist of a simple `key` -> `version` and a `substitutor` which is where the agent should get its update
/// This means that for each origin e.g. cachix, you need to call update seperately
pub async fn update_hosts(
    State(state): State<YeetState>,
    User(user): User,

    VerifiedJson(api::HostUpdateRequest {
        hosts,
        public_key,
        substitutor,
    }): VerifiedJson<api::HostUpdateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    db::tag::auth_build(&mut conn, user).await?;
    for host in hosts.keys() {
        let Ok(Some(host)) = db::hosts::host_by_hostname(&mut conn, host).await else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Host `{host}` does not exist".to_owned(),
            ));
        };
        db::tag::auth_tag(&mut conn, user, api::tag::Resource::from(host)).await?;
    }

    db::hosts::update(&mut conn, hosts.iter(), public_key, substitutor)
        .await
        .bad_request()?;

    Ok(StatusCode::CREATED)
}

// #[cfg(test)]
// mod test_host {

//     use axum_test::TestServer;
//     use ed25519_dalek::VerifyingKey;
//     use sqlx::SqlitePool;

//     async fn add_host(server: &TestServer) {
//         let code: i64 = server
//             .post("/verification/add")
//             .json(&api::VerificationAttempt {
//                 key: VerifyingKey::default(),
//                 nixos_facter: Some("hi".to_owned()),
//             })
//             .await
//             .json();

//         assert!(code >= 100_000 && code <= 999_999);

//         let facter: Option<String> = server
//             .put(&format!("/verification/{code}/accept"))
//             .json(&"myhost".to_owned())
//             .await
//             .json();
//         assert_eq!(facter, Some("hi".to_owned()));
//     }

//     #[sqlx::test]
//     async fn list(pool: SqlitePool) {
//         let server = crate::test_server(pool.clone()).await;

//         add_host(&server).await;

//         let hosts: Vec<api::Host> = server.get("/host/list").await.json();

//         assert_eq!(
//             hosts,
//             vec![api::Host {
//                 id: api::HostID::new(1),
//                 key: VerifyingKey::default(),
//                 hostname: "myhost".to_owned(),
//                 state: api::ProvisionState::NotSet,
//                 last_ping: jiff::Timestamp::now(),
//                 version: None,
//                 latest_update: None
//             }]
//         );
//     }

//     #[sqlx::test]
//     async fn rename(pool: SqlitePool) {
//         let server = crate::test_server(pool.clone()).await;

//         add_host(&server).await;

//         server.put("/host/1/rename/otherhost").await;

//         let hosts: Vec<api::Host> = server.get("/host/list").await.json();

//         assert_eq!(
//             hosts,
//             vec![api::Host {
//                 id: api::HostID::new(1),
//                 key: VerifyingKey::default(),
//                 hostname: "otherhost".to_owned(),
//                 state: api::ProvisionState::NotSet,
//                 last_ping: jiff::Timestamp::now(),
//                 version: None,
//                 latest_update: None
//             }]
//         );
//     }

//     #[sqlx::test]
//     async fn delete(pool: SqlitePool) {
//         let server = crate::test_server(pool.clone()).await;

//         add_host(&server).await;

//         server
//             .delete("/key/delete")
//             .json(&VerifyingKey::default())
//             .await;

//         let hosts: Vec<api::Host> = server.get("/host/list").await.json();

//         assert_eq!(hosts, vec![]);
//     }
// }
