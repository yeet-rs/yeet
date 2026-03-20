// use zbus::Connection;
// use zbus_polkit::policykit1::{
//     AuthorityProxy, AuthorizationResult, CheckAuthorizationFlags, Subject,
// };

#[derive(thiserror::Error, Debug)]
pub enum PolkitError {
    #[error("Could not connect to polkit dbus")]
    ZBusError(#[from] zbus::Error),
    #[error("Could not get start time of the subject process")]
    SubjectError(#[from] zbus_polkit::Error),
}

// pub async fn detach(pid: u32, uid: u32) -> Result<AuthorizationResult, PolkitError> {
//     let connection = Connection::system().await?;
//     let proxy = AuthorityProxy::new(&connection).await?;
//     let subject = Subject::new_for_owner(pid, None, Some(uid))?;
//     Ok(proxy
//         .check_authorization(
//             &subject,
//             "ch.yeetme.yeet.Detach",
//             &std::collections::HashMap::new(),
//             CheckAuthorizationFlags::AllowUserInteraction.into(),
//             "",
//         )
//         .await?)
// }
