pub enum Host {
    /// Rename the hostname of an existing host
    Rename,
    /// Delete an host in its interiety (destructive!)
    Remove,
    /// Publish an update for a hosts (use carefully!)
    Update,
    /// Accept an verification attempt (e.g. Adding new hosts)
    Accept,
    /// Attach ANOTHER host
    Attach,
    /// Set Detach permission per host
    DetachPermission,
}
pub enum Settings {
    /// Set global detach permission
    DetachGlobal,
}

pub enum Secret {
    /// Add new secrets or replace the content of existing secrets
    CreateOrUpdate,
    /// Rename an existing secret
    Rename,
    /// Delete secrets
    Remove,
    /// Define which host is allowed to access which secret
    /// TODO: should a user see that host a can access secret x if user does not have visibility on host a
    ACL,
    /// Define which secrets whould be viewable
    ListSecrets,
}

pub enum Status {
    ListHosts,
    ListHostnameByKey,
}
