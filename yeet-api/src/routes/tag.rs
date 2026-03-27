use std::hash::Hash;

use serde::{Deserialize, Serialize};

// use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param};
use crate::{HostID, SecretID, UserID, request};

crate::db_id!(TagID);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]

pub struct Tag {
    pub id: TagID,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
pub enum ResourceType {
    Host,
    Secret,
    // Users
    // Tags
    // Policies
}

impl ResourceType {
    pub fn with_id(&self, id: i64) -> Resource {
        match self {
            ResourceType::Host => Resource::Host(HostID(id)),
            ResourceType::Secret => Resource::Secret(SecretID(id)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Resource {
    Host(HostID),
    Secret(SecretID),
    // Users
    // Tags
    // Policies
}

impl From<Resource> for ResourceType {
    fn from(value: Resource) -> Self {
        match value {
            Resource::Host(_) => Self::Host,
            Resource::Secret(_) => Self::Secret,
        }
    }
}

impl From<Resource> for i64 {
    fn from(value: Resource) -> Self {
        match value {
            Resource::Host(id) => id.0,
            Resource::Secret(id) => id.0,
        }
    }
}

impl From<SecretID> for Resource {
    fn from(value: SecretID) -> Self {
        Self::Secret(value)
    }
}

impl From<HostID> for Resource {
    fn from(value: HostID) -> Self {
        Self::Host(value)
    }
}

request! (
    create_tag(name: &str),
    post("/tag/create/{name}") -> TagID
);

request! (
    rename_tag(tag: TagID, name: &str),
    put("/tag/{tag}/rename/{name}") -> StatusCode
);

request! (
    delete_tag(tag: TagID),
    delete("/tag/{tag}/delete") -> StatusCode
);

request! (
    tag_allow_user(tag: TagID, user: UserID),
    put("/tag/{tag}/allow/{user}") -> StatusCode
);

request! (
    tag_remove_user(tag: TagID, user: UserID),
    delete("/tag/{tag}/remove/{user}") -> StatusCode
);

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ResourceTag {
    pub resource: Resource,
    pub tag: TagID,
}

request! (
    tag_resource(resource: ResourceTag),
    put("/resource/add_tag") -> StatusCode,
    body: &resource
);

request! (
    delete_resource_from_tag(resource: ResourceTag),
    delete("/resource/delete_tag") -> StatusCode,
    body: &resource
);

request! (
    list_tags(),
    get("/tag") -> Vec<Tag>
);

// pub type Tag = uuid::Uuid;
// pub type TagSet = HashSet<Tag>;

// pub const ALL_TAGS: Tag = uuid!("00000000-0000-0000-0000-000000000000");

// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
// pub enum Host {
//     /// View properties of an host
//     View,
//     /// Rename the hostname of an existing host
//     Rename,
//     /// Delete an host in its interiety (destructive!)
//     Delete,
//     /// Publish an update for a hosts (use carefully!)
//     Update,
//     /// Accept an verification attempt (e.g. Adding new hosts)
//     Accept,
// }

// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
// pub enum Secret {
//     /// Shows the secret and its ACL
//     View,
//     /// Add new secrets
//     Create,
//     /// Allow an host to access a secret (requires `View` on the target host)
//     Allow,
//     /// Same as `Allow` but removes access
//     Block,
//     /// Rename an existing secret
//     Rename,
//     /// Delete secrets
//     Delete,
// }

// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
// pub enum Policy {
//     /// Create or replace a a policy
//     Set,
//     /// List all policies that exist
//     ListAll,
// }

// This is only used to group all the actions und one enum so they can be stored in one place
// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
// pub enum Action {
//     Host(Host),
//     Secret(Secret),
//     // Policy(Policy),
//     ALL,
// }

// impl From<Host> for Action {
//     fn from(value: Host) -> Self {
//         Self::Host(value)
//     }
// }

// impl From<Secret> for Action {
//     fn from(value: Secret) -> Self {
//         Self::Secret(value)
//     }
// }

// impl From<Policy> for Action {
//     fn from(value: Policy) -> Self {
//         Self::Policy(value)
//     }
// }
