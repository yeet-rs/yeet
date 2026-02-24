use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

pub type Tag = uuid::Uuid;
pub type TagSet = HashSet<Tag>;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Settings {
    /// Set global detach permission
    DetachGlobal,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Status {
    ListHosts,
    ListHostnameByKey,
}

/// This is only used to group all the actions und one enum so they can be stored in one place
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Action {
    Host(Host),
    Settings(Settings),
    Secret(Secret),
    Status(Status),
}

impl From<Host> for Action {
    fn from(value: Host) -> Self {
        Self::Host(value)
    }
}

impl From<Settings> for Action {
    fn from(value: Settings) -> Self {
        Self::Settings(value)
    }
}

impl From<Secret> for Action {
    fn from(value: Secret) -> Self {
        Self::Secret(value)
    }
}

impl From<Status> for Action {
    fn from(value: Status) -> Self {
        Self::Status(value)
    }
}

/// There are two possible solution on how to implement the Policy Store.
/// One possible solution is to let the consumer decide how tags are stored
/// This also means that the consumer has to keep tag consistency when deletion / renames happen
/// The benefit is that no complex mapping between some id and the tag name has to be done.
/// On the other hand this gives more burden for the consumer
///
/// The alternative is to only give back an unique id to the consumer.
/// When deleting a tag the reference of the consumer would just be non existent.
/// This improves security because all information is contained in the Policy Store
/// The drawback is to fetch the name the client has to do a lookup.
///
/// A middle ground would be to return the current name and an id like Tag {name , id}
/// The consumer would still have to implement the renaming of tags etc but this would improve security
///
/// # Example
/// ```
/// use yeet_api::auth;
/// let owner = String::from("my_user"); // The owner can be of any type. You need to make sure this is unique and the correct owner
///
/// let mut store = auth::PolicyStore::<String>::default(); // Create a new store
/// let tag = store.create_tag(); // Before you can create policy you need to have a resource tag
/// store.set_policy(owner.clone(), auth::Host::Rename.into(), [tag].into()); // Allow `my_user` to `Rename` all `Hosts` with `tag`
///
/// let check = store.check_permission(owner.clone(), auth::Host::Rename.into(), &[tag].into()); // Does user `my_user` have permission to `Rename` Hosts with `tag`
/// assert!(check); // Yes since we created a policy
/// let check = store.check_permission(owner.clone(), auth::Host::Remove.into(), &[tag].into()); // Does user `my_user` have permission to `Remove` Hosts with `tag`
/// assert!(!check); // No! Since there is no policy in place
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyStore<Identity: Eq + Hash> {
    tags: TagSet,
    policies: HashMap<(Identity, Action), TagSet>,
}

impl<Identity: DeserializeOwned + Eq + Hash> PolicyStore<Identity> {
    /// Reserve a new tag
    pub fn create_tag(&mut self) -> Tag {
        let tag = Uuid::new_v4();
        self.tags.insert(tag);
        tag
    }

    /// Remove a tag from the valid tag list
    pub fn delete_tag(&mut self, tag: &Tag) {
        self.tags.remove(tag);
        for policy in self.policies.values_mut() {
            policy.remove(tag);
        }
    }

    /// Allow `owner` to execute `action` for all resources with one of `tags`
    /// IMPORTANT: Resource does not need to have ALL tags but ANY tag in `tags`
    pub fn set_policy(&mut self, owner: Identity, action: Action, tags: TagSet) {
        self.policies.insert((owner, action), tags);
    }

    /// Delete a policy. This does not delete the tags. Use `delete_tag` to remove tags
    pub fn delete_policy(&mut self, owner: Identity, action: Action) -> Option<HashSet<Tag>> {
        self.policies.remove(&(owner, action))
    }

    /// Returns all tags for a given owner and action. If there is no policy the TagSet will be empty
    pub fn get_tags(&self, owner: Identity, action: Action) -> TagSet {
        self.policies
            .get(&(owner, action))
            .cloned()
            .unwrap_or_default()
    }

    /// Check if `owner` is allowed to execute `action` on any of `tags`
    /// If you want to check if `owner` is allowed on ALL you want to use `get_tags`
    pub fn check_permission(&self, owner: Identity, action: Action, tags: &TagSet) -> bool {
        self.get_tags(owner, action).intersection(tags).count() > 0
    }
}

#[cfg(test)]
mod test {

    use crate::auth::{self, PolicyStore};

    #[test]
    fn happy_path() {
        let mut store = PolicyStore::<String>::default();
        let some_tag = store.create_tag();
        store.set_policy("me".into(), auth::Host::Rename.into(), [some_tag].into());
        let check =
            store.check_permission("me".into(), auth::Host::Rename.into(), &[some_tag].into());
        assert!(check)
    }

    #[test]
    fn delete_tag() {
        let mut store = PolicyStore::<String>::default();

        let some_tag = store.create_tag();
        store.set_policy("me".into(), auth::Host::Rename.into(), [some_tag].into());
        let check =
            store.check_permission("me".into(), auth::Host::Rename.into(), &[some_tag].into());
        assert!(check);

        store.delete_tag(&some_tag);
        let check =
            store.check_permission("me".into(), auth::Host::Rename.into(), &[some_tag].into());
        assert!(!check);
    }

    #[test]
    fn delete_policy() {
        let mut store = PolicyStore::<String>::default();

        let some_tag = store.create_tag();
        store.set_policy("me".into(), auth::Host::Rename.into(), [some_tag].into());
        let check =
            store.check_permission("me".into(), auth::Host::Rename.into(), &[some_tag].into());
        assert!(check);

        store.delete_policy("me".into(), auth::Host::Rename.into());
        let check =
            store.check_permission("me".into(), auth::Host::Rename.into(), &[some_tag].into());
        assert!(!check);
    }
}
