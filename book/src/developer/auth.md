# Auth

## GOAL

Currently there are only two kinds of authorizations possible: Build and Admin. Admin gives full power over every aspect of the yeet fleet
To support credential scoping there fist needs a process to group resources with tags. Tags should be applicable to all resources.

List of resources:

- credentials themself
- tags themself
- hosts
- verifications / approvals
- global detach
- secrets

## Concept

To simplify the auth checking, we make auth checks only on the tag levels. Meaning the implementation has no concept of a tag per se.
You can think of it like this:

User is permitted to execute `action::Host::Rename` on the tags `a,b,c`
Host x has the tags `x,f,a`
Since tag `a` is present on User and Host the action is permitted.
The implementation does not have to track which resources exists. The logic on how tags are stored is defined on the resources. Meaning that instead of tags have knowledge of resources, resources have knowledge on tags.

This make the storage logic slightly more complex while making the permission logic way simpler.

Example:

```rust
Policy {
    actions: [UpdateHost, AddSecret, Status],
    scope: [Tag::MyTag]
}
```

An endpoint can then request some resources.

Example how a current build-key would look like:

```rust
Policy {
  actions: [UpdateHost],
  scope: [Tag::ALL]
}
```

Admin-key:

```rust
Policy {
  actions: [action::ALL],
  scope: [Tag::ALL]
}
```

As you can see there are two special items: `action::ALL` and `TAG::ALL`

## Required checks

The server needs some way to check for permissions. The first step is to always fetch all tags on the resources. This is always specific to each resources since checks are solely done on tags.

`get_tags(action::Secret::ListSecrets) -> Vec<Tag>`
Useful when filtering items for a user e.g. `ListHosts` / `ListSecrets`

`check_permission(host.tags, action::Host::Remove) -> true/false`
is implemented as `get_tags(action).intersection(tags).next.is_some()`

## Resource creation

Imagin the following scenario. User U wants to create Host H for this he has the permission `action::Host::Accept` on Tag T. If Host H would be created without Tag T User U would maybe not be able to see the created host.
This means that for such requests the user must be able to specifiy under which tag the resource should be created.

This means that the client must have a possability to list all tags under which the user is allowed to create resources. The client should furthermore prompt the user for seletion or default if there is only a single possible solution.

## Server side implementation and storage

Since policies are create for credentials we bind policies to a `VerifyingKey`.
The lookup process would look like this: `VerifyingKey -> Action -> TagList`.
A possible storage solution would be `HashMap<(VerifyingKey,Action), TagList>`.

## Possible expansion

Currently, tags are user-created strings. This does allow host-specific permission with the annoiance of creating a tag for each host.
Possible alternative would be to create a special tag like `Tag::Specific("myhost")`.
