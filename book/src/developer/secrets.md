# Yeet secret management

## GOAL

As a NixOS admin I want to be able to include nix secrets in my os configuration. It is not advised to include the secrets directly in the nix config because this will publicly expose the secrets in the nix-store.

### Existing solutions

Widely used solutions to this problems are tools like `agenix` or `sops-nix`. These tools encrypt the secret with the public key of the target and then decrypt them once the system is enrolled on the target system with the sshd identity key. This ensures that only the intended host can decrypt the secrets.

This solution has a relative high initial configuration cost and also has the chicken-egg problem:
Before we can encrypt a secret we have to get its public key but before we can get the system we have to setup the system.

Furthermore, if we have `n` hosts, `s` secrets and `a` hosts we have to encrypt the secret with `(n*s*a)` keys. Because administrators will have to be able to decrypt and re-encrypt the secret once a new host needs access to the secret.

These tools require a lot of manual work, it is possible to automate this workflow.

### Morph

Morph is another nix deployment tool, it implements secret managing. Morphs secret management is realtively stupid. It simply copies file to the target. See https://github.com/DBCDK/morph/blob/master/examples/secrets.nix.
This make it trivial for new users who do not have to manage keys. The chicken-egg problem is also resolved.

## Proposed Solution

In Yeet we can make use of the best of both worlds. Yeet has information of the public keys of all hosts. This make it possible for the nix server to manage secrets in a secure way. The flow is best described by a quick example:

`yeet secret add nix-cache-signing-key --from-file ../secrets/very-secret.txt`
Sequence:

1. Yeet cli downloads the public server key
2. Content from `../secrets/very-secret.txt` is age encrypted with public server key
3. The Yeet server creates a new secret with the name `nix-cache-signing-key` that is stored at rest encrypted

The admin them would reference this secret in the configuration something like this (pseudo syntax):

```nix
yeet.secrets."nix-cache-signing-key" = {
  path = "/var/secrets/very-secret.txt";
  mode = "0400";
  owner = "nginx";
  group = "nginx";
};

services.mysuperservices.settings.signingKeyFile = config.yeet.secrets."nix-cache-signing-key".path;
```

When building the nix derivation at build time, all `yeet.secrets` are stored in the output derivation.

To support secrets the `yeet-agent` would have to make changes to the update process:

1. Agent receives `SwitchTo->RemoteStore` RemoteStore would now include a field `fetch_secrets`: Vec<String>
2. Agent requests all secrets from `fetch_secrets` (this only includes netrc at the moment)
3. Agent creates temporary netrc
4. Agent fetches the `RemoteStorePath`
5. Agent reads all the secrets that are required by the `RemoteStorePath`
6. Agent tries to request all required secrets (Activation fails if not all secrets exist on the Yeet server)
7. Secrets are created by the Agent.
8. System Activation begins
9. If System activation is successfull delete old generation of secrets else we delete the new generation

On the server the following happens:

1. Server receives an `Update` for a host with some `fetch_secrets` set
2. Server receives agent `SystemCheck` responds with `RemoteStorePath`
3. Server receives secret request for `netrc` secret.
   1. Check access for `$HOST` for `netrc`
   2. Encrypt `netrc` with pub key of `$HOST` and respond
4. Server receives request for multiple secrets
   1. Check access for all request secrets
   2. Encrypt all secrets with pub key of `$HOST` and respond

## Alternatives considered

### Using agenix with yeet

An alternative would be that when building the derivation yeet could fetch the secrets at build time and age encrypt them with agenix. The main point against this is that yeet would just be an agenix wrapper and create dependencies at build time. With the proposed solution, secrets would be able to change without re-deploying the derivation. Which is a double edged sword because on the one side now derivations are no longer hermetic but on the other side secrets are not meant to be hermetic, they always rely on some state bound secret for unlocking even in the case of agenix.

## Future extension

This proposal does not exactly define how the secrets are created on the host. This is because there are many possible solutions:

- create a tmpfs so that they are destroy if powerloss happens
- bind them to the tpm
- plain write them to disk (simplest)

Especially the tpm solution can be interesting for critical secrets as this would protect a device against hardware attacks. Once a device is stolen you can revoke the access on the yeet server and then if the device is tampered with it will lose its secrets and will not be able to fetch them again from the yeet-server.
