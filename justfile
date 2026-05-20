export DATABASE_URL := "sqlite:yeet.db"
export YEET_URL := "https://localhost:4337"

# env.YEET_HOST = "0.0.0.0";
# # env.YEET_URL = "https://example.com";
# env.YEET_SPLUNK_URL = "http://localhost";
# env.YEET_SPLUNK_INDEX = "my_index";
# env.YEET_SPLUNK_TOKEN = "<>";

[positional-arguments]
@cli *args:
    cargo run --bin yeet -- "$@"


[env("YEET_CERT", "cert.pem")]
[env("YEET_CERT_KEY", "key.pem")]
serve:
    #!/usr/bin/env bash
    if [ ! -f "cert.pem" ]; then
        just certs
    fi
    if [ ! -f "yeet.db" ]; then
        just db-reset
    fi
    cargo run --bin yeetd


# create openssl certs required when using osquery / tls
certs:
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 \
        -nodes -subj "/CN=hostname" \
        -addext "subjectAltName=DNS:hostname" \
        -addext "basicConstraints=CA:FALSE"

    ssh-keygen -t ed25519 -f yeet-admin.key -N ''
    rm yeet-admin.key.pub

# removes files like database, certificate and encryption keys
clean:
    #!/usr/bin/env sh
    rm yeet.db*
    rm key.pem
    rm cert.pem
    rm age.key
    rm yeet-admin.key

# deletes and creates a fresh database
db-reset:
    #!/usr/bin/env sh
    rm yeet.db
    sqlx database create
    sqlx migrate run

migrate:
    sqlx migrate run

prep:
    cargo sqlx prepare --workspace
    nix run github:NixOS/nixpkgs/nixos-unstable#crate2nix -- generate
