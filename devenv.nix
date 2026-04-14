{
  pkgs,
  inputs,
  ...
}:
let
  pkgs-unstable = import inputs.nixpkgs-unstable { system = pkgs.stdenv.system; };
in
{
  languages.rust = {
    enable = false;
  };

  cachix.enable = true;

  packages = with pkgs; [
    openssl
    pkgs-unstable.rustup # because else we cannot use cargo +nightly fmt
    openssl
    gcc
    pkg-config
    sqlx-cli
    bacon
    sqlite-interactive
    pkgs-unstable.cargo-tarpaulin
  ];
  env.RUSTFLAGS = "--cfg tokio_unstable";
  env.DATABASE_URL = "sqlite:yeet.db";
  env.YEET_CERT = "cert.pem";
  env.YEET_CERT_KEY = "key.pem";
  env.YEET_HOST = "0.0.0.0";
  # env.YEET_URL = "https://example.com";
  env.YEET_SPLUNK_URL = "http://localhost";
  env.YEET_SPLUNK_INDEX = "my_index";
  env.YEET_SPLUNK_TOKEN = "<>";
}
