{
  pkgs,
  inputs,
  lib,
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
    gcc
    pkg-config
    sqlx-cli
    bacon
    sqlite-interactive
    pkgs-unstable.cargo-tarpaulin
    just
  ];
  env.DATABASE_URL = "sqlite:yeet.db";
}
