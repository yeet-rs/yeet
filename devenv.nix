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
  ];
  env.RUSTFLAGS = "--cfg tokio_unstable";
  env.DATABASE_URL = "sqlite:yeet.db";
}
