{ pkgs, ... }:
let
  manifest = (pkgs.lib.importTOML ../yeet-server/Cargo.toml).package;
in
pkgs.rustPlatform.buildRustPackage {
  pname = manifest.name;
  version = manifest.version;
  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "zlink-0.4.0" = "sha256-cS8Oi9zaDcpnP9v12pNSuDEK25KkyC1x55YMcg27qQI=";
    };
  };
  src = ../.;
  buildAndTestSubdir = "yeet-server";
  nativeBuildInputs = with pkgs; [
    pkg-config
  ];
  buildInputs = with pkgs; [
    openssl
  ];
}
