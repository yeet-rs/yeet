{
  pkgs,
  rustPlatform ? pkgs.rustPlatform,
  lib ? pkgs.lib,
  stdenv ? pkgs.stdenv,
  ...
}:
let
  manifest = (lib.importTOML ../yeet-agent/Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = manifest.name;
  version = manifest.version;
  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "zlink-0.4.0" = "sha256-Frx2gDrSTidbn0ntW5jvirLwLNqqk/wWljK7AHYXr6c=";
    };
  };
  src = ../.;
  buildAndTestSubdir = "yeet-agent";
  nativeBuildInputs = [
    pkgs.pkg-config
    pkgs.makeWrapper
  ];
  buildInputs = [
    pkgs.openssl
  ]
  ++ lib.optionals stdenv.isDarwin [
    pkgs.apple-sdk
  ]
  ++ lib.optionals stdenv.isLinux [
    pkgs.dbus
  ];

  RUSTFLAGS = "--cfg tokio_unstable";

  postInstall = ''
    wrapProgram $out/bin/yeet --prefix PATH : ${
      lib.makeBinPath [
        pkgs.nixos-facter
        pkgs.cachix
        pkgs.nix
      ]
    }

    mkdir -p $out/share/polkit-1/actions/
    cp share/polkit-1/actions/* $out/share/polkit-1/actions/
  '';

  meta = {
    description = "A pull-based nix deployment tool";
    homepage = "https://github.com/srylaz/yeet";
    platforms = lib.platforms.all;
    license = lib.licenses.agpl3Plus;
    mainProgram = "yeet";
    maintainers = with lib.maintainers; [ Srylax ];
  };
}
