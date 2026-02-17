{
  system ? builtins.currentSystem,
  sources ? import ./sources.nix,
  pkgs ? import sources.nixpkgs {
    inherit system;
  },
  lib ? pkgs.lib,
}:
let
  cargo_nix = pkgs.callPackage ./Cargo.nix {
    buildRustCrateForPkgs =
      pkgs:
      pkgs.buildRustCrate.override {
        defaultCrateOverrides = pkgs.defaultCrateOverrides // {
          yeet = attrs: {
            extraRustcOpts = [
              "--cfg"
              "tokio_unstable"
            ];
            nativeBuildInputs = [
              pkgs.makeWrapper
            ];
            postInstall = ''
              wrapProgram $out/bin/yeet --prefix PATH : ${
                lib.makeBinPath [
                  pkgs.nixos-facter
                  pkgs.cachix
                  # pkgs.nix # do not bake in so we can use lix
                  # pkgs.nix-output-monitor
                ]
              }

              mkdir -p $out/share/polkit-1/actions/
              cp share/polkit-1/actions/* $out/share/polkit-1/actions/
            '';
          };

          tokio = attrs: {
            features = [
              "rt"
              "rt-multi-thread"
              "io-util"
              "io-std"
              "net"
              "time"
              "process"
              "macros"
              "sync"
              "signal"
              "fs"
              "parking_lot"
            ];
            extraRustcOpts = [
              "--cfg"
              "tokio_unstable"
            ];
          };
        };
      };
  };

in
{
  packages = {
    yeet = cargo_nix.workspaceMembers."yeet".build;
    yeetd = cargo_nix.workspaceMembers."yeetd".build;
  };
}
