{
  # Add all your dependencies here
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  # Load the blueprint
  # outputs = inputs: inputs.blueprint { inherit inputs; };
  outputs = inputs: {};
}
# {
#   inputs = {
#     nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
#     utils.url = "github:numtide/flake-utils";
#   };
#   outputs = {
#     self,
#     nixpkgs,
#     utils,
#   }:
#     utils.lib.eachDefaultSystem (
#       system: let
#         pkgs = import nixpkgs {inherit system;};
#         server-manifest = (pkgs.lib.importTOML ./yeet-server/Cargo.toml).package;
#         agent-manifest = (pkgs.lib.importTOML ./yeet-agent/Cargo.toml).package;
#       in rec {
#         packages = {
#           yeet-server = pkgs.rustPlatform.buildRustPackage {
#             pname = server-manifest.name;
#             version = server-manifest.version;
#             cargoLock.lockFile = ./Cargo.lock;
#             src = ./.;
#             buildAndTestSubdir = "yeet-server";
#           };
#           yeet-agent = pkgs.rustPlatform.buildRustPackage {
#             pname = agent-manifest.name;
#             version = agent-manifest.version;
#             cargoLock.lockFile = ./Cargo.lock;
#             src = ./.;
#             buildAndTestSubdir = "yeet-agent";
#             nativeBuildInputs = with pkgs; [
#               pkg-config
#             ];
#             buildInputs =
#               [pkgs.openssl]
#               ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (
#                 with pkgs.darwin.apple_sdk.frameworks; [
#                   SystemConfiguration
#                   CoreServices
#                   Cocoa
#                 ]
#               )
#               ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
#                 pkgs.dbus
#               ];
#           };
#           default = packages.yeet-agent;
#         };
#       }
#     )
#     // {
#       nixosModules.yeet-agent = import ./yeet-agent.nix;
#     };
# }
