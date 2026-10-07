{
  nixpkgs ? <nixpkgs>,
  disko ? fetchTarball {
    url = "https://github.com/nix-community/disko/archive/master.tar.gz";
    sha256 = "sha256-uZkBR7yHdIKUFB5SZdfgh1qkGfI3XmYmI/lTiquxbck=";
  },
  ...
}:
import "${nixpkgs}/nixos" {
  configuration = {
    imports = [
      "${disko}/module.nix"
      ../modules/common.nix
      ../disko/btrfs-subvolumes.nix
    ];
  };
}
