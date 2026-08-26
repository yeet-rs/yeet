{
  pkgs ? import <nixpkgs> { },
  ...
}:
import <nixpkgs/nixos> {
  configuration = {
    imports = [
      "${fetchTarball "https://github.com/nix-community/disko/archive/master.tar.gz"}/module.nix"
      ../disko/luks-btrfs-subvolumes.nix
    ];
    services.journald.extraConfig = ''
      ForwardToConsole=no
      ForwardToWall=no
      MaxLevelConsole=emerg
    '';

    systemd.services."getty@tty1".enable = false;
    systemd.services."autovt@tty1".enable = false;

    systemd.services.yeet.serviceConfig = {
      StandardOutput = "tty";
      StandardError = "tty";

      TTYPath = "/dev/tty1";

      TTYReset = "yes";
      TTYVHangup = "yes";
      TTYVTDisallocate = "yes";
    };

    nixpkgs.hostPlatform = "x86_64-linux";

    system.stateVersion = "26.05";
  };
}
