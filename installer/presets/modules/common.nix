{
  nixpkgs,
  pkgs ? import nixpkgs { },
  ...
}:
{

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  nix.package = pkgs.lixPackageSets.stable.lix;
  nixpkgs.overlays = [
    (final: prev: {
      inherit (prev.lixPackageSets.stable)
        nixpkgs-review
        nix-eval-jobs
        nix-fast-build
        colmena
        ;
    })
  ];

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
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

  documentation = {
    enable = false;
    doc.enable = false;
    info.enable = false;
    man.enable = false;
    nixos.enable = false;
  };

  environment = {
    # Perl is a default package.
    defaultPackages = [ ];
    stub-ld.enable = false;
  };

  programs = {
    command-not-found.enable = false;
    fish.generateCompletions = false;
  };

  services = {
    logrotate.enable = false;
    udisks2.enable = false;
  };

  xdg = {
    autostart.enable = false;
    icons.enable = false;
    mime.enable = false;
    sounds.enable = false;
  };

  nixpkgs.hostPlatform = "x86_64-linux";

  system.stateVersion = "26.05";

}
