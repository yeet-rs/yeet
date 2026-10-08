{
  nixpkgs,
  pkgs ? import nixpkgs { },
  ...
}:
let
  yeetSrc = fetchTarball {
    url = "https://github.com/yeet-rs/yeet/archive/master.tar.gz";
    sha256 = "sha256-YC0qdEZlA/x4MSVsaATN4xHTCD2NKRJjE4duzmMH8Bg=";
  };
  yeet = import yeetSrc { inherit pkgs; };
in
{
  imports = [
    yeet.nixosModules.yeet
  ];

  # services.journald.settings.Journal
  # services.journald.extraConfig = ''
  #   ForwardToConsole=no
  #   ForwardToWall=no
  #   MaxLevelConsole=emerg
  # '';

  environment.systemPackages = [
    pkgs.nixos-facter
    pkgs.nix-output-monitor
    yeet.packages.yeet
  ];

  services.yeet = {
    enable = true;
    server = "https://yeet.bsiag.com";
    facter = true;
  };

  services.openssh.enable = true;

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
}
