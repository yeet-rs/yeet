{
  pkgs,
  lib,
  modulesPath,
  config,
  ...
}:
let
  getty = {
    ExecStart = [
      ""
      "${pkgs.yeet-installer}/bin/yeet-installer"
    ];
    Restart = "no";

    Type = "idle";
    StandardInput = "tty"; # We want input for luks
    StandardOutput = "inherit";
    StandardError = "inherit";
    TTYVTDisallocate = false;

    TTYReset = "yes";
    TTYVHangup = "yes";
  };
in
{
  imports = [
    "${modulesPath}/installer/cd-dvd/installation-cd-minimal.nix"
    # Include a copy of Nixpkgs so that nixos-install works out of
     # the box.
    # "${modulesPath}/installer/cd-dvd/channel.nix"
  ];

  nixpkgs.hostPlatform = "x86_64-linux";
  system.stateVersion = "26.05"; # initial nixos state

  # isoImage.makeBiosBootable = false;
  # isoImage.makeUsbBootable = true;
  # isoImage.makeEfiBootable = true;

  isoImage.contents = [{
    source = ./presets; target = "/installer";
  }];

  # swapDevices = [ ];
  # fileSystems = config.lib.isoFileSystems;
  # boot.initrd.luks.devices = { };

  # boot.loader.grub.memtest86.enable = true;

  image.baseName = lib.mkForce "yeet-installer-${config.system.stateVersion}-${pkgs.stdenv.hostPlatform.system}";
  system.nixos.variant_id = "yeet-installer";

  nixpkgs.config.allowUnfree = true;
  hardware.enableAllFirmware = true;

  # nix.settings.substituters = lib.mkForce [ ];

  # boot.supportedFilesystems.zfs = false;
  # boot.zfs.forceImportRoot = false;

  users.users.me.isNormalUser = true;
  users.users.me.password = "test";
  users.users.me.extraGroups = [ "wheel" ];

  virtualisation.vmVariant.virtualisation = {
    # memorySize = 4096;
    # cores = 8;
    # diskSize = lib.mkForce 10 * 1024;
    graphics = false;
    qemu.options = lib.optionals (config.virtualisation.vmVariant.virtualisation.graphics) [
        "-display sdl,gl=on"
      ];
  };


  # To speed up installation a little bit, include the complete
  # stdenvNoCC in the Nix store on the CD.
  # system.extraDependencies =

  #   [
  #     pkgs.stdenvNoCC # for runCommand
  #   ];

  systemd.services."getty@tty1" = {
    overrideStrategy = "asDropin";
    serviceConfig = getty //  {
      TTYPath = "/dev/tty1";
    };
  };

  # this is only needed for local testing
  systemd.services."serial-getty@ttyS0" = {
    overrideStrategy = "asDropin";
    serviceConfig = getty //  {
      TTYPath = "/dev/ttyS0";
    };
  };
}
