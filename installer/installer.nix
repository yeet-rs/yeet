{
  nixpkgs,
  pkgs,
  lib,
  modulesPath,
  config,
  ...
}:
let

  presetLanzabooteLuks = import ./presets/systems/lanzaboote-luks.nix {  inherit nixpkgs;};
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
    "${fetchTarball "https://github.com/nix-community/disko/archive/master.tar.gz"}/module.nix"
    "${fetchTarball "https://github.com/nix-community/disko/archive/master.tar.gz"}/example/simple-efi.nix"
    "${modulesPath}/profiles/minimal.nix"
    "${modulesPath}/installer/cd-dvd/channel.nix"
  ];

  boot.loader.grub.efiSupport = true;
  boot.loader.grub.efiInstallAsRemovable = true;
  disko.devices.disk.main.imageSize = "4000M";

  nixpkgs.hostPlatform = "x86_64-linux";
  system.stateVersion = "26.05"; # initial nixos state

  environment.etc."yeet".source = ./presets;

  boot.initrd.availableKernelModules = [
    "xhci_pci"
    "ehci_pci"
    "usb_storage"
    "usbhid"
    "sd_mod"
  ];

  # image.baseName = lib.mkForce "yeet-installer-${config.system.stateVersion}-${pkgs.stdenv.hostPlatform.system}";
  # system.nixos.variant_id = "yeet-installer";
  # system.nixos.distroName = lib.mkForce "Yeet Installer";

  boot.zfs.forceImportRoot = false;

  nixpkgs.config.allowUnfree = true;
  hardware.enableAllFirmware = true;

  nix.settings.substituters = lib.mkForce [ ];

  users.users.me.isNormalUser = true;
  users.users.me.password = "test";
  users.users.me.extraGroups = [ "wheel" ];

  environment.systemPackages = [
    pkgs.nix-output-monitor
    pkgs.yeet-installer
  ];

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  # build speed improvements
  system.extraDependencies = [
    presetLanzabooteLuks.config.system.build.diskoScript
    pkgs.stdenvNoCC # for runCommand
    pkgs.busybox
    # For boot.initrd.systemd
    pkgs.makeInitrdNGTool
  ]
  ++ pkgs.jq.all; # for closureInfo

  # Tell the Nix evaluator to garbage collect more aggressively.
  # This is desirable in memory-constrained environments that don't
  # (yet) have swap set up.
  environment.variables.GC_INITIAL_HEAP_SIZE = "1M";

  # Make the installer more likely to succeed in low memory
  # environments.  The kernel's overcommit heustistics bite us
  # fairly often, preventing processes such as nix-worker or
  # download-using-manifests.pl from forking even if there is
  # plenty of free memory.
  boot.kernel.sysctl."vm.overcommit_memory" = "1";

  virtualisation.vmVariant.virtualisation = {
    memorySize = 4096;
    # cores = 8;
    # diskSize = lib.mkForce 10 * 1024;
    graphics = false;
    qemu.options = lib.optionals (config.virtualisation.vmVariant.virtualisation.graphics) [
      "-display sdl,gl=on"
    ];
  };

  systemd.services."getty@tty1" = {
    overrideStrategy = "asDropin";
    path = [
      pkgs.nix-output-monitor
      pkgs.nix
    ];
    environment.NIX_PATH = "nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixos";
    serviceConfig = getty // {
      TTYPath = "/dev/tty1";
    };
  };

  # this is only needed for local testing
  systemd.services."serial-getty@ttyS0" = {
    overrideStrategy = "asDropin";
    path = [
      pkgs.nix-output-monitor
      pkgs.nix
    ];
    environment.NIX_PATH = "nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixos";
    serviceConfig = getty // {
      TTYPath = "/dev/ttyS0";
    };
  };
}
