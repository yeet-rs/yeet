{
  pkgs,
  lib,
  modulesPath,
  config,
  ...
}:
let

  preset = import (pkgs.path + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [
      ./presets/modules/disko.nix
      ./presets/modules/common.nix
      ./presets/disko/btrfs-subvolumes.nix
    ];
  };

  # raw image has no free space. emulate a stick
  vmStick =
    let
      vmCfg = config.virtualisation.vmVariant;
    in
    pkgs.runCommand "yeet-installer-vm-stick" { nativeBuildInputs = [ pkgs.qemu-utils ]; } ''
      mkdir $out
      qemu-img create -f qcow2 \
        -b ${vmCfg.system.build.image}/${vmCfg.image.fileName} -F raw \
        $out/stick.qcow2 ${toString vmCfg.virtualisation.diskSize}M
    '';

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
    "${modulesPath}/profiles/minimal.nix"
    ./image.nix

    "${modulesPath}/installer/cd-dvd/channel.nix"
  ];

  nixpkgs.hostPlatform = "x86_64-linux";
  system.stateVersion = "26.05"; # initial nixos state

  nixpkgs.config.allowUnfree = true;
  hardware.enableAllFirmware = true;

  nix.settings.substituters = lib.mkForce [ ];

  users.users.nixos = {
    isNormalUser = true;
    extraGroups = [
      "wheel"
    ];
    initialHashedPassword = "";
  };

  users.users.root.initialHashedPassword = "";
  nix.settings.trusted-users = [ "nixos" ];

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
    # add disko so that we do not have to download it again
    preset.config.system.build.diskoScript
    preset.config.system.build.toplevel
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

  # faster networking
  networking.useNetworkd = true;
  networking.dhcpcd.enable = false;

  virtualisation.vmVariant.virtualisation = {
    diskImage = null; # don't create the qcow2 root
    useDefaultFilesystems = false; # use reparted image
    fileSystems = config.fileSystems;
    useBootLoader = true; # use the UKI
    # eval tries to pull out efi vars failing in "can only be used with partition table of type.."
    efi.keepVariables = false;
    # OVMF required for UKI
    useEFIBoot = true;
    # remove qemu's ESP
    bootPartition = null;

    qemu.drives = [
      {
        name = "stick";
        file = "${vmStick}/stick.qcow2";
        driveExtraOpts = {
          format = "qcow2";
          snapshot = "on"; # don't write into the nix store
        };
        deviceExtraOpts.bootindex = "0";
      }
    ];

    # where the new system gets installed
    emptyDiskImages = [
      # (20 * 1024)
      (20 * 1024)
    ];

    memorySize = 4096;
    # cores = 8;
    diskSize = 10 * 1024; # virtual size of the stick
    graphics = false;
    qemu.options = [
      "-smbios type=11,value=io.systemd.stub.kernel-cmdline-extra=console=ttyS0"
    ]
    ++ lib.optionals (config.virtualisation.vmVariant.virtualisation.graphics) [
      "-display sdl,gl=on"
    ];
  };

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

  systemd.services."getty@tty1" = {
    overrideStrategy = "asDropin";
    path = [
      pkgs.nix-output-monitor
      pkgs.nix
      pkgs.nixos-install
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
      pkgs.nixos-install
    ];
    environment.NIX_PATH = "nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixos";
    serviceConfig = getty // {
      TTYPath = "/dev/ttyS0";
    };
  };
}
