{
  nixpkgs,
  pkgs,
  lib,
  modulesPath,
  config,
  ...
}:
let
  presetLanzabooteLuks = import ./presets/systems/lanzaboote-luks.nix { inherit nixpkgs; };
  presetBtrfs = import ./presets/systems/btrfs.nix { inherit nixpkgs; };
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
    (fetchTarball {
      url = "https://github.com/nix-community/disko/archive/master.tar.gz";
      sha256 = "sha256-uZkBR7yHdIKUFB5SZdfgh1qkGfI3XmYmI/lTiquxbck=";
    })
    presetLanzabooteLuks.config.system.build.diskoScript
    presetBtrfs.config.system.build.diskoScript
    presetBtrfs.config.system.build.toplevel
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
    memorySize = 4096;
    # cores = 8;
    # diskSize = lib.mkForce 10 * 1024;
    graphics = false;
    qemu.options = lib.optionals (config.virtualisation.vmVariant.virtualisation.graphics) [
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
