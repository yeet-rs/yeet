{
  config,
  pkgs,
  lib,
  modulesPath,
  utils,
  ...
}:
let

  repartWithDisk = pkgs.writeShellScript "systemd-repart-yeet" ''
    set -eu
    part=$(${pkgs.coreutils}/bin/readlink -f /dev/disk/by-partlabel/YEET_ROOTFS)
    part_sysfs=$(${pkgs.coreutils}/bin/readlink -f "/sys/class/block/$(${pkgs.coreutils}/bin/basename "$part")")
    disk="/dev/$(${pkgs.coreutils}/bin/basename "$(${pkgs.coreutils}/bin/dirname "$part_sysfs")")"

    exec ${config.boot.initrd.systemd.package}/bin/systemd-repart \
      --definitions=/etc/repart.d \
      --dry-run=no \
      --empty=${config.boot.initrd.systemd.repart.empty} \
      --discard=${lib.boolToString config.boot.initrd.systemd.repart.discard} \
      ${utils.escapeSystemdExecArgs config.boot.initrd.systemd.repart.extraArgs} \
      "$disk"
  '';
in
{
  imports = [ "${modulesPath}/image/repart.nix" ];

  boot.loader.grub.enable = false;
  boot.kernelParams = [ "systemd.setenv=SYSTEMD_SULOGIN_FORCE=1" ];

  boot.initrd.availableKernelModules = [
    "xhci_pci"
    "ehci_pci"
    "usb_storage"
    "usbhid"
    "sd_mod"
    "squashfs" # /nix/.ro-store
    "overlay" # /nix/store
  ];

  boot.zfs.forceImportRoot = false;

  image.repart = {
    name = "yeet-installer";

    partitions = {
      "10-esp" = {
        contents = {
          "/EFI/BOOT/BOOTX64.EFI".source = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi";

          "/EFI/Linux/${config.system.boot.loader.ukiFile}".source =
            "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
        };
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          SizeMinBytes = "128M";
          SizeMaxBytes = "256M";
        };
      };

      "20-config" = {
        contents = {
          "/".source = ./presets;
        };
        repartConfig = {
          Type = "linux-generic";
          Label = "YEET_CONFIG";
          Format = "vfat";
          SizeMinBytes = "64M";
          SizeMaxBytes = "256M";
        };
      };

      "30-rootfs" = {
        storePaths = [ config.system.build.toplevel ];
        nixStorePrefix = "/";
        contents = {
          "/nix-path-registration".source = "${
            pkgs.closureInfo { rootPaths = [ config.system.build.toplevel ]; }
          }/registration";
        };
        repartConfig = {
          Type = "linux-generic";
          Label = "YEET_ROOTFS";
          Format = "squashfs";
          Minimize = "best";
        };
      };
    };
  };

  systemd.services.register-nix-paths = {
    description = "Register Nix Store Paths";
    unitConfig.DefaultDependencies = false;
    wantedBy = [ "sysinit.target" ];
    before = [
      "sysinit.target"
      "shutdown.target"
      "nix-daemon.socket"
      "nix-daemon.service"
    ];
    after = [ "local-fs.target" ];
    conflicts = [ "shutdown.target" ];
    restartIfChanged = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      # After booting, register the contents of the Nix store on the
      # CD in the Nix database in the tmpfs.
      ${lib.getExe' config.nix.package.out "nix-store"} --load-db < /nix/store/nix-path-registration

      # nixos-rebuild also requires a "system" profile and an /etc/NIXOS tag.
      touch /etc/NIXOS
      ${lib.getExe' config.nix.package.out "nix-env"} -p /nix/var/nix/profiles/system --set /run/current-system
    '';
  };

  boot.initrd.systemd.repart.enable = true;
  boot.initrd.systemd.services.systemd-repart = {
    # disk can't be set because / is tmpfs
    unitConfig.RequiresMountsFor = "/sysroot/nix/.ro-store";
    serviceConfig.ExecStart = lib.mkForce [
      " " # reset the upstream ExecStart
      "${repartWithDisk}"
    ];
  };

  # include the repartWithDisk
  boot.initrd.systemd.storePaths = [
    "${repartWithDisk}"
    pkgs.runtimeShell
    pkgs.coreutils
  ];

  systemd.repart.partitions."40-nix-rw" = {
    Type = "3db01e4f-d3f4-4b3a-85c6-572a140ca6d7"; # random uuid
    Label = "YEET_NIX_STORE";
    Format = "ext4";
    SizeMinBytes = "1G";
    GrowFileSystem = "yes";
  };

  fileSystems."/" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
  };

  fileSystems."/nix/.ro-store" = {
    device = "/dev/disk/by-partlabel/YEET_ROOTFS";
    fsType = "squashfs";
    options = [ "ro" ];
    neededForBoot = true;
  };

  fileSystems."/nix/.rw-store" = {
    device = "/dev/disk/by-partlabel/YEET_NIX_STORE";
    fsType = "ext4";
    options = [
      "rw"
    ];
    neededForBoot = true;
  };

  fileSystems."/nix/store" = {
    overlay = {
      lowerdir = [ "/nix/.ro-store" ];
      upperdir = "/nix/.rw-store/store";
      workdir = "/nix/.rw-store/work";
    };
  };

  fileSystems."/etc/yeet" = {
    device = "/dev/disk/by-partlabel/YEET_CONFIG";
    fsType = "vfat";
  };

}
