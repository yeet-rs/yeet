{
  config,
  pkgs,
  lib,
  modulesPath,
  ...
}:
{
  imports = [ "${modulesPath}/image/repart.nix" ];

  boot.loader.grub.enable = false;

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
          "/EFI/BOOT/BOOTX64.EFI".source =
            "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi";

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
        contents = {
          "/nix/store/nix-path-registration".source = "${pkgs.closureInfo { rootPaths = [ config.system.build.toplevel ]; }}/registration";
        };
        repartConfig = {
          Type = "linux-generic";
          Label = "YEET_ROOTFS";
          Format = "squashfs";
          Minimize = "best";
        };
      };

      # "40-nix-rw" = {
      #   repartConfig = {
      #     Type = "linux-generic";
      #     Label = "YEET_NIX_STORE";
      #     Format = "vfat";
      #   };
      # };
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
    fsType = "tmpfs";
    options = [ "mode=0755" ];
    neededForBoot = true;
  };

  fileSystems."/nix/store" = {
    overlay = {
      lowerdir= ["/nix/.ro-store/nix/store"];
      upperdir="/nix/.rw-store/store";
      workdir="/nix/.rw-store/work";
    };
  };

  fileSystems."/etc/yeet" = {
    device = "/dev/disk/by-partlabel/YEET_CONFIG";
    fsType = "vfat";
  };

}
