{
  pkgs ? import <nixpkgs> { },
  ...
}:
let
  yeet = import ../../default.nix { inherit pkgs; };
in
import <nixpkgs/nixos> {
  configuration = {
    imports = [
      yeet.nixosModules.yeet
      <nixpkgs/nixos/modules/virtualisation/qemu-vm.nix>
    ];

    services.yeet = {
      enable = true;
      # qemu special value which corresponds to the host device
      server = "https://10.0.2.2:4337";
      facter = true;
    };

    #
    security.pki.certificateFiles = [ ../../cert.pem ];

    # required so that the agent has an identity
    services.openssh.enable = true;

    environment.systemPackages = [
      pkgs.nixos-facter
      yeet.packages.yeet
    ];

    # === vm config

    services.getty.helpLine = ''
      If you are connect via serial console:
      Type Ctrl-a c to switch to the qemu console
      and `quit` to stop the VM.
    '';
    services.getty.autologinUser = "root";

    virtualisation.msize = 104857600;

    virtualisation = {
      graphics = false;
      memorySize = 700;

      qemu.consoles = [
        "tty0"
        "hvc0"
      ];

      qemu.options = [
        "-serial null"
        "-device virtio-serial"
        "-chardev stdio,mux=on,id=char0,signal=off"
        "-mon chardev=char0,mode=readline"
        "-device virtconsole,chardev=char0,nr=0"
      ];
    };

    system.stateVersion = "25.11";
  };
}
