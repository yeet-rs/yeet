{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.services.yeetd;
in
{
  meta.maintainers = [ lib.maintainers.Srylax ];

  options.services.yeetd = {
    enable = mkEnableOption "Yeet Server: https://github.com/Srylax/yeet";

    port = mkOption {
      type = types.port;
      description = "Yeet-API Port";
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "localhost";
      description = "The listen host for HTTP API";
    };

    user = mkOption {
      type = types.str;
      default = "yeet";
      description = ''
        User to run the Yeet Server as.
      '';
    };

    stateLocation = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/yeetd/state.json";
      description = "Location where yeetd state is stored";
    };

    initKey = lib.mkOption {
      type = lib.types.path;
      description = ''
        When starting the server for the first time, an admin key must be given
        or else no one would be able to init the server.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open the immich port in the firewall";
    };

    group = mkOption {
      type = types.str;
      default = "yeet";
      description = ''
        Group to run the Yeet Server as.
      '';
    };

    package = mkPackageOption pkgs "yeetd" { };
  };

  config = mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [
      cfg.port
    ];
    systemd.services.yeetd = {
      description = "Yeet Server";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment.YEET_PORT = "${cfg.port}";
      environment.YEET_HOST = "${cfg.host}";
      environment.YEET_STATE = "${cfg.stateLocation}";
      environment.YEET_INIT_KEY = "${cfg.initKey}";

      serviceConfig = {
        StateDirectoryMode = "0700";
        StateDirectory = "yeet";
        RuntimeDirectory = "yeetd";
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${lib.getExe cfg.package}";
      };
    };
  };
}
