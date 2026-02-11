{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.services.yeet;
  cfg_secret = config.yeet;
  secretType = lib.types.submodule (
    { config, ... }:
    {
      options = {
        name = lib.mkOption {
          type = lib.types.str;
          default = config._module.args.name;
          defaultText = lib.literalExpression "config._module.args.name";
          description = ''
            Name of the file used in {option}`age.secretsDir`
          '';
        };
        path = lib.mkOption {
          type = lib.types.str;
          default = "${cfg_secret.secretsDir}/${config.name}";
          defaultText = lib.literalExpression ''
            "''${cfg_secret.secretsDir}/''${config.name}"
          '';
          description = ''
            Path where the decrypted secret is installed.
          '';
        };
        mode = lib.mkOption {
          type = lib.types.str;
          default = "0400";
          description = ''
            Permissions mode of the decrypted secret in a format understood by chmod.
          '';
        };
        owner = lib.mkOption {
          type = lib.types.str;
          default = "0";
          description = ''
            User of the decrypted secret.
          '';
        };
        group = lib.mkOption {
          type = lib.types.str;
          default = lib.users.${config.owner}.group or "0";
          defaultText = lib.literalExpression ''
            users.''${config.owner}.group or "0"
          '';
          description = ''
            Group of the decrypted secret.
          '';
        };
        symlink = lib.mkEnableOption "symlinking secrets to their destination" // {
          default = true;
        };
      };
    }
  );

  secrets = pkgs.writeText "yeet-secrets.json" (builtins.toJSON cfg_secret.secrets);
in
{
  meta.maintainers = [ lib.maintainers.Srylax ];
  options.yeet = {
    secrets = lib.mkOption {
      type = lib.types.attrsOf secretType;
      default = { };
      description = ''
        Attrset of secrets.
      '';
    };

    secretsDir = lib.mkOption {
      type = lib.types.path;
      default = "/run/yeet";
      description = ''
        Folder where secrets are symlinked to
      '';
    };

    secretsMountPoint = lib.mkOption {
      type =
        lib.types.addCheck lib.types.str (
          s:
          (builtins.match "[ \t\n]*" s) == null # non-empty
          && (builtins.match ".+/" s) == null
        ) # without trailing slash
        // {
          description = "${lib.types.str.description} (with check: non-empty without trailing slash)";
        };
      default = "/run/agenix.d";
      description = ''
        Where secrets are created before they are symlinked to {option}`age.secretsDir`
      '';
    };
  };

  options.services.yeet = {
    enable = lib.mkEnableOption "Yeet Deploy Agent: https://github.com/Srylax/yeet";

    server = lib.mkOption {
      type = lib.types.str;
      description = "Yeet server url to use.";
    };

    sleep = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "Seconds to wait between updates";
    };

    facter = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Collect information about the system with `nixos-facter`";
    };

    key = lib.mkOption {
      type = lib.types.str;
      default = "/etc/ssh/ssh_host_ed25519_key";
      description = "ED25519 key used as the hosts identity";
    };

    package = lib.mkPackageOption pkgs "yeet" { };
  };

  config = (
    lib.mkMerge [
      (lib.optionalAttrs cfg.enable {

        users.groups = {
          yeet = { };
        };

        systemd.services.yeet = {
          description = "Yeet Deploy Agent";
          wants = [ "network-online.target" ];
          after = [ "network-online.target" ];
          path = [ config.nix.package ];
          wantedBy = [ "multi-user.target" ];

          environment.USER = "root";

          # don't stop the service if the unit disappears
          unitConfig.X-StopOnRemoval = false;

          serviceConfig = {
            # we don't want to kill children processes as those are deployments
            KillMode = "process";
            Restart = "always";
            RestartSec = 5;
            RuntimeDirectory = "yeet";
            ExecStart = ''
              ${lib.getExe cfg.package} agent --sleep ${toString cfg.sleep} --server ${cfg.server} --key ${cfg.key} ${lib.optionalString cfg.facter "--facter"}
            '';
          };
        };
      })
      (lib.optionalAttrs (cfg_secret.secrets != { }) {
        system.systemBuilderCommands = ''
          ln -s ${secrets} $out/yeet-secrets.json
        '';
      })
    ]
  );
}
