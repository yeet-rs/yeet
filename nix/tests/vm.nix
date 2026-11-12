# vm tests for yeet. boots a server and a host and lets them talk to each other like in
# real life. runs in throwaway vms in the sandbox so nothing on your machine gets touched
#
#   nix-build -A tests.vm
#   nix-build -A tests.vm.driverInteractive  # for debugging, then ./result/bin/nixos-test-driver
{ pkgs }:
let
  inherit (pkgs) lib;
  root = ../..;

  # yeetd, yeet-agent and the test driver built from the working copy.
  # not crate2nix because packages.yeetd doesn't build there (sqlx...)
  yeet = pkgs.rustPlatform.buildRustPackage {
    pname = "yeet-vm-test";
    version = "0.17.0";
    src = lib.fileset.toSource {
      inherit root;
      fileset =
        lib.fileset.difference
          (lib.fileset.unions [
            (root + "/Cargo.toml")
            (root + "/Cargo.lock")
            (root + "/api")
            (root + "/agent")
            (root + "/cli")
            (root + "/server")
          ])
          (
            lib.fileset.unions [
              (lib.fileset.maybeMissing (root + "/api/target"))
              (lib.fileset.maybeMissing (root + "/server/target"))
              (lib.fileset.fileFilter (
                file:
                lib.any file.hasExt [
                  "db"
                  "pem"
                  "key"
                ]
              ) root)
            ]
          );
    };
    cargoLock = {
      lockFile = root + "/Cargo.lock";
      outputHashes."osquery-tls-0.2.0" = "sha256-mksJfkctYoTZYq9by+uy6z3cbV6NyQ3Kpz8yAdWOZL8=";
    };
    cargoBuildFlags = [
      "--package=yeetd"
      "--package=yeet-agent"
      "--package=yeet"
      "--bins"
      "--example=vm-test-driver"
    ];
    # sqlx checks the queries against server/.sqlx instead of a live db
    env.SQLX_OFFLINE = "true";
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.cmake
      pkgs.perl
    ];
    buildInputs = [ pkgs.openssl ];
    doCheck = false;
    postInstall = ''
      find target -path '*/release/examples/vm-test-driver' -type f \
        -exec install -Dm755 {} $out/bin/vm-test-driver \;
    '';
    meta.mainProgram = "yeet-agent";
  };

  # yeetd always wants tls so the server gets a cert from a test ca
  certs = pkgs.runCommand "yeet-test-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj /CN=yeet-test-ca -keyout ca.key -out $out/ca.pem
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -subj /CN=server -keyout $out/key.pem -out server.csr
    printf 'subjectAltName=DNS:server\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext
    openssl x509 -req -in server.csr -CA $out/ca.pem -CAkey ca.key -CAcreateserial \
      -days 3650 -extfile ext -out $out/cert.pem
  '';

  agent = {
    imports = [ (root + "/yeet.nix") ];
    security.pki.certificateFiles = [ "${certs}/ca.pem" ];
    services.yeet = {
      enable = true;
      server = "https://server:4337";
      sleep = 2;
      package = yeet;
    };
    # for /etc/ssh/ssh_host_ed25519_key, the agent uses that as its identity
    services.openssh.enable = true;
  };
in
pkgs.testers.runNixOSTest {
  name = "yeet";

  nodes = {
    server = {
      security.pki.certificateFiles = [ "${certs}/ca.pem" ];
      networking.firewall.allowedTCPPorts = [ 4337 ];
      environment.systemPackages = [ yeet ];
      systemd.services.yeetd = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        environment = {
          YEET_ADDR = "[::]:4337";
          YEET_CERT = "${certs}/cert.pem";
          YEET_CERT_KEY = "${certs}/key.pem";
          RUST_LOG = "info";
        };
        serviceConfig = {
          ExecStart = "${yeet}/bin/yeetd";
          DynamicUser = true;
          # yeet.db and age.key end up in the working directory
          StateDirectory = "yeetd";
          WorkingDirectory = "/var/lib/yeetd";
        };
      };
    };
    host = agent;
  };

  testScript = ''
    URL = "https://server:4337"

    def enroll(machine, name):
        machine.wait_for_unit("yeet.service")
        code = machine.wait_until_succeeds(
            "journalctl -u yeet --no-pager | grep -oE 'verification code is: [0-9]+' | tail -1 | grep -oE '[0-9]+$'"
        ).strip()
        server.succeed(f"vm-test-driver --url {URL} accept {code} {name}")
        machine.wait_until_succeeds("journalctl -u yeet --no-pager | grep -q 'Verified!'")

    start_all()
    server.wait_for_unit("yeetd.service")
    server.wait_for_open_port(4337)
    server.succeed(f"vm-test-driver --url {URL} bootstrap")

    with subtest("enroll hosts"):
        enroll(host, "host")

    with subtest("host polls the server"):
        host.wait_until_succeeds("journalctl -u yeet --no-pager | grep -q 'Nothing'")
  '';
}
