{
  ...
}:
let
  version = "1.13.0";
  disko = fetchTarball {
    url = "https://github.com/nix-community/disko/archive/refs/tags/v${version}.zip";
    sha256 = "sha256-CNzzBsRhq7gg4BMBuTDObiWDH/rFYHEuDRVOwCcwXw4=";
  };
in
{
  imports = [
    "${disko}/module.nix"
  ];

  system.extraDependencies = [ disko ];
}
