{
  ...
}:
let
  disko = fetchTarball {
    url = "https://github.com/nix-community/disko/archive/master.tar.gz";
    sha256 = "sha256-uZkBR7yHdIKUFB5SZdfgh1qkGfI3XmYmI/lTiquxbck=";
  };
in
{
  imports = [
    "${disko}/module.nix"
  ];
}
