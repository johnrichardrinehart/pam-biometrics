{
  pkgs,
  package,
  nixosModules,
}:
let
  images = pkgs.callPackage ./images.nix { };
in
{
  cargo-test = package.overrideAttrs { doCheck = true; };

  clippy = package.overrideAttrs (previous: {
    nativeBuildInputs = previous.nativeBuildInputs ++ [ pkgs.clippy ];
    buildPhase = ''
      runHook preBuild
      cargo clippy --offline --frozen --workspace --all-targets -- --deny warnings
      runHook postBuild
    '';
    doCheck = false;
    installPhase = ''
      touch "$out"
    '';
  });

  encoding-parity = pkgs.callPackage ./encoding-parity.nix { inherit images package; };

  vm = pkgs.callPackage ./vm.nix { inherit images nixosModules; };
}
