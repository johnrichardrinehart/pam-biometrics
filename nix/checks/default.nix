{
  pkgs,
  package,
}:
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
}
