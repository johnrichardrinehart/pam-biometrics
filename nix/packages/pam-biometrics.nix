{
  lib,
  rustPlatform,
  pkg-config,
  makeBinaryWrapper,
  dlib,
  blas,
  lapack,
  linux-pam,
  ffmpeg-headless,
  python3Packages,
  runCommand,
}:
let
  root = ../..;

  # The dlib models that the face_recognition Python package uses. Copies
  # keep the Python package out of the runtime closure.
  models =
    let
      inherit (python3Packages) face-recognition-models python;
    in
    runCommand "dlib-face-models-${face-recognition-models.version}" { } ''
      models=${face-recognition-models}/${python.sitePackages}/face_recognition_models/models
      install -Dm0444 -t "$out" \
        "$models/shape_predictor_5_face_landmarks.dat" \
        "$models/dlib_face_recognition_resnet_model_v1.dat"
    '';
in
rustPlatform.buildRustPackage {
  pname = "pam-biometrics";
  inherit ((lib.importTOML (root + "/Cargo.toml")).workspace.package) version;

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/crates")
      (root + "/examples")
      (root + "/schema")
    ];
  };

  cargoLock.lockFile = root + "/Cargo.lock";

  nativeBuildInputs = [
    pkg-config
    makeBinaryWrapper
  ];

  buildInputs = [
    blas
    dlib
    lapack
    linux-pam
  ];

  env = {
    # The PAM module runs the helper from this path.
    PAM_BIOMETRICS_HELPER = "${placeholder "out"}/bin/pam-biometrics";
    # The daemon loads the dlib models from this directory.
    PAM_BIOMETRICS_MODEL_DIR = "${models}";
  };

  # checks.cargo-test runs the tests.
  doCheck = false;

  postInstall = ''
    install -Dm0444 -t "$out/share/pam-biometrics" schema/policy.schema.json
    install -Dm0444 -t "$out/share/pam-biometrics/examples" examples/*.json
    install -Dm0444 "$out/lib/libpam_biometrics_module.so" "$out/lib/security/pam_biometrics.so"
    rm "$out/lib/libpam_biometrics_module.so"
    wrapProgram "$out/bin/pam-biometricsd" \
      --prefix PATH : ${lib.makeBinPath [ ffmpeg-headless ]}
  '';

  passthru = {
    inherit models;
  };

  meta = {
    description = "Fingerprint and face factors for PAM, after the password";
    homepage = "https://github.com/johnrichardrinehart/pam-biometrics";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "pam-biometrics";
    platforms = lib.platforms.linux;
  };
}
