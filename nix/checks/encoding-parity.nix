# Compares the encodings of pam-biometricsd with the encodings of the
# face_recognition Python package for the same pixels.
{
  images,
  package,
  python3,
  runCommand,
}:
runCommand "pam-biometrics-encoding-parity"
  {
    nativeBuildInputs = [ (python3.withPackages (ps: [ ps.face-recognition ])) ];
  }
  ''
    set -o pipefail
    python3 ${./encoding_parity.py} \
      --daemon ${package}/bin/pam-biometricsd \
      --tolerance 1e-3 \
      ${images.obama} ${images.obama2} ${images.biden} ${images.biden-top} \
      | tee "$out"
  ''
