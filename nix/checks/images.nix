# Public domain test photos from the face_recognition examples.
{
  fetchurl,
  ffmpeg-headless,
  runCommand,
}:
let
  example =
    name: hash:
    fetchurl {
      url = "https://raw.githubusercontent.com/ageitgey/face_recognition/master/examples/${name}";
      inherit hash;
    };
  biden = example "biden.jpg" "sha256-PBdQi7kVVMY3ouq93655DluxyrqTEwgU/CrFC+l2DEw=";
in
{
  obama = example "obama.jpg" "sha256-CTDjqoyuWSAynAyMvGoqtw9HsOZ7Qyh1vqqVy/fnQfY=";
  obama2 = example "obama2.jpg" "sha256-p+/MkHN1J0eW85ZGUQcEqoZnLVn21Uadaa88hVkJdqY=";
  inherit biden;
  # The face in the full photo is small after scaling to the camera size.
  # The top 970x1000 pixels contain the face.
  biden-top = runCommand "biden-top.png" { nativeBuildInputs = [ ffmpeg-headless ]; } ''
    ffmpeg -nostdin -loglevel error -i ${biden} -vf crop=970:1000:0:0 "$out.png"
    mv "$out.png" "$out"
  '';
}
