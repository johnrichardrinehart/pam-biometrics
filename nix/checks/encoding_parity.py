"""Compare the face encodings of pam-biometricsd and face_recognition.

The script loads each image with face_recognition, writes the same RGB pixels
to a raw file, and runs `pam-biometricsd encode` on that file. The face boxes
must be equal. The encodings must agree within the tolerance.
"""

import argparse
import json
import subprocess
import sys
import tempfile
import warnings

with warnings.catch_warnings():
    # face_recognition_models imports the deprecated pkg_resources module.
    warnings.simplefilter("ignore")
    import face_recognition
import numpy


def reference(image):
    locations = face_recognition.face_locations(
        image, number_of_times_to_upsample=0, model="hog"
    )
    encodings = face_recognition.face_encodings(image, locations)
    return [list(location) for location in locations], encodings


def rust(daemon, image):
    height, width, _ = image.shape
    with tempfile.NamedTemporaryFile(suffix=".rgb") as raw:
        raw.write(numpy.ascontiguousarray(image, dtype=numpy.uint8).tobytes())
        raw.flush()
        output = subprocess.run(
            [
                daemon,
                "encode",
                "--width",
                str(width),
                "--height",
                str(height),
                raw.name,
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    faces = json.loads(output)
    return [face["location"] for face in faces], [
        numpy.array(face["encoding"]) for face in faces
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--tolerance", type=float, required=True)
    parser.add_argument("images", nargs="+")
    args = parser.parse_args()

    worst = 0.0
    failed = False
    for path in args.images:
        image = face_recognition.load_image_file(path)
        expected_locations, expected = reference(image)
        actual_locations, actual = rust(args.daemon, image)
        if not expected:
            print(f"{path}: face_recognition found no face")
            failed = True
            continue
        if expected_locations != actual_locations:
            print(f"{path}: boxes differ: {expected_locations} != {actual_locations}")
            failed = True
            continue
        difference = max(
            float(numpy.abs(e - a).max()) for e, a in zip(expected, actual)
        )
        worst = max(worst, difference)
        print(
            f"{path}: {len(expected)} face(s) at {expected_locations}, "
            f"max abs diff {difference:.3e}"
        )
        if difference > args.tolerance:
            failed = True

    print(f"max abs diff over all images: {worst:.3e} (tolerance {args.tolerance:g})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
