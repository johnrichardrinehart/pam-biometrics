# pam-biometrics

pam-biometrics adds a biometric step to a PAM stack. The step runs after the
password module. It accepts a fingerprint through fprintd or a face from a
webcam. A policy file sets the factors, how the step combines them, and the
thresholds for each PAM service and user.

The password stays necessary. The step can only add a check after the
password or reject the attempt.

## Contents

- [How it works](#how-it-works)
- [Security model](#security-model)
- [Installation](#installation)
- [PAM placement](#pam-placement)
- [Key binding](#key-binding)
- [Command reference](#command-reference)
- [Policy reference](#policy-reference)
- [Enrollment tips](#enrollment-tips)
- [Development](#development)
- [License](#license)

## How it works

The project has four parts:

| Part                 | Function                                                                                                                                               |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pam-biometricsd`    | A daemon that owns the camera and the face models. It scans faces on request and keeps the last result of each user.                                   |
| `pam-biometrics`     | The command line client and the PAM helper. It enrolls faces, starts scans, and decides the PAM step. It does not link dlib, so it starts fast.        |
| `pam_biometrics.so`  | A small PAM module. It runs `pam-biometrics pam-helper`, shows the output lines of the helper as PAM messages, and maps the exit code to a PAM result. |
| `policy.schema.json` | The JSON Schema of the policy file, in `share/pam-biometrics/`.                                                                                        |

Face scans start on demand only. A key binding runs `pam-biometrics face scan`.
The daemon scans for a few seconds and stores the result. The PAM step takes
the result. The PAM step never turns on the camera.

The PAM step runs the enabled factors in parallel until the policy decides
or the timeout passes:

- The fingerprint factor claims the default fprintd device and verifies any
  enrolled finger. After a wrong finger, it starts a new verification until
  `fingerprint.max_tries` wrong fingers.
- The face factor asks the daemon for the stored result of the user every
  200 ms. The step consumes each result when it reads it. A result that
  nobody reads expires after the result TTL. A match ends the face factor
  at once. Other results do not end it, so the user can scan again until
  the timeout. At the timeout, the last result counts. With
  `"combine": "all"`, a face reject ends the step at once.

Each factor ends with one of three outcomes:

| Outcome       | Fingerprint                                                              | Face                                                                                                                    |
| ------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `match`       | fprintd reports `verify-match`.                                          | The best distance is at or below `face.match_distance`.                                                                 |
| `reject`      | fprintd reports `verify-no-match` `fingerprint.max_tries` times.         | Faces are in at least `face.min_reject_frames` frames, and the best distance is above `face.reject_distance`.           |
| `no_decision` | No finger, no reader, no enrolled finger, a D-Bus error, or the timeout. | No scan, no face, dark frames, a best distance between the two thresholds, no enrolled face, no daemon, or the timeout. |

The helper exit code gives the PAM result:

| Step outcome  | Exit code | PAM result     |
| ------------- | --------- | -------------- |
| `success`     | 0         | `PAM_SUCCESS`  |
| `reject`      | 10        | `PAM_AUTH_ERR` |
| `no_decision` | 20        | `PAM_IGNORE`   |

A crash of the helper also gives `PAM_IGNORE`.

The face engine uses dlib with the defaults of the `face_recognition` Python
package: the HOG frontal face detector without upsampling, the 5-point shape
predictor, 150 pixel face chips, one jitter, the ResNet model
`dlib_face_recognition_resnet_model_v1.dat`, and the Euclidean distance. The
model files come from nixpkgs. A flake check compares the encodings with
`face_recognition` within 1e-3.

## Security model

- The password module comes first in the stack with the `requisite`
  control, so a wrong password ends the attempt. The biometric step adds a
  second check after the password. It does not replace the password.
- An RGB camera has no liveness detection. A photo of the user can pass the
  face factor. Use the face factor as a convenience factor or together with
  the fingerprint (`"combine": "all"`), not as a strong factor alone.
- The daemon runs as a dynamic user without network access. It can open
  video devices only. The face models are in `/var/lib/pam-biometrics` with
  mode 0600. The daemon saves no images.
- Every user can connect to the socket `/run/pam-biometrics/socket`. The
  daemon reads the peer credentials of each connection. Root can use every
  operation for every user. Other users can use every operation for
  themselves. The greeter user can start scans for every user, and it has no
  other access.
- The PAM module runs the helper from a store path that the build sets. The
  helper gets an empty environment except `PAM_USER`, `PAM_SERVICE`, and
  `PAM_TYPE`.

## Installation

Add the flake as an input and import the NixOS module:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    pam-biometrics = {
      url = "github:johnrichardrinehart/pam-biometrics";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, pam-biometrics, ... }:
    {
      nixosConfigurations.example = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          pam-biometrics.nixosModules.default
          ./configuration.nix
        ];
      };
    };
}
```

Then configure the service in `configuration.nix`:

```nix
{ config, ... }:
{
  services.fprintd.enable = true;

  services.pam-biometrics = {
    enable = true;
    camera = {
      device = "/dev/v4l/by-id/usb-Example_Webcam-video-index0";
      inputFormat = "mjpeg";
      width = 640;
      height = 360;
    };
    greeterUser = "greeter";
    policy = {
      defaults.prompt = "Touch the fingerprint reader or press Super+Alt+F.";
      services.polkit-1.on_no_decision = "deny";
    };
  };
}
```

The module has these options:

| Option                                        | Default    | Description                                                             |
| --------------------------------------------- | ---------- | ----------------------------------------------------------------------- |
| `services.pam-biometrics.enable`              | `false`    | Runs the daemon, installs the commands, and writes the policy.          |
| `services.pam-biometrics.package`             | this flake | The package.                                                            |
| `services.pam-biometrics.camera.device`       |            | The V4L2 device of the camera.                                          |
| `services.pam-biometrics.camera.inputFormat`  | `null`     | The V4L2 input format, for example `mjpeg`.                             |
| `services.pam-biometrics.camera.width`        | `640`      | The frame width in pixels.                                              |
| `services.pam-biometrics.camera.height`       | `360`      | The frame height in pixels.                                             |
| `services.pam-biometrics.scanSeconds`         | `4`        | The duration of a scan.                                                 |
| `services.pam-biometrics.enrollSeconds`       | `6`        | The duration of an enrollment.                                          |
| `services.pam-biometrics.resultTtlSeconds`    | `120`      | The time after which an unused scan result expires.                     |
| `services.pam-biometrics.greeterUser`         | `null`     | A user that can start scans for every user.                             |
| `services.pam-biometrics.policy`              | `{ }`      | The policy. The module sets `version` to 1 and checks it at build time. |
| `services.pam-biometrics.pamRule` (read-only) |            | The PAM line of the biometric step.                                     |

## PAM placement

Put the step after the password module. The `pamRule` option contains the
complete line:

```text
auth [success=ok ignore=ignore default=die] /nix/store/…-pam-biometrics-0.1.0/lib/security/pam_biometrics.so
```

For example, for a screen locker:

```nix
{ config, ... }:
{
  security.pam.services.hyprlock.text = ''
    account required pam_unix.so

    auth requisite pam_unix.so nullok
    ${config.services.pam-biometrics.pamRule}
    auth required pam_permit.so

    password required pam_unix.so
    session required pam_unix.so
  '';
}
```

The control values have this effect:

- `success=ok`: a match lets the stack continue.
- `ignore=ignore`: without a decision, the other modules decide.
- `default=die`: a reject ends the attempt with a failure.

The module passes its arguments to `pam-biometrics pam-helper`. For example,
`[--prompt=Touch the reader.]` sets the prompt for one PAM service. The
square brackets keep the spaces in one argument.

## Key binding

A key binding starts a face scan for the user that the binding runs as. The
lock screen can show the state of the scan with
`pam-biometrics face status`.

An example for niri:

```kdl
binds {
    Mod+Alt+F allow-when-locked=true { spawn "pam-biometrics" "face" "scan"; }
}
```

A login greeter runs as the greeter user. Set `greeterUser` to that user. The
greeter then runs `pam-biometrics face scan USER` for the user that logs in.

## Command reference

The commands group by factor. All commands accept `--socket PATH` (default
`/run/pam-biometrics/socket`) and `--policy PATH` (default
`/etc/pam-biometrics/policy.json`).

### Face commands

The face commands talk to `pam-biometricsd`. `USER` is the current user if
it is not given.

| Command                                           | Function                                                                                                                                                                           |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pam-biometrics face enroll [USER] [--add]`       | Records face samples. Without `--add`, it replaces the model. With `--add`, it adds samples and keeps the newest 30.                                                               |
| `pam-biometrics face verify [USER] [--json]`      | Scans now and prints `Verify result: verify-match`, `verify-no-match`, or `verify-retry-scan`. Exits 0 only on a match. `--json` prints the daemon reply and its class.            |
| `pam-biometrics face delete USER...`              | Deletes the face models.                                                                                                                                                           |
| `pam-biometrics face list USER...`                | Shows the number of samples of each user.                                                                                                                                          |
| `pam-biometrics face scan [USER]`                 | Starts a background scan. The next PAM step for the user uses the result.                                                                                                          |
| `pam-biometrics face status [USER] [--service S]` | Prints one line for a lock screen: `Face: scanning…`, `Face: recognized`, `Face: not sure`, `Face: not recognized`, `Face: no face found`, `Face: not enrolled`, or an empty line. |
| `pam-biometrics face wait [USER] [--service S]`   | Waits for a running scan, then prints the same line as `status`.                                                                                                                   |

### Other commands

| Command                                                      | Function                                                                             |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| `pam-biometrics policy check [FILE]`                         | Validates a policy file. Exits 1 with a message if the file is missing or not valid. |
| `pam-biometrics policy show [--service S] [--user U] [FILE]` | Prints the resolved settings as JSON.                                                |
| `pam-biometrics pam-helper [--prompt TEXT]`                  | Decides the PAM step. `pam_biometrics.so` runs it.                                   |

### Daemon flags

The daemon has these flags:

| Flag                    | Default                           | Description                                                 |
| ----------------------- | --------------------------------- | ----------------------------------------------------------- |
| `--device PATH`         |                                   | The V4L2 camera device.                                     |
| `--input-format FORMAT` |                                   | The V4L2 input format.                                      |
| `--width N`             | `640`                             | The frame width.                                            |
| `--height N`            | `360`                             | The frame height.                                           |
| `--scan-seconds N`      | `4`                               | The duration of a scan.                                     |
| `--enroll-seconds N`    | `6`                               | The duration of an enrollment.                              |
| `--result-ttl N`        | `120`                             | The time after which a scan result expires.                 |
| `--dark-threshold N`    | `10`                              | Frames with a lower mean brightness (0 to 255) are skipped. |
| `--greeter-user USER`   |                                   | A user that can start scans for every user.                 |
| `--state-dir PATH`      |                                   | The directory of the face models.                           |
| `--policy PATH`         | `/etc/pam-biometrics/policy.json` | The policy file.                                            |
| `--socket PATH`         | `/run/pam-biometrics/socket`      | The socket path.                                            |
| `--model-dir PATH`      | the dlib models of the package    | The directory of the dlib model files.                      |

`pam-biometricsd encode --width W --height H FILE` prints the face boxes and
encodings of a raw RGB24 image as JSON. The encoding parity check uses it.

The daemon writes one line for each scan, verification, and enrollment to
the journal: the user, the state, the best distance, and the number of
frames with a face.

## Policy reference

The policy file is `/etc/pam-biometrics/policy.json`. Without the file, the
built-in defaults apply. Unknown fields are errors. The schema is
[`schema/policy.schema.json`](schema/policy.schema.json). The directory
[`examples`](examples) contains valid policies.

```json
{
  "version": 1,
  "defaults": {
    "factors": ["fingerprint", "face"],
    "combine": "any",
    "on_no_decision": "allow",
    "timeout_seconds": 15,
    "fingerprint": { "max_tries": 3 },
    "face": {
      "match_distance": 0.45,
      "reject_distance": 0.6,
      "min_reject_frames": 3
    }
  },
  "services": {
    "sudo": { "factors": ["fingerprint", "face"] },
    "greetd": { "timeout_seconds": 20 }
  },
  "users": {
    "john": {
      "defaults": { "face": { "match_distance": 0.4 } },
      "services": { "polkit-1": { "on_no_decision": "deny" } }
    }
  }
}
```

### Resolution

The settings for a PAM service and a user come from five layers. Each layer
is a partial object. A later layer overrides an earlier layer:

1. The built-in defaults.
2. `defaults`.
3. `services[service]`.
4. `users[user].defaults`.
5. `users[user].services[service]`.

Lists replace the list of the earlier layer. Objects merge field by field.
`pam-biometrics policy show --service S --user U` prints the result.

### Fields

| Field                    | Type                          | Default                   | Meaning                                                                                      |
| ------------------------ | ----------------------------- | ------------------------- | -------------------------------------------------------------------------------------------- |
| `factors`                | list of `fingerprint`, `face` | `["fingerprint", "face"]` | The enabled factors. An empty list gives `no_decision` at once and ignores `on_no_decision`. |
| `combine`                | `any` or `all`                | `any`                     | How the step combines the factor outcomes.                                                   |
| `on_no_decision`         | `allow` or `deny`             | `allow`                   | `allow` gives `PAM_IGNORE`. `deny` gives `PAM_AUTH_ERR`.                                     |
| `timeout_seconds`        | integer, 1 or more            | `15`                      | The maximum wait for the factors.                                                            |
| `prompt`                 | text                          | depends on the factors    | The first line that the step shows. `--prompt` of the helper overrides it.                   |
| `fingerprint.max_tries`  | integer, 1 or more            | `3`                       | Wrong fingers before a reject.                                                               |
| `face.match_distance`    | number above 0                | `0.45`                    | A best distance at or below this value is a match.                                           |
| `face.reject_distance`   | number above 0                | `0.6`                     | A best distance above this value can reject. It must not be below `match_distance`.          |
| `face.min_reject_frames` | integer, 1 or more            | `3`                       | A reject needs a face in this many frames.                                                   |

The default prompt is `Touch the fingerprint reader or scan your face.` with
both factors, `Touch the fingerprint reader.` with the fingerprint only, and
`Scan your face.` with the face only.

### Semantics

| `combine` | Factor outcomes                                     | Step outcome                                        |
| --------- | --------------------------------------------------- | --------------------------------------------------- |
| `any`     | One factor gives `match`.                           | `success` at once.                                  |
| `any`     | No `match`. One factor gives `reject`.              | `reject` after all factors end or the timeout.      |
| `any`     | No `match` and no `reject`.                         | `no_decision`, then `on_no_decision` applies.       |
| `all`     | One factor gives `reject`.                          | `reject` at once.                                   |
| `all`     | All factors give `match`.                           | `success`.                                          |
| `all`     | A factor gives `no_decision` or the timeout passes. | `no_decision`, then `on_no_decision` applies.       |
| either    | `factors` is empty.                                 | `no_decision` at once. `on_no_decision` is ignored. |

The face factor classifies the scan result with the resolved thresholds:

| Condition                                                                 | Class          | Outcome       |
| ------------------------------------------------------------------------- | -------------- | ------------- |
| best ≤ `match_distance`                                                   | recognized     | `match`       |
| `match_distance` < best ≤ `reject_distance`                               | not sure       | `no_decision` |
| best > `reject_distance` and faces in at least `min_reject_frames` frames | not recognized | `reject`      |
| fewer frames with a face, or no face                                      | no face found  | `no_decision` |

A scan stops early when a frame reaches the smallest `match_distance` of all
resolved settings for the user. The result is then a match for every
service.

## Enrollment tips

- Enroll in the light where you use the computer:
  `pam-biometrics face enroll`.
- Add samples for each other light condition:
  `pam-biometrics face enroll --add`. The model keeps the newest 30
  samples. The match uses the closest sample.
- Enrollment needs exactly one face in at least 3 frames. It keeps at most
  10 samples per run, at even intervals.
- `pam-biometrics face verify --json` shows the best distance. The distance
  between two photos of the same person is usually 0.15 to 0.45. The
  distance to other people is usually above 0.6.
- A model file has the format
  `{"version": 1, "encodings": [[128 numbers], ...]}`. Encodings from the
  `face_recognition` Python package are valid samples.

## Development

```console
nix develop                         # enter the development shell
nix fmt                             # format all files
nix flake check --print-build-logs  # run all checks
```

The checks are:

| Check             | Content                                                                                               |
| ----------------- | ----------------------------------------------------------------------------------------------------- |
| `cargo-test`      | The unit tests of all crates. Mock factors cover the fingerprint paths.                               |
| `clippy`          | `cargo clippy --all-targets -- --deny warnings`.                                                      |
| `encoding-parity` | The encodings of the daemon and of `face_recognition` for the same pixels agree within 1e-3.          |
| `vm`              | A NixOS VM with a v4l2loopback camera that shows still photos. It drives PAM services with pamtester. |
| `pre-commit`      | treefmt and the Git hooks.                                                                            |

## License

The project is available under either of these licenses, at your option:

- [MIT](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)
