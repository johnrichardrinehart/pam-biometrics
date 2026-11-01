# pam-biometrics

pam-biometrics adds biometric steps around the password module of a PAM
stack. The user gives a fingerprint through fprintd or a face from a webcam,
before or after typing the password. A policy file sets the factors, how the
steps combine them, the prompts, and the thresholds for each PAM service and
user.

The password stays necessary. `pam_unix` checks it. The biometric steps can
only add a check to the password or reject the attempt.

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

| Part                 | Function                                                                                                                                                                                                         |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pam-biometricsd`    | A daemon that owns the camera and the face models. It scans faces on request and keeps the last result of each user.                                                                                             |
| `pam-biometrics`     | The command line client and the PAM helper. It enrolls faces and fingers, starts scans, and runs the factors of one PAM attempt. It does not link dlib, so it starts fast.                                       |
| `pam_biometrics.so`  | A small PAM module with two modes. `start` runs `pam-biometrics pam-session` and asks for the password. `finish` waits for the decision of the helper after the password and maps its exit code to a PAM result. |
| `policy.schema.json` | The JSON Schema of the policy file, in `share/pam-biometrics/`.                                                                                                                                                  |

Face scans start on demand only. The camera turns on only on an explicit
trigger: a key binding that runs `pam-biometrics face scan`, the face trigger
as the response to the password prompt, the face trigger typed on the
terminal during the wait of `finish`, or a command of the greeter. The daemon
scans for a few seconds and stores the result. The helper takes the result.

The password is always necessary. The biometric factors are optional, with
these rules:

- A wrong finger (`fingerprint.max_tries` times) or a face beyond
  `face.reject_distance` at any point of the attempt, before, during, or
  after the password, fails the attempt. The reject sticks: a later match,
  a scan without a face, or an uncertain face does not undo it, with
  `"combine": "any"` as with `"combine": "all"`.
- A missing finger or face costs time: `finish` waits `timeout_seconds` for
  one, then gives no decision. `on_no_decision` then applies: with `allow`,
  the password alone passes, with `deny`, the attempt fails.
- A face between `face.match_distance` and `face.reject_distance` counts as
  missing. The user can scan again until the end of the wait.

### One attempt

One call of `pam_authenticate` runs these steps:

1. `start` starts the helper. The helper runs the enabled factors in the
   background until `finish` or `pam_end`.
2. `start` asks for the password with `password_prompt`. The face trigger as
   the response starts a face scan. The trigger is Enter alone by default.
   `start` then shows `Scanning face…` and asks again with another prompt.
   Any other response becomes `PAM_AUTHTOK`, and `start` returns
   `PAM_IGNORE`. Without the face factor, every response is the password.
3. `pam_unix` checks the password with `try_first_pass`. A wrong password
   ends the attempt. `pam_end` then stops the helper.
4. `finish` decides with the outcomes so far. A reject decides at once and
   wins over a match. A match without a reject also decides at once.
   Otherwise `finish` shows `wait_message` and waits until a match or a
   reject, at most `timeout_seconds` from its start. Without a decision,
   `on_no_decision` applies. `finish` never asks a question.
5. `finish` stops the helper.

A user can thus give the finger or the face before the password, at the
prompt of `start`, or after the password, during the wait of `finish`.
`start` and `finish` show the lines of the helper as information messages:
before each prompt of `start`, and as they arrive during the wait, for
example `Fingerprint recognized.` or `Face not certain. Scan again.`.

### Face trigger during the wait

During the wait, `finish` reads lines from the terminal of the application
if `PAM_TTY` names a terminal in line mode (`ICANON`). That is the case for
`login`, `sudo`, and `su` on a terminal. A line equal to `face.trigger`
starts a face scan. With the default trigger, that is Enter alone. The
module discards other lines.

- `PAM_TTY` can be a name such as `tty1` or `pts/3`, or a path under
  `/dev/`. Other values, such as an X display `:0`, mean no terminal.
- The module opens the terminal read-only and non-blocking, and only if it
  is a character device in line mode. It never changes the terminal
  settings. It does not read a terminal without `ICANON`, such as a greeter
  that draws in raw mode. It discards the input that waits when the wait
  starts, and closes the terminal before `finish` returns.
- The module reads the terminal only during the wait, and nothing it reads
  is a secret: a line only decides whether to start a scan. The password
  comes from the prompt of `start`.
- Graphical clients have no terminal. A key binding starts a scan there.

The factors run like this:

- The fingerprint factor claims the default fprintd device and verifies any
  enrolled finger. After a wrong finger, it starts a new verification until
  `fingerprint.max_tries` wrong fingers. After a device error, a lost
  device, or no device, it starts again after a pause. The pause is 1 s and
  doubles up to 30 s while the errors repeat.
- The face factor takes the stored result of the user from the daemon. It
  asks again every 200 ms, and waits for a running scan. The helper
  consumes each result when it reads it. A result that nobody reads expires
  after the result TTL. A match ends the face factor. A result between the
  two thresholds, or without a face, does not end it, so the user can scan
  again. A reject ends the attempt for good: the helper ignores later
  results, also a match.

Each factor ends with one of three outcomes:

| Outcome       | Fingerprint                                                                            | Face                                                                                                                                  | Effect at `finish`                                      |
| ------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `match`       | fprintd reports `verify-match`.                                                        | The best distance is at or below `face.match_distance`.                                                                               | `success` at once.                                      |
| `reject`      | fprintd reports `verify-no-match` `fingerprint.max_tries` times.                       | Faces are in at least `face.min_reject_frames` frames, and the best distance is above `face.reject_distance`.                         | `reject` at once.                                       |
| `no_decision` | No finger, no reader, no enrolled finger, or a D-Bus error, until the end of the wait. | No scan, no face, dark frames, a best distance between the two thresholds, no enrolled face, or no daemon, until the end of the wait. | The wait goes on. At its end, `on_no_decision` applies. |

The exit code of the helper after `finish` gives the PAM result:

| Step outcome  | Exit code | PAM result     |
| ------------- | --------- | -------------- |
| `success`     | 0         | `PAM_SUCCESS`  |
| `reject`      | 10        | `PAM_AUTH_ERR` |
| `no_decision` | 20        | `PAM_IGNORE`   |

A crash of the helper also gives `PAM_IGNORE`. A helper that does not start
lets `start` return `PAM_IGNORE` without a prompt. `pam_unix` then asks for
the password itself.

### Helper protocol

The module and the helper exchange lines over a socket pair on the standard
input and output of the helper. A line is a word, then a space and a text
for some words. No text contains a line break. Each side ignores unknown
lines. The password never goes to the helper.

The helper sends its settings first:

| Line            | Meaning                                                                         |
| --------------- | ------------------------------------------------------------------------------- |
| `off`           | No factor is enabled. The helper exits.                                         |
| `prompt TEXT`   | The first password prompt.                                                      |
| `reprompt TEXT` | The password prompt after a face trigger. It differs from `prompt`.             |
| `trigger TEXT`  | The face trigger. An empty text is Enter alone. Absent without the face factor. |
| `ready`         | The end of the settings. The factors run.                                       |

Then the module sends commands:

| Command  | Effect                                                                  |
| -------- | ----------------------------------------------------------------------- |
| `scan`   | Start a face scan for the user. Also valid during the wait of `finish`. |
| `state`  | The helper replies `state VERDICT FACE`.                                |
| `finish` | Wait for a decision until the timeout, then exit with the exit code.    |
| `stop`   | Stop the factors and exit. The end of the input does the same.          |

The helper sends these lines at any time:

| Line                 | Meaning                                                                         |
| -------------------- | ------------------------------------------------------------------------------- |
| `info TEXT`          | A line for the user.                                                            |
| `state VERDICT FACE` | `VERDICT` is `success`, `reject`, or `pending`. `FACE` is `scanning` or `idle`. |

`finish` sends the wait message as an `info` line when it starts to wait.

### Face engine

The face engine uses dlib with the defaults of the `face_recognition` Python
package: the HOG frontal face detector without upsampling, the 5-point shape
predictor, 150 pixel face chips, one jitter, the ResNet model
`dlib_face_recognition_resnet_model_v1.dat`, and the Euclidean distance. The
model files come from nixpkgs. A flake check compares the encodings with
`face_recognition` within 1e-3.

## Security model

- `pam_unix` checks the password with the `requisite` control, so a wrong
  password ends the attempt. `start` only reads the password and hands it to
  `pam_unix` as `PAM_AUTHTOK`. `finish` adds a biometric check after the
  password. The biometric steps do not replace the password.
- The password stays in the PAM module. The helper never receives it. The
  module compares a response with the face trigger, then zeroes it before
  it frees it. Choose a trigger that is not a password: with the face
  factor, `start` never takes the trigger as the password, except after 5
  triggers in one attempt.
- The camera turns on only on an explicit trigger: a key binding, the face
  trigger at the password prompt or on the terminal during the wait, or a
  command of the greeter.
- `finish` reads only lines from the terminal of the attempt, only during
  the wait, and only in line mode. A line can only start a scan. See
  [Face trigger during the wait](#face-trigger-during-the-wait).
- An RGB camera has no liveness detection. A photo of the user can pass the
  face factor. Use the face factor as a convenience factor or together with
  the fingerprint (`"combine": "all"`), not as a strong factor alone.
- The daemon runs as the dynamic user `pam-biometrics` without network
  access. It can open video devices and the system bus only. The face
  models are in `/var/lib/pam-biometrics` with mode 0600. The daemon saves
  no images.
- Every user can connect to the socket `/run/pam-biometrics/socket`. The
  daemon reads the peer credentials of each connection and decides with
  this table:

  | Operation                          | Own face             | Face of another user                 | Root                      |
  | ---------------------------------- | -------------------- | ------------------------------------ | ------------------------- |
  | `enroll`                           | polkit `face.enroll` | polkit `face.manage-other`           | polkit, which allows root |
  | `delete`                           | polkit `face.delete` | polkit `face.manage-other`           | polkit, which allows root |
  | `verify`, `list`                   | allowed              | polkit `face.manage-other`           | allowed                   |
  | `scan`                             | allowed              | refused, except for the greeter user | allowed                   |
  | `status`, `wait`, PAM result reads | allowed              | refused                              | allowed                   |

  The helper runs as the caller of the PAM application: root for `login`,
  `sudo`, greetd, and the polkit agent helper of `run0`, and the user for a
  screen locker. Both may scan the face of the user that logs in.

- polkit decides with the actions below and the polkit rules of the
  system. The defaults need the password of the user for the own face, and
  an administrator password for the face of another user. Both need an
  active local session. polkit remembers a successful authentication for a
  short time.
- fprintd and its polkit rules decide the finger commands.
- The PAM module runs the helper from a store path that the build sets. The
  helper gets an empty environment except `PAM_USER`, `PAM_SERVICE`, and
  `PAM_TYPE`. A socket pair connects the module and the helper, so a helper
  that ends cannot raise SIGPIPE in the application.
- `pam_end` stops a helper that still runs, also after a wrong password or
  an aborted conversation: the module sends `stop`, sends SIGTERM after 2 s,
  sends SIGKILL after 0.5 s more, and reaps the helper. The helper releases
  the fprintd device on `stop`. fprintd also releases the device of a client
  that disconnects.

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
      services.polkit-1.on_no_decision = "deny";
      services.greetd.face.trigger = "f";
    };
  };
}
```

The module has these options:

| Option                                                | Default    | Description                                                             |
| ----------------------------------------------------- | ---------- | ----------------------------------------------------------------------- |
| `services.pam-biometrics.enable`                      | `false`    | Runs the daemon, installs the commands, and writes the policy.          |
| `services.pam-biometrics.package`                     | this flake | The package.                                                            |
| `services.pam-biometrics.camera.device`               |            | The V4L2 device of the camera.                                          |
| `services.pam-biometrics.camera.inputFormat`          | `null`     | The V4L2 input format, for example `mjpeg`.                             |
| `services.pam-biometrics.camera.width`                | `640`      | The frame width in pixels.                                              |
| `services.pam-biometrics.camera.height`               | `360`      | The frame height in pixels.                                             |
| `services.pam-biometrics.scanSeconds`                 | `4`        | The duration of a scan.                                                 |
| `services.pam-biometrics.enrollSeconds`               | `6`        | The duration of an enrollment.                                          |
| `services.pam-biometrics.resultTtlSeconds`            | `120`      | The time after which an unused scan result expires.                     |
| `services.pam-biometrics.greeterUser`                 | `null`     | A user that can start scans for every user.                             |
| `services.pam-biometrics.policy`                      | `{ }`      | The policy. The module sets `version` to 1 and checks it at build time. |
| `services.pam-biometrics.pamRules.start` (read-only)  |            | The PAM line of the biometric step before the password module.          |
| `services.pam-biometrics.pamRules.finish` (read-only) |            | The PAM line of the biometric step after the password module.           |

## PAM placement

Put `start` before the password module and `finish` after it. The
`pamRules.start` and `pamRules.finish` options contain the complete lines.
Every PAM service that uses pam-biometrics has this auth stack:

```text
auth [success=ok ignore=ignore default=die] /nix/store/…-pam-biometrics-0.1.0/lib/security/pam_biometrics.so start
auth requisite pam_unix.so nullok try_first_pass
auth [success=ok ignore=ignore default=die] /nix/store/…-pam-biometrics-0.1.0/lib/security/pam_biometrics.so finish
auth optional pam_gnome_keyring.so
```

The last line is optional. `pam_unix` needs `try_first_pass`: it takes the
password from `start`, and asks for the password itself when `start` sets
none, for example without an enabled factor.

For example, for a screen locker:

```nix
{ config, ... }:
{
  security.pam.services.hyprlock.text = ''
    account required pam_unix.so

    ${config.services.pam-biometrics.pamRules.start}
    auth requisite pam_unix.so nullok try_first_pass
    ${config.services.pam-biometrics.pamRules.finish}
    auth required pam_permit.so

    password required pam_unix.so
    session required pam_unix.so
  '';
}
```

The control values have this effect:

- `success=ok`: a match lets the stack continue.
- `ignore=ignore`: without a decision, the other modules decide. `start`
  always gives `PAM_IGNORE` after the password.
- `default=die`: a reject ends the attempt with a failure. So does an
  aborted conversation at the prompt of `start`, which gives
  `PAM_CONV_ERR`.

The first module argument selects the mode, `start` or `finish`. Without
one of them, the module runs `finish`, so one line after the password
module is a complete after-password step. The module passes the other
arguments to `pam-biometrics pam-session`, for example
`--policy=/etc/pam-biometrics/other.json`.

The applications differ in how they show the prompts:

- The second prompt of `start` differs from the first one, and the prompts
  alternate after more triggers. An application that answers a repeated
  prompt with the last response thus cannot start scans in a loop. After 5
  triggers in one attempt, every response is the password.
- `sudo` shows its own `[sudo] password for USER:` prompt instead of the
  PAM prompt `Password: `. It shows the other prompts as they are.
- `finish` asks nothing, so every application can wait through it. The
  application may show the wait message and the other information
  messages in its own way, or not at all.
- Only applications that set `PAM_TTY` to a terminal in line mode get the
  face trigger during the wait. Elsewhere, a key binding starts a scan.

## Key binding

A key binding starts a face scan for the user that the binding runs as. The
helper takes the result during the password prompt or the wait of
`finish`. The lock screen can show the state of the scan with
`pam-biometrics face status`.

An example for niri:

```kdl
binds {
    Mod+Alt+F allow-when-locked=true { spawn "pam-biometrics" "face" "scan"; }
}
```

The face trigger also starts a scan without a key binding: as the response
to the password prompt of `start`, and as a line on a terminal in line mode
during the wait of `finish`. The trigger is Enter alone by default.
`face.trigger` sets another text.

A login greeter runs as the greeter user. Set `greeterUser` to that user. The
greeter then runs `pam-biometrics face scan USER` for the user that logs in.
greetd runs the PAM stack as root, so the face trigger at the password
prompt works there without `greeterUser`.

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
| `pam-biometrics face scan [USER]`                 | Starts a background scan. The next or running PAM attempt for the user uses the result.                                                                                            |
| `pam-biometrics face status [USER] [--service S]` | Prints one line for a lock screen: `Face: scanning…`, `Face: recognized`, `Face: not sure`, `Face: not recognized`, `Face: no face found`, `Face: not enrolled`, or an empty line. |
| `pam-biometrics face wait [USER] [--service S]`   | Waits for a running scan, then prints the same line as `status`.                                                                                                                   |

`enroll` and `delete` need polkit authorization. So do `verify` and `list`
for the face of another user. See [Authorization](#authorization).

### Finger commands

The finger commands talk to fprintd on the system bus. Their output and exit
codes follow `fprintd-enroll`, `fprintd-verify`, `fprintd-delete`, and
`fprintd-list`. `USER` is the current user if it is not given. fprintd and
its polkit rules decide which caller can enroll, verify, or delete fingers of
other users.

| Command                                                        | Function                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pam-biometrics finger enroll [USER] [--finger NAME]`          | Enrolls a finger on the default device and prints each `Enroll result:` line. The default finger is `right-index-finger`. Exits 0 only on `enroll-completed`.                                                                                                                       |
| `pam-biometrics finger verify [USER] [--finger NAME] [--json]` | Verifies a finger on the default device and prints each `Verify result:` line. The default finger is `any`, which accepts every enrolled finger. Exits 0 only on `verify-match`. `--json` prints only `{"state": "match", "no-match", or "unavailable", "finger": …, "device": …}`. |
| `pam-biometrics finger delete USER... [--finger NAME]`         | Deletes all enrolled fingers of each user, or one finger, on every device.                                                                                                                                                                                                          |
| `pam-biometrics finger list USER...`                           | Lists the enrolled fingers of each user on every device.                                                                                                                                                                                                                            |

The finger names are `left-thumb`, `left-index-finger`, `left-middle-finger`,
`left-ring-finger`, `left-little-finger`, `right-thumb`,
`right-index-finger`, `right-middle-finger`, `right-ring-finger`, and
`right-little-finger`. Without a reader, or without enrolled fingers, the
commands print the reason and exit 1.

fprintd asks polkit before `finger enroll` and `finger delete`. The default
fprintd rule needs the password of the user for the own fingers.

### Authorization

polkit needs an authentication agent to ask for a password. A desktop
session often has one. Without it, the commands that need authorization
start `pkttyagent` for their own process when stdin is a terminal. polkit
then asks for the password in the terminal. Without a terminal and without
an agent, polkit refuses, and the command prints `not authorized`. Root
needs no password.

The face actions are in
`share/polkit-1/actions/io.github.johnrichardrinehart.pam-biometrics.policy`:

| Action ID                                                        | Default for an active session | Covers                                                          |
| ---------------------------------------------------------------- | ----------------------------- | --------------------------------------------------------------- |
| `io.github.johnrichardrinehart.pam-biometrics.face.enroll`       | `auth_self_keep`              | `face enroll` and `face enroll --add` for the own face.         |
| `io.github.johnrichardrinehart.pam-biometrics.face.delete`       | `auth_self_keep`              | `face delete` for the own face.                                 |
| `io.github.johnrichardrinehart.pam-biometrics.face.manage-other` | `auth_admin_keep`             | `face enroll`, `delete`, `verify`, and `list` for another user. |

Inactive and remote sessions get `no` for all three actions. A polkit rule
can change that. For example, this rule lets the members of `wheel` enroll
their own face without a password:

```nix
{
  security.polkit.extraConfig = ''
    polkit.addRule(function (action, subject) {
      if (action.id == "io.github.johnrichardrinehart.pam-biometrics.face.enroll" &&
          subject.isInGroup("wheel")) {
        return polkit.Result.YES;
      }
    });
  '';
}
```

The daemon checks the actions for the client processes. polkit lets only
root and the owners of an action do that, so the actions name the user
`pam-biometrics` as their owner. The NixOS module runs the daemon as that
user and turns on polkit.

### Other commands

| Command                                                      | Function                                                                             |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| `pam-biometrics policy check [FILE]`                         | Validates a policy file. Exits 1 with a message if the file is missing or not valid. |
| `pam-biometrics policy show [--service S] [--user U] [FILE]` | Prints the resolved settings as JSON.                                                |
| `pam-biometrics pam-session`                                 | Runs the factors of one PAM attempt. `pam_biometrics.so` runs it.                    |

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
      "min_reject_frames": 3,
      "trigger": ""
    }
  },
  "services": {
    "sudo": { "factors": ["fingerprint", "face"] },
    "greetd": { "timeout_seconds": 20, "face": { "trigger": "f" } }
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

| Field                    | Type                          | Default                   | Meaning                                                                                                                                   |
| ------------------------ | ----------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `factors`                | list of `fingerprint`, `face` | `["fingerprint", "face"]` | The enabled factors. An empty list gives `no_decision` at once and ignores `on_no_decision`.                                              |
| `combine`                | `any` or `all`                | `any`                     | How the steps combine the factor outcomes.                                                                                                |
| `on_no_decision`         | `allow` or `deny`             | `allow`                   | `allow` gives `PAM_IGNORE`. `deny` gives `PAM_AUTH_ERR`.                                                                                  |
| `timeout_seconds`        | integer, 1 or more            | `15`                      | The wait of `finish` for a finger or a face after the password, from the start of `finish`.                                               |
| `password_prompt`        | one line of text              | depends on the factors    | The first password prompt of `start`.                                                                                                     |
| `wait_message`           | one line of text              | depends on the factors    | The information message that `finish` shows when it waits.                                                                                |
| `fingerprint.max_tries`  | integer, 1 or more            | `3`                       | Wrong fingers before a reject.                                                                                                            |
| `face.match_distance`    | number above 0                | `0.45`                    | A best distance at or below this value is a match.                                                                                        |
| `face.reject_distance`   | number above 0                | `0.6`                     | A best distance above this value can reject. It must not be below `match_distance`.                                                       |
| `face.min_reject_frames` | integer, 1 or more            | `3`                       | A reject needs a face in this many frames.                                                                                                |
| `face.trigger`           | one line of text              | `""`                      | The response to the password prompt, or the line on the terminal during the wait, that starts a face scan. The empty text is Enter alone. |

The prompts, the message, and the trigger cannot contain line breaks or
other control characters. Without the face factor, the trigger means
nothing.

The defaults depend on the factors, on `face.trigger`, and on
`timeout_seconds`. `TRIGGER` stands for `press Enter` with the empty
trigger, and for `type f` with the trigger `f`. `N` stands for
`timeout_seconds`:

| Factors          | `password_prompt`                 | `wait_message`                                                      |
| ---------------- | --------------------------------- | ------------------------------------------------------------------- |
| both, `any`      | `Password (Enter to scan face): ` | `Touch the fingerprint reader or TRIGGER to scan your face (N s).`  |
| both, `all`      | `Password (Enter to scan face): ` | `Touch the fingerprint reader and TRIGGER to scan your face (N s).` |
| fingerprint only | `Password: `                      | `Touch the fingerprint reader (N s).`                               |
| face only        | `Password (Enter to scan face): ` | `TRIGGER to scan your face (N s).`, with a capital letter           |

With a non-empty trigger, the default password prompt is
`Password (type f to scan face): `. After a trigger, `start` asks with
`Password: `, or with `Password (face scan started): ` if the first prompt
is `Password: `. A custom `wait_message` appears as it is.

### Semantics

`finish` decides with the outcomes so far: the ended factors and the last
result of the face factor that is not a reject. A reject of either factor
sticks for the whole attempt and wins over a match. `finish` decides at
once on a reject or a match, before or during the wait. At the end of the
wait, a factor without an outcome counts as `no_decision`.

| `combine` | Factor outcomes                           | Step outcome                                                                |
| --------- | ----------------------------------------- | --------------------------------------------------------------------------- |
| either    | One factor gave `reject` at any point.    | `reject` at once, also after a `match`.                                     |
| `any`     | No `reject`. One factor gives `match`.    | `success` at once.                                                          |
| `any`     | No `match` and no `reject`.               | The wait goes on. At its end, `no_decision`, then `on_no_decision` applies. |
| `all`     | No `reject`. All factors give `match`.    | `success` at once.                                                          |
| `all`     | No `reject`. A factor has no `match` yet. | The wait goes on. At its end, `no_decision`, then `on_no_decision` applies. |
| either    | `factors` is empty.                       | `no_decision` at once. `start` asks nothing. `on_no_decision` is ignored.   |

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

| Check             | Content                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `cargo-test`      | The unit tests of all crates. Mock factors cover the fingerprint paths and the session decisions. Shell scripts stand in for the helper in the module tests. |
| `clippy`          | `cargo clippy --all-targets -- --deny warnings`.                                                                                                             |
| `encoding-parity` | The encodings of the daemon and of `face_recognition` for the same pixels agree within 1e-3.                                                                 |
| `vm`              | A NixOS VM with a v4l2loopback camera that shows still photos. It drives `start`, `pam_unix`, and `finish` with pamtester in a terminal.                     |
| `pre-commit`      | treefmt and the Git hooks.                                                                                                                                   |

## License

The project is available under either of these licenses, at your option:

- [MIT](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)
