{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.pam-biometrics;
  json = pkgs.formats.json { };

  policyFile =
    pkgs.runCommand "pam-biometrics-policy.json"
      {
        nativeBuildInputs = [ cfg.package ];
        policy = builtins.toJSON ({ version = 1; } // cfg.policy);
        passAsFile = [ "policy" ];
      }
      ''
        cp "$policyPath" "$out"
        pam-biometrics policy check "$out"
      '';

  stateDirectory = "/var/lib/pam-biometrics";
  socket = "/run/pam-biometrics/socket";
in
{
  options.services.pam-biometrics = {
    enable = lib.mkEnableOption "the pam-biometrics face daemon and policy";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The pam-biometrics package.";
    };

    camera = {
      device = lib.mkOption {
        type = lib.types.str;
        example = "/dev/v4l/by-id/usb-Example_Webcam-video-index0";
        description = "The V4L2 device of the camera.";
      };

      inputFormat = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "mjpeg";
        description = ''
          The V4L2 input format. With a value, the daemon also requests the
          width and height from the camera.
        '';
      };

      width = lib.mkOption {
        type = lib.types.ints.positive;
        default = 640;
        description = "The frame width in pixels.";
      };

      height = lib.mkOption {
        type = lib.types.ints.positive;
        default = 360;
        description = "The frame height in pixels.";
      };
    };

    scanSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 4;
      description = "The duration of a face scan.";
    };

    enrollSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 6;
      description = "The duration of an enrollment.";
    };

    resultTtlSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 120;
      description = "The time after which an unused scan result expires.";
    };

    greeterUser = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "greeter";
      description = ''
        A user that can start face scans for any user, for example the user
        of the login greeter.
      '';
    };

    policy = lib.mkOption {
      inherit (json) type;
      default = { };
      example = lib.literalExpression ''
        {
          defaults.timeout_seconds = 20;
          services.polkit-1.on_no_decision = "deny";
          users.alice.defaults.face.match_distance = 0.4;
        }
      '';
      description = ''
        The policy. The module writes it to
        {file}`/etc/pam-biometrics/policy.json` and sets `version` to 1.
        `pam-biometrics policy check` validates it at build time. See the
        README for the fields.
      '';
    };

    pamRules =
      let
        rule =
          mode: description:
          lib.mkOption {
            type = lib.types.str;
            readOnly = true;
            default = "auth [success=ok ignore=ignore default=die] ${cfg.package}/lib/security/pam_biometrics.so ${mode}";
            defaultText = lib.literalExpression ''"auth [success=ok ignore=ignore default=die] ''${cfg.package}/lib/security/pam_biometrics.so ${mode}"'';
            description = ''
              ${description} Each PAM service that uses pam-biometrics has
              this auth stack:

              ```
              ''${config.services.pam-biometrics.pamRules.start}
              auth requisite pam_unix.so nullok try_first_pass
              ''${config.services.pam-biometrics.pamRules.finish}
              auth optional pam_gnome_keyring.so
              ```

              `start` asks for the password and gives it to `pam_unix`
              through `try_first_pass`. The face trigger as a response
              starts a face scan. In `finish`, a match or a reject so far
              decides at once. Otherwise, with the policy value
              `after_password = "wait"` (the default), `finish` asks
              nothing, shows `wait_message`, and watches a terminal in
              line mode for the face trigger: `PAM_TTY`, or the terminal of
              the polkit agent, such as pkttyagent under `run0`. With
              `after_password = "prompt"`, for clients without a terminal,
              `finish` asks once with `after_password_prompt`; the trigger
              as the answer starts a face scan. Then `finish` waits up to
              `timeout_seconds` for a finger or a face, and
              `on_no_decision` applies. The last line is optional.
            '';
          };
      in
      {
        start = rule "start" "The PAM line of the biometric step before the password module.";
        finish = rule "finish" "The PAM line of the biometric step after the password module.";
      };
  };

  config = lib.mkIf cfg.enable {
    # The package also holds the polkit actions in share/polkit-1/actions.
    # NixOS links share/polkit-1 of system packages into the directory
    # that polkitd reads.
    environment.systemPackages = [ cfg.package ];

    # The daemon asks polkit before face model changes.
    security.polkit.enable = true;

    # The socket-activated polkit agent helper has no PAM_TTY. During the
    # wait of finish, pam_biometrics.so reads trigger lines from the
    # controlling terminal of the agent at the other end of the socket, for
    # example pkttyagent under run0. The upstream unit allows only
    # /dev/null. PrivateDevices keeps /dev/pts, so read access to the
    # pseudo terminals is enough.
    systemd.services."polkit-agent-helper@".serviceConfig.DeviceAllow = [ "char-pts r" ];

    environment.etc."pam-biometrics/policy.json".source = policyFile;

    systemd.services.pam-biometrics = {
      description = "Face scans for the pam-biometrics PAM step";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe' cfg.package "pam-biometricsd")
            "--device"
            cfg.camera.device
            "--width"
            (toString cfg.camera.width)
            "--height"
            (toString cfg.camera.height)
            "--scan-seconds"
            (toString cfg.scanSeconds)
            "--enroll-seconds"
            (toString cfg.enrollSeconds)
            "--result-ttl"
            (toString cfg.resultTtlSeconds)
            "--state-dir"
            stateDirectory
            "--policy"
            "/etc/pam-biometrics/policy.json"
            "--socket"
            socket
          ]
          ++ lib.optionals (cfg.camera.inputFormat != null) [
            "--input-format"
            cfg.camera.inputFormat
          ]
          ++ lib.optionals (cfg.greeterUser != null) [
            "--greeter-user"
            cfg.greeterUser
          ]
        );
        DynamicUser = true;
        # The polkit actions name this user as their owner, so that the
        # daemon can check them for the processes of its clients.
        User = "pam-biometrics";
        SupplementaryGroups = [ "video" ];
        StateDirectory = "pam-biometrics";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "pam-biometrics";
        RuntimeDirectoryMode = "0755";
        DevicePolicy = "closed";
        DeviceAllow = [ "char-video4linux rw" ];
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        ProtectHome = true;
        Restart = "on-failure";
      };
    };
  };
}
