# Runs the daemon on a v4l2loopback camera that shows still photos, and
# drives PAM stacks with the start and finish steps through a terminal.
{
  images,
  nixosModules,
  testers,
}:
testers.runNixOSTest {
  name = "pam-biometrics";

  nodes.machine =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    {
      imports = [ nixosModules.default ];

      virtualisation = {
        cores = 2;
        memorySize = 2048;
      };

      boot = {
        extraModulePackages = [ config.boot.kernelPackages.v4l2loopback ];
        kernelModules = [ "v4l2loopback" ];
        extraModprobeConfig = ''
          options v4l2loopback devices=1 video_nr=10 card_label=camera exclusive_caps=1
        '';
      };

      users.users = {
        alice = {
          isNormalUser = true;
          password = "alice-password";
        };
        bob.isNormalUser = true;
      };

      # fprintd runs without a reader. The finger commands report that.
      services.fprintd.enable = true;

      environment.systemPackages = [
        pkgs.ffmpeg-headless
        pkgs.pamtester
        (pkgs.writers.writePython3Bin "converse" {
          libraries = [ pkgs.python3Packages.pexpect ];
        } (builtins.readFile ./converse.py))
      ];

      # polkitd logs the registration of authentication agents at the info
      # level.
      systemd.services.polkit.serviceConfig.ExecStart = lib.mkForce [
        ""
        "${config.security.polkit.package.out}/lib/polkit-1/polkitd --log-level=info"
      ];

      # Test only: alice can enroll her own face once the test creates the
      # flag file. Without the file, polkit has no agent to ask and refuses.
      security.polkit.extraConfig = ''
        polkit.addRule(function (action, subject) {
          if (action.id == "io.github.johnrichardrinehart.pam-biometrics.face.enroll" &&
              subject.user == "alice") {
            try {
              polkit.spawn(["/run/current-system/sw/bin/test", "-e", "/run/allow-alice-enroll"]);
              return polkit.Result.YES;
            } catch (error) {
              return polkit.Result.NOT_HANDLED;
            }
          }
        });
      '';

      services.pam-biometrics = {
        enable = true;
        camera = {
          device = "/dev/video10";
          width = 1280;
          height = 720;
        };
        scanSeconds = 6;
        enrollSeconds = 10;
        policy = {
          defaults.timeout_seconds = 15;
          services = {
            test-deny.on_no_decision = "deny";
            test-none.factors = [ ];
            test-trigger.face.trigger = "f";
            test-rescan.timeout_seconds = 40;
          };
        };
      };

      security.pam.services =
        let
          inherit (config.services.pam-biometrics) pamRules;
        in
        lib.genAttrs
          [
            "test-own"
            "test-deny"
            "test-none"
            "test-trigger"
            "test-rescan"
          ]
          (_: {
            text = ''
              ${pamRules.start}
              auth requisite pam_unix.so nullok try_first_pass
              ${pamRules.finish}
              account required pam_permit.so
            '';
          })
        // {
          # A stack without start: pam_unix asks for the password itself.
          test-finish.text = ''
            auth requisite pam_unix.so nullok
            ${pamRules.finish}
            account required pam_permit.so
          '';
        };
    };

  testScript = ''
    import json
    import shlex
    import time

    machine.wait_for_unit("pam-biometrics.service")
    machine.wait_for_file("/run/pam-biometrics/socket")

    PROMPT = "?Password (Enter to scan face): "
    FINISH = "?Touch the fingerprint reader, or press Enter to scan your face: "
    PASSWORD = "!alice-password"


    def show(image):
        """Feed a still image to the loopback camera."""
        machine.execute("systemctl stop camera-feed")
        machine.succeed(
            "systemd-run --unit=camera-feed --collect "
            "ffmpeg -nostdin -loglevel error -re -loop 1 -i " + image + " "
            "-vf 'scale=1280:720:force_original_aspect_ratio=decrease,"
            "pad=1280:720:(ow-iw)/2:(oh-ih)/2,format=yuv420p' "
            "-f v4l2 /dev/video10"
        )
        machine.wait_until_succeeds("systemctl is-active camera-feed")
        time.sleep(3)


    def no_helper():
        """pam_end leaves no helper process."""
        machine.fail("pgrep -f 'pam-biometrics pam-[s]ession'")


    def converse(service, *steps):
        """Authenticate alice through a terminal. See converse.py."""
        command = shlex.join(["converse", service, "alice", *steps])
        start = time.monotonic()
        status, output = machine.execute(command)
        elapsed = time.monotonic() - start
        print(f"{service}: status {status} after {elapsed:.1f} s\n{output}")
        assert status in (0, 1), output
        no_helper()
        return status, output, elapsed


    def agent_registrations():
        return int(
            machine.succeed(
                "journalctl -u polkit.service"
                " | grep -c 'Registered Authentication Agent for unix-process' || true"
            )
        )


    with subtest("enrollment without polkit authorization fails"):
        show("${images.obama}")
        # Without a terminal, the command starts no polkit agent.
        output = machine.fail("runuser -u alice -- pam-biometrics face enroll < /dev/null")
        assert "Enroll result: enroll-failed (not authorized)" in output, output
        machine.fail("test -e /var/lib/private/pam-biometrics/alice.json")
        output = machine.fail(
            "runuser -u bob -- pam-biometrics face enroll alice < /dev/null"
        )
        assert "Enroll result: enroll-failed (not authorized)" in output, output
        output = machine.fail("runuser -u bob -- pam-biometrics face list alice < /dev/null")
        assert "Failed for user alice: not authorized" in output, output
        assert agent_registrations() == 0
        # With a terminal, the command starts pkttyagent for its own process.
        # polkit still refuses without a prompt, because the runuser session
        # is not active.
        output = machine.fail(
            "script -qec 'runuser -u alice -- pam-biometrics face enroll' /dev/null"
        )
        assert "Enroll result: enroll-failed (not authorized)" in output, output
        assert "cannot start" not in output, output
        # polkitd writes each registration to syslog and to stdout.
        assert agent_registrations() > 0

    with subtest("enroll from one photo with a polkit rule"):
        machine.succeed("touch /run/allow-alice-enroll")
        output = machine.succeed("runuser -u alice -- pam-biometrics face enroll")
        assert "Enroll result: enroll-completed" in output, output
        output = machine.succeed("pam-biometrics face list alice")
        assert "Face for user alice on /dev/video10:" in output, output
        machine.succeed("stat -c %a /var/lib/private/pam-biometrics/alice.json | grep -x 600")
        # Without a rule, alice cannot delete her face.
        output = machine.fail("runuser -u alice -- pam-biometrics face delete alice")
        assert "Failed for user alice: not authorized" in output, output

    with subtest("polkit authorizes root without a prompt"):
        output = machine.succeed("pam-biometrics face enroll alice --add")
        assert "Enroll result: enroll-completed (20 samples)" in output, output
        output = machine.succeed("pam-biometrics face delete bob")
        assert "No face to delete on /dev/video10" in output, output

    with subtest("other users cannot scan for alice"):
        output = machine.fail("runuser -u bob -- pam-biometrics face scan alice")
        assert "permission denied" in output, output

    with subtest("a scan before the attempt counts without start"):
        show("${images.obama2}")
        machine.succeed("pam-biometrics face scan alice")
        output = machine.succeed("pam-biometrics face wait alice")
        assert output.strip() == "Face: recognized", output
        # pam_unix asks for the password itself.
        status, output, _ = converse("test-finish", "?Password: ", PASSWORD)
        assert status == 0, output
        assert "Face recognized." in output, output
        assert "successfully authenticated" in output, output
        # The step consumed the result.
        assert machine.succeed("pam-biometrics face status alice").strip() == ""

    with subtest("verify mirrors fprintd-verify"):
        output = machine.succeed("runuser -u alice -- pam-biometrics face verify")
        assert "Verify result: verify-match (done)" in output, output

    with subtest("the password alone gives success at once"):
        status, output, elapsed = converse("test-own", PROMPT, PASSWORD)
        assert status == 0, output
        assert "successfully authenticated" in output, output
        assert "Touch" not in output, output
        assert elapsed < 5, elapsed

    with subtest("a wrong password fails and stops the helper"):
        status, output, _ = converse("test-own", PROMPT, "!wrong-password")
        assert status == 1, output
        assert "Authentication failure" in output, output

    with subtest("Enter scans the face before the password"):
        status, output, _ = converse(
            "test-own", PROMPT, "!", "?Scanning face", "?Password: ", PASSWORD
        )
        assert status == 0, output
        assert "Face recognized." in output, output
        assert "successfully authenticated" in output, output
        assert machine.succeed("pam-biometrics face status alice").strip() == ""

    with subtest("a stranger gives AUTH_ERR"):
        show("${images.biden-top}")
        status, output, _ = converse(
            "test-own", PROMPT, "!", "?Scanning face", "?Password: ", PASSWORD
        )
        assert status == 1, output
        assert "Face not recognized." in output, output
        assert "Not recognized." in output, output
        assert "Authentication failure" in output, output
        machine.fail("runuser -u alice -- pam-biometrics face verify")

    with subtest("deny asks after the password, and Enter scans the face"):
        show("${images.obama2}")
        status, output, _ = converse("test-deny", PROMPT, PASSWORD, FINISH, "!")
        assert status == 0, output
        assert "Scanning face" in output, output
        assert "Face recognized." in output, output
        assert "successfully authenticated" in output, output

    with subtest("deny fails without a factor"):
        status, output, _ = converse("test-deny", PROMPT, PASSWORD, FINISH, "!no")
        assert status == 1, output
        assert "Scanning face" not in output, output
        assert "A fingerprint or a face is necessary." in output, output
        assert "Authentication failure" in output, output

    with subtest("a custom trigger scans the face"):
        trigger_prompt = "?Password (type f to scan face): "
        status, output, _ = converse(
            "test-trigger", trigger_prompt, "!f", "?Scanning face", "?Password: ", PASSWORD
        )
        assert status == 0, output
        assert "Face recognized." in output, output
        # Enter alone is a password here.
        status, output, _ = converse("test-trigger", trigger_prompt, "!")
        assert status == 1, output
        assert "Scanning face" not in output, output

    with subtest("an empty factor list leaves the prompt to pam_unix"):
        status, output, elapsed = converse("test-none", "?Password: ", PASSWORD)
        assert status == 0, output
        assert "scan face" not in output, output
        assert elapsed < 5, elapsed

    with subtest("key binding scans during the password prompt count"):
        show("${images.biden-top}")
        inner = shlex.join(
            ["converse", "test-rescan", "alice", PROMPT, "=/tmp/rescan-go", PASSWORD]
        )
        machine.succeed(
            "systemd-run --unit=rescan-auth --collect /bin/sh -c "
            + shlex.quote(
                "export PATH=/run/current-system/sw/bin:$PATH; "
                + inner
                + " > /tmp/rescan.log 2>&1; echo $? > /tmp/rescan.status"
            )
        )
        machine.wait_until_succeeds("pgrep -f 'pam-biometrics pam-[s]ession'")
        machine.succeed("pam-biometrics face scan alice")
        machine.succeed("pam-biometrics face wait alice")
        # The helper took the reject during the password prompt.
        machine.wait_until_succeeds(
            'test -z "$(pam-biometrics face status alice)"', timeout=10
        )
        show("${images.obama2}")
        machine.succeed("pam-biometrics face scan alice")
        machine.wait_until_succeeds(
            'test -z "$(pam-biometrics face status alice)"', timeout=20
        )
        machine.fail("test -e /tmp/rescan.status")
        machine.succeed("touch /tmp/rescan-go")
        machine.wait_for_file("/tmp/rescan.status", timeout=40)
        output = machine.succeed("cat /tmp/rescan.log")
        print(output)
        assert machine.succeed("cat /tmp/rescan.status").strip() == "0", output
        assert "Face not recognized." in output, output
        assert "Face recognized." in output, output
        assert "successfully authenticated" in output, output
        no_helper()

    with subtest("finger commands report a missing reader"):
        status, output = machine.execute("pam-biometrics finger list alice")
        assert status == 1, output
        assert output.strip() == "No devices available", output
        status, output = machine.execute("pam-biometrics finger enroll alice")
        assert status == 1, output
        assert output.strip() == "Impossible to enroll: No devices available", output
        status, output = machine.execute("pam-biometrics finger verify alice --json")
        assert status == 1, output
        assert json.loads(output) == {
            "state": "unavailable",
            "finger": "any",
            "device": None,
        }, output

    machine.succeed("journalctl -u pam-biometrics.service | grep 'scan for alice: finished'")
  '';
}
