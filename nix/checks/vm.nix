# Runs the daemon on a v4l2loopback camera that shows still photos, and
# drives PAM services that use the pam-biometrics step.
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
        alice.isNormalUser = true;
        bob.isNormalUser = true;
      };

      environment.systemPackages = [
        pkgs.ffmpeg-headless
        pkgs.pamtester
      ];

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
          defaults.timeout_seconds = 5;
          services = {
            test-deny.on_no_decision = "deny";
            test-none.factors = [ ];
            test-rescan.timeout_seconds = 40;
          };
        };
      };

      security.pam.services =
        lib.genAttrs
          [
            "test-own"
            "test-deny"
            "test-none"
            "test-rescan"
          ]
          (_: {
            text = ''
              auth requisite pam_permit.so
              ${config.services.pam-biometrics.pamRule}
              account required pam_permit.so
            '';
          });
    };

  testScript = ''
    import time

    machine.wait_for_unit("pam-biometrics.service")
    machine.wait_for_file("/run/pam-biometrics/socket")


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


    def authenticate(service):
        start = time.monotonic()
        status, output = machine.execute(f"pamtester {service} alice authenticate 2>&1")
        elapsed = time.monotonic() - start
        print(f"{service}: status {status} after {elapsed:.1f} s\n{output}")
        return status, output, elapsed


    with subtest("enroll from one photo"):
        show("${images.obama}")
        output = machine.succeed("runuser -u alice -- pam-biometrics enroll")
        assert "Enroll result: enroll-completed" in output, output
        output = machine.succeed("pam-biometrics list alice")
        assert "Face for user alice on /dev/video10:" in output, output
        machine.succeed("stat -c %a /var/lib/private/pam-biometrics/alice.json | grep -x 600")

    with subtest("other users cannot scan for alice"):
        output = machine.fail("runuser -u bob -- pam-biometrics scan alice")
        assert "permission denied" in output, output

    with subtest("own face after a scan gives success"):
        show("${images.obama2}")
        machine.succeed("pam-biometrics scan alice")
        output = machine.succeed("pam-biometrics wait alice")
        assert output.strip() == "Face: recognized", output
        status, output, _ = authenticate("test-own")
        assert status == 0, output
        assert "Face recognized." in output, output
        assert "successfully authenticated" in output, output
        # The step consumed the result.
        assert machine.succeed("pam-biometrics status alice").strip() == ""

    with subtest("verify mirrors fprintd-verify"):
        output = machine.succeed("runuser -u alice -- pam-biometrics verify")
        assert "Verify result: verify-match (done)" in output, output

    with subtest("a stranger gives AUTH_ERR"):
        show("${images.biden-top}")
        machine.succeed("pam-biometrics scan alice")
        output = machine.succeed("pam-biometrics wait alice")
        assert output.strip() == "Face: not recognized", output
        status, output, _ = authenticate("test-own")
        assert status != 0, output
        assert "Face not recognized." in output, output
        assert "Not recognized." in output, output
        assert "Authentication failure" in output, output
        machine.fail("runuser -u alice -- pam-biometrics verify")

    with subtest("no scan gives success through PAM_IGNORE"):
        status, output, elapsed = authenticate("test-own")
        assert status == 0, output
        assert "Touch the fingerprint reader or scan your face." in output, output
        assert "successfully authenticated" in output, output
        assert elapsed >= 4, elapsed

    with subtest("on_no_decision deny fails without a scan"):
        status, output, _ = authenticate("test-deny")
        assert status != 0, output
        assert "A fingerprint or a face is necessary." in output, output
        assert "Authentication failure" in output, output

    with subtest("an empty factor list gives PAM_IGNORE at once"):
        status, output, elapsed = authenticate("test-none")
        assert status == 0, output
        assert "Touch" not in output, output
        assert elapsed < 3, elapsed

    with subtest("a second scan in the same attempt counts"):
        show("${images.biden-top}")
        machine.succeed(
            "systemd-run --unit=rescan-auth --collect /bin/sh -c "
            "'/run/current-system/sw/bin/pamtester test-rescan alice authenticate "
            "> /tmp/rescan.log 2>&1; echo $? > /tmp/rescan.status'"
        )
        time.sleep(1)
        machine.succeed("pam-biometrics scan alice")
        machine.succeed("pam-biometrics wait alice")
        # The PAM step took the reject and keeps waiting.
        machine.wait_until_succeeds('test -z "$(pam-biometrics status alice)"', timeout=10)
        machine.fail("test -e /tmp/rescan.status")
        show("${images.obama2}")
        machine.succeed("pam-biometrics scan alice")
        machine.wait_for_file("/tmp/rescan.status", timeout=40)
        output = machine.succeed("cat /tmp/rescan.log")
        print(output)
        assert machine.succeed("cat /tmp/rescan.status").strip() == "0", output
        assert "Face not recognized." in output, output
        assert "Face recognized." in output, output
        assert "successfully authenticated" in output, output

    machine.succeed("journalctl -u pam-biometrics.service | grep 'scan for alice: finished'")
  '';
}
