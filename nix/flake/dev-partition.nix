{ inputs, ... }:
{
  imports = [
    inputs.git-hooks.flakeModule
    inputs.treefmt-nix.flakeModule
  ];

  perSystem =
    {
      config,
      pkgs,
      system,
      ...
    }:
    let
      package = inputs.self.packages.${system}.pam-biometrics;
    in
    {
      checks = import ../checks { inherit pkgs package; };

      # One definition drives `nix fmt` and the treefmt Git hook. The hook is
      # also exercised by the sandboxed pre-commit check. Formatters and
      # file-oriented linters belong here, not in git-hooks.
      treefmt = {
        projectRootFile = "flake.nix";

        # `checks.pre-commit` already runs the treefmt hook in the sandbox
        # along with Git-specific hooks. Avoid a second derivation that
        # repeats it.
        flakeCheck = false;
        programs = {
          actionlint.enable = true;
          clang-format.enable = true;
          deadnix.enable = true;
          nixfmt.enable = true;
          prettier.enable = true;
          ruff-check.enable = true;
          ruff-format.enable = true;
          rustfmt.enable = true;
          shellcheck.enable = true;
          shfmt.enable = true;
          statix.enable = true;
          taplo.enable = true;
        };
        settings.formatter = {
          shellcheck.includes = [
            "*.sh"
            ".envrc"
          ];
          shfmt.includes = [
            "*.sh"
            ".envrc"
          ];
        };
      };

      pre-commit.settings.hooks = {
        treefmt.enable = true;
        check-added-large-files.enable = true;
        check-merge-conflicts.enable = true;

        flake-check-before-push = {
          enable = true;
          name = "authoritative Nix checks";
          entry = "${pkgs.nix}/bin/nix flake check --print-build-logs";
          always_run = true;
          pass_filenames = false;
          require_serial = true;
          stages = [ "pre-push" ];
        };
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [ package ];
        packages = [
          pkgs.clippy
          pkgs.nixd
          pkgs.rust-analyzer
          pkgs.rustfmt
        ];
        shellHook = config.pre-commit.installationScript;
      };
    };
}
