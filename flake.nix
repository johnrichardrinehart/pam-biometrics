{
  description = "Fingerprint and face factors for PAM, after the password";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, self, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      imports = [ inputs.flake-parts.flakeModules.partitions ];

      perSystem =
        { pkgs, ... }:
        {
          packages = rec {
            pam-biometrics = pkgs.callPackage ./nix/packages/pam-biometrics.nix { };
            default = pam-biometrics;
          };
        };

      flake.nixosModules.default =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/nixos/pam-biometrics.nix ];
          services.pam-biometrics.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.pam-biometrics;
        };

      # Development tools do not enter the input closure of package and
      # module consumers.
      partitionedAttrs = {
        checks = "dev";
        devShells = "dev";
        formatter = "dev";
      };

      partitions.dev = {
        extraInputsFlake = ./dev;
        module = import ./nix/flake/dev-partition.nix;
      };
    };
}
