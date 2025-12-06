{
  description = "Barbican - NIST 800-53 Compliant Security Infrastructure for Rust and NixOS";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      # NixOS modules for security hardening
      nixosModules = {
        # Individual modules
        secureUsers = import ./nix/modules/secure-users.nix;
        securePostgres = import ./nix/modules/secure-postgres.nix;
        hardenedSSH = import ./nix/modules/hardened-ssh.nix;
        secretsManagement = import ./nix/modules/secrets-management.nix;
        observabilityAuth = import ./nix/modules/observability-auth.nix;
        vmFirewall = import ./nix/modules/vm-firewall.nix;
        databaseBackup = import ./nix/modules/database-backup.nix;
        resourceLimits = import ./nix/modules/resource-limits.nix;
        kernelHardening = import ./nix/modules/kernel-hardening.nix;
        timeSync = import ./nix/modules/time-sync.nix;
        intrusionDetection = import ./nix/modules/intrusion-detection.nix;
        systemdHardening = import ./nix/modules/systemd-hardening.nix;

        # Composite profiles
        minimal = import ./nix/profiles/minimal.nix;
        standard = import ./nix/profiles/standard.nix;
        hardened = import ./nix/profiles/hardened.nix;

        # All modules combined (for easy import)
        all = { ... }: {
          imports = [
            ./nix/modules/secure-users.nix
            ./nix/modules/secure-postgres.nix
            ./nix/modules/hardened-ssh.nix
            ./nix/modules/secrets-management.nix
            ./nix/modules/observability-auth.nix
            ./nix/modules/vm-firewall.nix
            ./nix/modules/database-backup.nix
            ./nix/modules/resource-limits.nix
            ./nix/modules/kernel-hardening.nix
            ./nix/modules/time-sync.nix
            ./nix/modules/intrusion-detection.nix
            ./nix/modules/systemd-hardening.nix
          ];
        };
      };

      # Helper library
      lib = {
        networkZones = import ./nix/lib/network-zones.nix { lib = nixpkgs.lib; };
        pki = import ./nix/lib/pki.nix { lib = nixpkgs.lib; };
        systemdHardening = import ./nix/lib/systemd-hardening-lib.nix { lib = nixpkgs.lib; };
      };

    in {
      inherit nixosModules lib;

      # Rust crate outputs
      packages = flake-utils.lib.eachDefaultSystemMap (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs { inherit system overlays; };
          rustToolchain = pkgs.rust-bin.stable.latest.default;
        in {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "barbican";
            version = "0.1.0";
            src = ./src;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];

            meta = with pkgs.lib; {
              description = "NIST 800-53 compliant security infrastructure library";
              license = licenses.mit;
            };
          };
        }
      );

      devShells = flake-utils.lib.eachDefaultSystemMap (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs { inherit system overlays; };
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" ];
          };
        in {
          default = pkgs.mkShell {
            buildInputs = [
              rustToolchain
              pkgs.pkg-config
              pkgs.openssl
              pkgs.postgresql_16
              pkgs.sqlx-cli
            ];

            RUST_BACKTRACE = 1;
          };
        }
      );

      # Template for new projects using Barbican
      templates = {
        microvm-stack = {
          path = ./templates/microvm-stack;
          description = "Secure MicroVM stack with Barbican hardening";
        };
      };
    };
}
