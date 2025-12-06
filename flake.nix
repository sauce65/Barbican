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

      # NixOS VM tests for security validation
      checks = flake-utils.lib.eachDefaultSystemMap (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          # Individual module tests
          secure-users = import ./nix/tests/secure-users.nix { inherit pkgs lib; };
          hardened-ssh = import ./nix/tests/hardened-ssh.nix { inherit pkgs lib; };
          kernel-hardening = import ./nix/tests/kernel-hardening.nix { inherit pkgs lib; };
          secure-postgres = import ./nix/tests/secure-postgres.nix { inherit pkgs lib; };
          time-sync = import ./nix/tests/time-sync.nix { inherit pkgs lib; };
          intrusion-detection = import ./nix/tests/intrusion-detection.nix { inherit pkgs lib; };
          vm-firewall = import ./nix/tests/vm-firewall.nix { inherit pkgs lib; };
          resource-limits = import ./nix/tests/resource-limits.nix { inherit pkgs lib; };

          # Combined security suite (all tests)
          all = (import ./nix/tests/default.nix { inherit pkgs; lib = pkgs.lib; }).all;
        }
      );

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

      # Apps for running tests and generating audit reports
      apps = flake-utils.lib.eachDefaultSystemMap (system:
        let
          pkgs = import nixpkgs { inherit system; };
          allTests = (import ./nix/tests/default.nix { inherit pkgs; lib = pkgs.lib; }).all;
        in {
          # Run all security tests: nix run .#audit
          audit = {
            type = "app";
            program = toString (pkgs.writeShellScript "barbican-audit" ''
              set -euo pipefail

              echo "=============================================="
              echo "  Barbican Security Audit"
              echo "  NIST 800-53 Compliance Validation"
              echo "=============================================="
              echo ""
              echo "Building and running NixOS VM security tests..."
              echo ""

              # Build and run the combined test suite
              nix build ${self}#checks.${system}.all --no-link --print-out-paths 2>/dev/null | while read -r path; do
                if [ -d "$path" ]; then
                  echo "Test output: $path"
                  # Copy audit report if it exists
                  if [ -f "$path/barbican-audit.json" ]; then
                    cp "$path/barbican-audit.json" ./barbican-audit-$(date +%Y%m%d-%H%M%S).json
                    echo "Audit report saved to: barbican-audit-$(date +%Y%m%d-%H%M%S).json"
                  fi
                fi
              done

              echo ""
              echo "Audit complete. Run 'nix flake check' to run individual tests."
            '');
          };

          # Run specific test: nix run .#test-secure-users
          test-secure-users = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-secure-users" ''
              echo "Running secure-users tests..."
              nix build ${self}#checks.${system}.secure-users --no-link -L
            '');
          };

          test-hardened-ssh = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-hardened-ssh" ''
              echo "Running hardened-ssh tests..."
              nix build ${self}#checks.${system}.hardened-ssh --no-link -L
            '');
          };

          test-kernel-hardening = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-kernel-hardening" ''
              echo "Running kernel-hardening tests..."
              nix build ${self}#checks.${system}.kernel-hardening --no-link -L
            '');
          };

          test-secure-postgres = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-secure-postgres" ''
              echo "Running secure-postgres tests..."
              nix build ${self}#checks.${system}.secure-postgres --no-link -L
            '');
          };

          test-time-sync = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-time-sync" ''
              echo "Running time-sync tests..."
              nix build ${self}#checks.${system}.time-sync --no-link -L
            '');
          };

          test-intrusion-detection = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-intrusion-detection" ''
              echo "Running intrusion-detection tests..."
              nix build ${self}#checks.${system}.intrusion-detection --no-link -L
            '');
          };

          test-vm-firewall = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-vm-firewall" ''
              echo "Running vm-firewall tests..."
              nix build ${self}#checks.${system}.vm-firewall --no-link -L
            '');
          };

          test-resource-limits = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-resource-limits" ''
              echo "Running resource-limits tests..."
              nix build ${self}#checks.${system}.resource-limits --no-link -L
            '');
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
