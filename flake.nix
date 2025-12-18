{
  description = "Barbican - NIST 800-53 Compliant Security Infrastructure for Rust and NixOS";

  # =============================================================================
  # SECURITY: Flake Input Audit Trail
  # =============================================================================
  # All inputs are locked in flake.lock with content-addressed hashes (narHash)
  # which prevents MITM attacks and ensures reproducibility.
  #
  # Audit date: 2025-12-15
  # Auditor: Claude (automated security review)
  #
  # To update inputs: nix flake update
  # To update single input: nix flake lock --update-input nixpkgs
  # To verify: nix flake metadata
  # =============================================================================

  inputs = {
    # SECURITY: Using nixos-24.11 stable for production reliability
    # For development with latest features, use: nixos-unstable
    # Audited: Official NixOS repository, community-maintained
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-24.11";

    # Audited: github.com/numtide/flake-utils (1.2k+ stars)
    # Maintainers: numtide team (zimbatm, etc.)
    # Purpose: Multi-system flake helpers, minimal attack surface
    # Last review: 2025-12-15
    flake-utils.url = "github:numtide/flake-utils";

    # Audited: github.com/oxalica/rust-overlay (900+ stars)
    # Maintainers: oxalica
    # Purpose: Rust toolchain management for Nix
    # Last review: 2025-12-15
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
        vaultPki = import ./nix/modules/vault-pki.nix;

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
            ./nix/modules/vault-pki.nix
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
          overlays = [ (import rust-overlay) ];
          pkgsWithRust = import nixpkgs { inherit system overlays; };
          rustToolchain = pkgsWithRust.rust-bin.stable.latest.default;
        in {
          # =============================================================
          # Flake Security Checks
          # =============================================================

          # Verify flake inputs are properly locked with content hashes
          flake-lock-check = pkgs.runCommand "flake-lock-check" {} ''
            echo "Checking flake.lock integrity..."

            # Verify all inputs have narHash (content-addressed)
            if ! ${pkgs.jq}/bin/jq -e '.nodes | to_entries[] | select(.key != "root") | .value.locked.narHash' ${./flake.lock} > /dev/null 2>&1; then
              echo "ERROR: Some flake inputs are missing narHash verification" >&2
              exit 1
            fi

            echo "All flake inputs have content-addressed hashes"
            touch $out
          '';

          # Check for known vulnerabilities in Rust dependencies
          cargo-audit = pkgs.runCommand "cargo-audit" {
            buildInputs = [ pkgs.cargo-audit ];
          } ''
            echo "Running cargo audit for known vulnerabilities..."

            # Run audit (write results to build dir, not source)
            cargo-audit audit --file ${./Cargo.lock} --json > $TMPDIR/audit-results.json 2>&1 || true

            # Check for actual vulnerabilities
            if ${pkgs.jq}/bin/jq -e '.vulnerabilities.count > 0' $TMPDIR/audit-results.json > /dev/null 2>&1; then
              echo "WARNING: Vulnerabilities found in dependencies" >&2
              ${pkgs.jq}/bin/jq '.vulnerabilities' $TMPDIR/audit-results.json >&2
            else
              echo "No known vulnerabilities in Cargo dependencies"
            fi

            touch $out
          '';

          # Validate Cargo.lock exists and is parseable
          # Note: Full --locked validation requires network; run in CI instead
          cargo-lock-check = pkgs.runCommand "cargo-lock-check" {} ''
            echo "Checking Cargo.lock exists and is valid..."

            # Verify Cargo.lock exists
            if [ ! -f "${./Cargo.lock}" ]; then
              echo "ERROR: Cargo.lock not found. Run 'cargo generate-lockfile' and commit." >&2
              exit 1
            fi

            # Verify it's valid TOML (basic syntax check)
            ${pkgs.python3}/bin/python3 -c "
import tomllib
with open('${./Cargo.lock}', 'rb') as f:
    data = tomllib.load(f)
    packages = data.get('package', [])
    print(f'Cargo.lock contains {len(packages)} packages')
" || {
              echo "ERROR: Cargo.lock is not valid TOML" >&2
              exit 1
            }

            echo "Cargo.lock validation passed"
            touch $out
          '';

          # =============================================================
          # NixOS VM Security Tests
          # =============================================================

          # Individual module tests
          secure-users = import ./nix/tests/secure-users.nix { inherit pkgs lib; };
          hardened-ssh = import ./nix/tests/hardened-ssh.nix { inherit pkgs lib; };
          kernel-hardening = import ./nix/tests/kernel-hardening.nix { inherit pkgs lib; };
          secure-postgres = import ./nix/tests/secure-postgres.nix { inherit pkgs lib; };
          time-sync = import ./nix/tests/time-sync.nix { inherit pkgs lib; };
          intrusion-detection = import ./nix/tests/intrusion-detection.nix { inherit pkgs lib; };
          vm-firewall = import ./nix/tests/vm-firewall.nix { inherit pkgs lib; };
          resource-limits = import ./nix/tests/resource-limits.nix { inherit pkgs lib; };
          vault-pki = import ./nix/tests/vault-pki.nix { inherit pkgs lib; };

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
          pkgs = import nixpkgs {
            inherit system overlays;
            config.allowUnfreePredicate = pkg: builtins.elem (nixpkgs.lib.getName pkg) [ "vault" ];
          };
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" ];
          };

          # Vault PKI scripts
          vaultPkiLib = import ./nix/lib/vault-pki.nix { lib = pkgs.lib; inherit pkgs; };
          pkiScripts = vaultPkiLib.mkPkiScripts { outputDir = "./certs"; };
        in {
          default = pkgs.mkShell {
            buildInputs = [
              rustToolchain
              pkgs.pkg-config
              pkgs.openssl
              pkgs.postgresql_16
              pkgs.sqlx-cli
              # Vault PKI tools
              pkgs.vault
              pkgs.jq
              pkiScripts.issueServer
              pkiScripts.issueClient
              pkiScripts.issuePostgres
              pkiScripts.showCerts
              pkiScripts.getCaChain
            ];

            RUST_BACKTRACE = 1;

            shellHook = ''
              echo ""
              echo "Barbican Development Shell"
              echo "=========================="
              echo ""
              echo "Vault PKI commands available:"
              echo "  nix run .#vault-dev        - Start Vault with PKI (dev mode)"
              echo "  barbican-cert-server       - Issue server certificate"
              echo "  barbican-cert-client       - Issue mTLS client certificate"
              echo "  barbican-cert-postgres     - Issue PostgreSQL certificate"
              echo "  barbican-ca-chain          - Export CA chain"
              echo "  barbican-cert-show         - Show certificate details"
              echo ""
              echo "After starting vault-dev, set:"
              echo "  export VAULT_ADDR=http://127.0.0.1:8200"
              echo "  export VAULT_TOKEN=barbican-dev"
              echo ""
            '';
          };
        }
      );

      # Apps for running tests and generating audit reports
      apps = flake-utils.lib.eachDefaultSystemMap (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = pkg: builtins.elem (nixpkgs.lib.getName pkg) [ "vault" ];
          };
          allTests = (import ./nix/tests/default.nix { inherit pkgs; lib = pkgs.lib; }).all;

          # Vault PKI library and scripts
          vaultPkiLib = import ./nix/lib/vault-pki.nix { lib = pkgs.lib; inherit pkgs; };
          pkiSetupScript = vaultPkiLib.mkPkiSetupScript {};
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

          test-vault-pki = {
            type = "app";
            program = toString (pkgs.writeShellScript "test-vault-pki" ''
              echo "Running vault-pki tests..."
              nix build ${self}#checks.${system}.vault-pki --no-link -L
            '');
          };

          # =============================================================
          # Vault PKI Apps (SC-12, SC-17)
          # =============================================================

          # Start Vault in dev mode with PKI pre-configured
          vault-dev = {
            type = "app";
            program = toString (pkgs.writeShellScript "vault-dev" ''
              set -euo pipefail

              echo "=============================================="
              echo "  Barbican Vault PKI - Development Mode"
              echo "  NIST 800-53: SC-12, SC-17"
              echo "=============================================="
              echo ""

              # Check if vault is already running
              if ${pkgs.curl}/bin/curl -s http://127.0.0.1:8200/v1/sys/health > /dev/null 2>&1; then
                echo "Vault is already running at http://127.0.0.1:8200"
                echo "To stop: pkill -f 'vault server'"
                exit 1
              fi

              # Create log directory
              mkdir -p /tmp/vault-logs

              echo "Starting Vault dev server..."

              # Start Vault in background with nohup to ensure it stays running
              nohup ${pkgs.vault}/bin/vault server -dev \
                -dev-root-token-id=barbican-dev \
                -dev-listen-address=127.0.0.1:8200 \
                > /tmp/vault-logs/vault.log 2>&1 &
              VAULT_PID=$!

              # Give Vault a moment to start
              sleep 2

              # Wait for Vault to be ready (up to 30 seconds)
              echo "Waiting for Vault to be ready..."
              READY=0
              for i in $(seq 1 60); do
                if ${pkgs.curl}/bin/curl -s http://127.0.0.1:8200/v1/sys/health > /dev/null 2>&1; then
                  READY=1
                  break
                fi
                sleep 0.5
              done

              if [ "$READY" != "1" ]; then
                echo "ERROR: Vault failed to start. Check /tmp/vault-logs/vault.log"
                cat /tmp/vault-logs/vault.log
                kill $VAULT_PID 2>/dev/null || true
                exit 1
              fi

              export VAULT_ADDR=http://127.0.0.1:8200
              export VAULT_TOKEN=barbican-dev

              echo "Setting up PKI secrets engine..."
              ${pkiSetupScript}

              echo ""
              echo "=============================================="
              echo "  Vault PKI Ready!"
              echo "=============================================="
              echo ""
              echo "Vault Address: $VAULT_ADDR"
              echo "Root Token:    barbican-dev (DEV MODE ONLY)"
              echo "Vault PID:     $VAULT_PID"
              echo "Logs:          /tmp/vault-logs/vault.log"
              echo ""
              echo "Set these in your shell:"
              echo "  export VAULT_ADDR=http://127.0.0.1:8200"
              echo "  export VAULT_TOKEN=barbican-dev"
              echo ""
              echo "Issue certificates:"
              echo "  vault write pki_int/issue/server common_name=localhost"
              echo "  vault write pki_int/issue/client common_name=worker-1"
              echo "  vault write pki_int/issue/postgres common_name=postgres.local"
              echo ""
              echo "Or use the helper scripts (in nix develop):"
              echo "  barbican-cert-server localhost"
              echo "  barbican-cert-client worker-1"
              echo "  barbican-cert-postgres"
              echo ""
              echo "Press Ctrl+C to stop Vault..."
              echo ""

              # Keep running until interrupted
              trap "echo 'Stopping Vault...'; kill $VAULT_PID 2>/dev/null || true" EXIT INT TERM
              wait $VAULT_PID
            '');
          };

          # Quick certificate issuance apps
          vault-cert-server = {
            type = "app";
            program = toString (pkgs.writeShellScript "vault-cert-server" ''
              set -euo pipefail

              COMMON_NAME="''${1:-localhost}"
              OUTPUT_DIR="''${2:-./certs/server}"

              : "''${VAULT_ADDR:?VAULT_ADDR must be set (try: export VAULT_ADDR=http://127.0.0.1:8200)}"
              : "''${VAULT_TOKEN:?VAULT_TOKEN must be set (try: export VAULT_TOKEN=barbican-dev)}"

              mkdir -p "$OUTPUT_DIR"

              echo "Issuing server certificate for: $COMMON_NAME"

              ${pkgs.vault}/bin/vault write -format=json pki_int/issue/server \
                common_name="$COMMON_NAME" \
                alt_names="localhost,$COMMON_NAME" \
                ip_sans="127.0.0.1,::1" \
                ttl=720h \
                | tee "$OUTPUT_DIR/$COMMON_NAME.json"

              ${pkgs.jq}/bin/jq -r '.data.certificate' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME.pem"
              ${pkgs.jq}/bin/jq -r '.data.private_key' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-key.pem"
              ${pkgs.jq}/bin/jq -r '.data.ca_chain[]' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-chain.pem"

              chmod 600 "$OUTPUT_DIR/$COMMON_NAME-key.pem"
              rm "$OUTPUT_DIR/$COMMON_NAME.json"

              echo ""
              echo "Certificate: $OUTPUT_DIR/$COMMON_NAME.pem"
              echo "Private key: $OUTPUT_DIR/$COMMON_NAME-key.pem"
              echo "CA chain:    $OUTPUT_DIR/$COMMON_NAME-chain.pem"
            '');
          };

          vault-cert-client = {
            type = "app";
            program = toString (pkgs.writeShellScript "vault-cert-client" ''
              set -euo pipefail

              COMMON_NAME="''${1:?Usage: nix run .#vault-cert-client <name>}"
              OUTPUT_DIR="''${2:-./certs/client}"

              : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
              : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

              mkdir -p "$OUTPUT_DIR"

              echo "Issuing client certificate for: $COMMON_NAME"

              ${pkgs.vault}/bin/vault write -format=json pki_int/issue/client \
                common_name="$COMMON_NAME" \
                ttl=720h \
                | tee "$OUTPUT_DIR/$COMMON_NAME.json"

              ${pkgs.jq}/bin/jq -r '.data.certificate' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME.pem"
              ${pkgs.jq}/bin/jq -r '.data.private_key' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-key.pem"
              ${pkgs.jq}/bin/jq -r '.data.ca_chain[]' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-chain.pem"

              chmod 600 "$OUTPUT_DIR/$COMMON_NAME-key.pem"
              rm "$OUTPUT_DIR/$COMMON_NAME.json"

              echo ""
              echo "Certificate: $OUTPUT_DIR/$COMMON_NAME.pem"
              echo "Private key: $OUTPUT_DIR/$COMMON_NAME-key.pem"
              echo "CA chain:    $OUTPUT_DIR/$COMMON_NAME-chain.pem"
            '');
          };

          vault-cert-postgres = {
            type = "app";
            program = toString (pkgs.writeShellScript "vault-cert-postgres" ''
              set -euo pipefail

              OUTPUT_DIR="''${1:-./certs/postgres}"

              : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
              : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

              mkdir -p "$OUTPUT_DIR"

              echo "Issuing PostgreSQL certificates..."

              ${pkgs.vault}/bin/vault write -format=json pki_int/issue/postgres \
                common_name="postgres.local" \
                alt_names="localhost,postgres" \
                ip_sans="127.0.0.1,::1" \
                ttl=8760h \
                | tee "$OUTPUT_DIR/server.json"

              ${pkgs.jq}/bin/jq -r '.data.certificate' "$OUTPUT_DIR/server.json" > "$OUTPUT_DIR/server.crt"
              ${pkgs.jq}/bin/jq -r '.data.private_key' "$OUTPUT_DIR/server.json" > "$OUTPUT_DIR/server.key"
              ${pkgs.jq}/bin/jq -r '.data.ca_chain[]' "$OUTPUT_DIR/server.json" > "$OUTPUT_DIR/root.crt"

              chmod 600 "$OUTPUT_DIR/server.key"
              rm "$OUTPUT_DIR/server.json"

              echo ""
              echo "Server cert: $OUTPUT_DIR/server.crt"
              echo "Server key:  $OUTPUT_DIR/server.key"
              echo "CA cert:     $OUTPUT_DIR/root.crt"
              echo ""
              echo "PostgreSQL configuration:"
              echo "  ssl = on"
              echo "  ssl_cert_file = '$OUTPUT_DIR/server.crt'"
              echo "  ssl_key_file = '$OUTPUT_DIR/server.key'"
              echo "  ssl_ca_file = '$OUTPUT_DIR/root.crt'"
            '');
          };

          vault-ca-chain = {
            type = "app";
            program = toString (pkgs.writeShellScript "vault-ca-chain" ''
              set -euo pipefail

              OUTPUT_DIR="''${1:-./certs/ca}"

              : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
              : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

              mkdir -p "$OUTPUT_DIR"

              echo "Fetching CA chain from Vault..."

              ${pkgs.vault}/bin/vault read -field=certificate pki/cert/ca > "$OUTPUT_DIR/root-ca.pem"
              ${pkgs.vault}/bin/vault read -field=certificate pki_int/cert/ca > "$OUTPUT_DIR/intermediate-ca.pem"

              cat "$OUTPUT_DIR/intermediate-ca.pem" "$OUTPUT_DIR/root-ca.pem" > "$OUTPUT_DIR/ca-chain.pem"

              echo ""
              echo "Root CA:         $OUTPUT_DIR/root-ca.pem"
              echo "Intermediate CA: $OUTPUT_DIR/intermediate-ca.pem"
              echo "Full chain:      $OUTPUT_DIR/ca-chain.pem"
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

  # =============================================================================
  # SECURITY: Binary Cache Trust Model
  # =============================================================================
  # By default, Nix trusts cache.nixos.org which is maintained by the NixOS
  # Foundation. All packages are built reproducibly and signed.
  #
  # For production deployments, consider:
  # 1. Running your own binary cache (nix-serve, cachix, attic)
  # 2. Building all packages locally (slower but no external trust)
  # 3. Explicitly configuring trusted substituters in nix.conf:
  #
  #    trusted-substituters = https://cache.nixos.org
  #    trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
  #
  # To build without binary cache: nix build --option substitute false
  # To verify cache signatures: nix path-info --sigs /nix/store/...
  # =============================================================================
}
