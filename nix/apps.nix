# Barbican Apps
#
# Provides runnable applications:
# - Security audit runner
# - Individual test runners
# - Vault PKI tools
# - Observability stack generator
{ pkgs, self, system, observabilityStackGenerator }:

let
  allTests = (import ./tests/default.nix { inherit pkgs; lib = pkgs.lib; }).all;

  # Vault PKI library and scripts
  vaultPkiLib = import ./lib/vault-pki.nix { lib = pkgs.lib; inherit pkgs; };
  pkiSetupScript = vaultPkiLib.mkPkiSetupScript { };

  # Helper to create a test runner app
  mkTestApp = name: {
    type = "app";
    program = toString (pkgs.writeShellScript "test-${name}" ''
      echo "Running ${name} tests..."
      nix build ${self}#checks.${system}.${name} --no-link -L
    '');
  };

in
{
  # =============================================================
  # Security Audit
  # =============================================================

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

  # =============================================================
  # Individual Test Runners
  # =============================================================

  test-secure-users = mkTestApp "secure-users";
  test-hardened-ssh = mkTestApp "hardened-ssh";
  test-kernel-hardening = mkTestApp "kernel-hardening";
  test-secure-postgres = mkTestApp "secure-postgres";
  test-time-sync = mkTestApp "time-sync";
  test-intrusion-detection = mkTestApp "intrusion-detection";
  test-vm-firewall = mkTestApp "vm-firewall";
  test-resource-limits = mkTestApp "resource-limits";
  test-vault-pki = mkTestApp "vault-pki";

  # =============================================================
  # Vault PKI Apps (SC-12, SC-17)
  # =============================================================

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

      # Start Vault in background
      nohup ${pkgs.vault}/bin/vault server -dev \
        -dev-root-token-id=barbican-dev \
        -dev-listen-address=127.0.0.1:8200 \
        > /tmp/vault-logs/vault.log 2>&1 &
      VAULT_PID=$!

      sleep 2

      # Wait for Vault to be ready
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

      trap "echo 'Stopping Vault...'; kill $VAULT_PID 2>/dev/null || true" EXIT INT TERM
      wait $VAULT_PID
    '');
  };

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

  # =============================================================
  # Observability Stack Generator (AU-2, AU-6, CA-7)
  # =============================================================

  observability-stack = {
    type = "app";
    program = toString (pkgs.writeShellScript "observability-stack" ''
      exec ${observabilityStackGenerator}/bin/generate_observability_stack "$@"
    '');
  };

  observability-init = {
    type = "app";
    program = toString (pkgs.writeShellScript "observability-init" ''
      set -euo pipefail

      echo "=============================================="
      echo "  Barbican Observability Stack Initializer"
      echo "  FedRAMP-Compliant Infrastructure Generator"
      echo "=============================================="
      echo ""

      # Get app name
      if [ -n "''${1:-}" ]; then
        APP_NAME="$1"
      else
        read -rp "Application name: " APP_NAME
      fi

      # Get app port
      if [ -n "''${2:-}" ]; then
        APP_PORT="$2"
      else
        read -rp "Metrics port [3000]: " APP_PORT
        APP_PORT="''${APP_PORT:-3000}"
      fi

      # Get output directory
      if [ -n "''${3:-}" ]; then
        OUTPUT_DIR="$3"
      else
        read -rp "Output directory [./observability]: " OUTPUT_DIR
        OUTPUT_DIR="''${OUTPUT_DIR:-./observability}"
      fi

      # Get compliance profile
      echo ""
      echo "Compliance profiles:"
      echo "  1) fedramp-low      - Basic security controls"
      echo "  2) fedramp-moderate - Standard FedRAMP (default)"
      echo "  3) fedramp-high     - Maximum security"
      echo "  4) soc2             - SOC 2 Type II"
      echo ""
      read -rp "Select profile [2]: " PROFILE_NUM
      PROFILE_NUM="''${PROFILE_NUM:-2}"

      case "$PROFILE_NUM" in
        1) PROFILE="fedramp-low" ;;
        3) PROFILE="fedramp-high" ;;
        4) PROFILE="soc2" ;;
        *) PROFILE="fedramp-moderate" ;;
      esac

      echo ""
      echo "Generating observability stack..."
      echo ""

      # Run the generator
      nix run ${self}#observability-stack -- \
        --app-name "$APP_NAME" \
        --app-port "$APP_PORT" \
        --output "$OUTPUT_DIR" \
        --profile "$PROFILE"
    '');
  };
}
