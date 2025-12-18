# Barbican Vault PKI Library
# Provides helpers for Vault PKI secrets engine setup and certificate issuance
#
# NIST 800-53 Controls:
# - SC-12: Cryptographic Key Establishment and Management
# - SC-17: Public Key Infrastructure Certificates
# - AU-2/AU-12: Audit logging via Vault audit device
{ lib, pkgs }:

with lib;

rec {
  # Default PKI configuration
  defaultConfig = {
    rootCaTtl = "87600h";        # 10 years
    intermediateCaTtl = "43800h"; # 5 years
    defaultCertTtl = "720h";     # 30 days
    maxCertTtl = "8760h";        # 1 year
    keyType = "ec";
    keyBits = 384;               # P-384 curve for EC
    organization = "Barbican";
  };

  # Default PKI roles
  defaultRoles = {
    server = {
      allowedDomains = [ "localhost" "local" ];
      allowSubdomains = true;
      allowBareDomains = true;
      allowAnyName = false;
      allowIpSans = true;
      serverFlag = true;
      clientFlag = false;
      keyUsage = [ "DigitalSignature" "KeyEncipherment" ];
      extKeyUsage = [ "ServerAuth" ];
      maxTtl = "8760h";  # 1 year
    };
    client = {
      allowedDomains = [];  # Not used when allow_any_name is true
      allowSubdomains = false;
      allowBareDomains = false;
      allowAnyName = true;  # Client certs can have any CN (service identifiers)
      allowIpSans = false;
      serverFlag = false;
      clientFlag = true;
      keyUsage = [ "DigitalSignature" ];
      extKeyUsage = [ "ClientAuth" ];
      maxTtl = "720h";  # 30 days (shorter for client certs)
    };
    postgres = {
      allowedDomains = [ "postgres" "localhost" "local" ];
      allowSubdomains = true;
      allowBareDomains = true;
      allowAnyName = false;
      allowIpSans = true;
      serverFlag = true;
      clientFlag = true;  # PostgreSQL can use same cert for both
      keyUsage = [ "DigitalSignature" "KeyEncipherment" ];
      extKeyUsage = [ "ServerAuth" "ClientAuth" ];
      maxTtl = "8760h";
    };
  };

  # Generate the complete PKI setup script
  # This initializes Vault with root CA, intermediate CA, and roles
  mkPkiSetupScript = {
    config ? defaultConfig,
    roles ? defaultRoles,
    enableAudit ? true
  }:
    pkgs.writeShellScript "vault-pki-setup" ''
      set -euo pipefail

      echo "=== Barbican Vault PKI Setup ==="
      echo "Configuring PKI secrets engine with root and intermediate CA"
      echo ""

      # Ensure VAULT_ADDR and VAULT_TOKEN are set
      : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
      : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

      # Wait for Vault to be ready
      until ${pkgs.vault}/bin/vault status > /dev/null 2>&1; do
        echo "Waiting for Vault to be ready..."
        sleep 1
      done

      ${optionalString enableAudit ''
      # Enable audit logging (AU-2, AU-12)
      if ! ${pkgs.vault}/bin/vault audit list | grep -q "file/"; then
        echo "Enabling file audit device..."
        # Try /var/log/vault first, fall back to /tmp for dev mode
        if ${pkgs.vault}/bin/vault audit enable file file_path=/var/log/vault/audit.log 2>/dev/null; then
          echo "Audit logging enabled at /var/log/vault/audit.log"
        elif ${pkgs.vault}/bin/vault audit enable file file_path=/tmp/vault-audit.log 2>/dev/null; then
          echo "Audit logging enabled at /tmp/vault-audit.log (dev mode fallback)"
        else
          echo "Warning: Could not enable audit device (continuing without audit logging)"
        fi
      fi
      ''}

      # =============================================================
      # Root CA Setup (pki/)
      # =============================================================
      echo "Setting up Root CA..."

      if ! ${pkgs.vault}/bin/vault secrets list | grep -q "^pki/"; then
        ${pkgs.vault}/bin/vault secrets enable -path=pki pki
        ${pkgs.vault}/bin/vault secrets tune -max-lease-ttl=${config.rootCaTtl} pki

        # Generate root CA
        ${pkgs.vault}/bin/vault write -format=json pki/root/generate/internal \
          common_name="${config.organization} Root CA" \
          issuer_name="root-ca" \
          key_type="${config.keyType}" \
          key_bits=${toString config.keyBits} \
          ttl=${config.rootCaTtl} \
          | tee /tmp/root-ca.json

        # Configure CA and CRL URLs
        ${pkgs.vault}/bin/vault write pki/config/urls \
          issuing_certificates="''${VAULT_ADDR}/v1/pki/ca" \
          crl_distribution_points="''${VAULT_ADDR}/v1/pki/crl"

        echo "Root CA created successfully"
      else
        echo "Root CA already exists, skipping..."
      fi

      # =============================================================
      # Intermediate CA Setup (pki_int/)
      # =============================================================
      echo "Setting up Intermediate CA..."

      if ! ${pkgs.vault}/bin/vault secrets list | grep -q "^pki_int/"; then
        ${pkgs.vault}/bin/vault secrets enable -path=pki_int pki
        ${pkgs.vault}/bin/vault secrets tune -max-lease-ttl=${config.intermediateCaTtl} pki_int

        # Generate intermediate CA CSR
        ${pkgs.vault}/bin/vault write -format=json pki_int/intermediate/generate/internal \
          common_name="${config.organization} Intermediate CA" \
          issuer_name="intermediate-ca" \
          key_type="${config.keyType}" \
          key_bits=${toString config.keyBits} \
          | tee /tmp/intermediate-csr.json

        # Extract CSR
        CSR=$(cat /tmp/intermediate-csr.json | ${pkgs.jq}/bin/jq -r '.data.csr')

        # Sign intermediate with root CA
        ${pkgs.vault}/bin/vault write -format=json pki/root/sign-intermediate \
          csr="$CSR" \
          format=pem_bundle \
          ttl=${config.intermediateCaTtl} \
          | tee /tmp/intermediate-signed.json

        # Extract signed certificate
        CERT=$(cat /tmp/intermediate-signed.json | ${pkgs.jq}/bin/jq -r '.data.certificate')

        # Set the signed certificate
        ${pkgs.vault}/bin/vault write pki_int/intermediate/set-signed certificate="$CERT"

        # Configure intermediate CA URLs
        ${pkgs.vault}/bin/vault write pki_int/config/urls \
          issuing_certificates="''${VAULT_ADDR}/v1/pki_int/ca" \
          crl_distribution_points="''${VAULT_ADDR}/v1/pki_int/crl"

        echo "Intermediate CA created and signed successfully"
      else
        echo "Intermediate CA already exists, skipping..."
      fi

      # =============================================================
      # Create PKI Roles
      # =============================================================
      echo "Creating PKI roles..."

      ${concatStringsSep "\n" (mapAttrsToList (name: role: ''
      echo "  Creating role: ${name}"
      ${pkgs.vault}/bin/vault write pki_int/roles/${name} \
        allowed_domains="${concatStringsSep "," role.allowedDomains}" \
        allow_subdomains=${boolToString role.allowSubdomains} \
        allow_bare_domains=${boolToString role.allowBareDomains} \
        allow_any_name=${boolToString (role.allowAnyName or false)} \
        allow_ip_sans=${boolToString role.allowIpSans} \
        server_flag=${boolToString role.serverFlag} \
        client_flag=${boolToString role.clientFlag} \
        key_type="${config.keyType}" \
        key_bits=${toString config.keyBits} \
        key_usage="${concatStringsSep "," role.keyUsage}" \
        ext_key_usage="${concatStringsSep "," role.extKeyUsage}" \
        max_ttl="${role.maxTtl}" \
        ttl="${config.defaultCertTtl}"
      '') roles)}

      echo ""
      echo "=== PKI Setup Complete ==="
      echo "Available roles: ${concatStringsSep ", " (attrNames roles)}"
      echo ""
      echo "Issue certificates with:"
      echo "  vault write pki_int/issue/<role> common_name=<hostname>"
      echo ""
      echo "Get CA chain:"
      echo "  vault read -field=certificate pki_int/cert/ca_chain"
    '';

  # Script to issue a server certificate
  mkIssueServerCertScript = { outputDir ? "./certs" }:
    pkgs.writeShellScriptBin "barbican-cert-server" ''
      set -euo pipefail

      COMMON_NAME="''${1:-localhost}"
      TTL="''${2:-720h}"
      OUTPUT_DIR="${outputDir}/server"

      : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
      : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

      mkdir -p "$OUTPUT_DIR"

      echo "Issuing server certificate for: $COMMON_NAME"

      # Build SANs
      SANS="localhost,127.0.0.1"
      if [ "$COMMON_NAME" != "localhost" ]; then
        SANS="$SANS,$COMMON_NAME"
      fi

      # Issue certificate
      ${pkgs.vault}/bin/vault write -format=json pki_int/issue/server \
        common_name="$COMMON_NAME" \
        alt_names="$SANS" \
        ip_sans="127.0.0.1,::1" \
        ttl="$TTL" \
        | tee "$OUTPUT_DIR/$COMMON_NAME.json"

      # Extract components
      ${pkgs.jq}/bin/jq -r '.data.certificate' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME.pem"
      ${pkgs.jq}/bin/jq -r '.data.private_key' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-key.pem"
      ${pkgs.jq}/bin/jq -r '.data.ca_chain[]' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-chain.pem"

      # Create bundle (cert + chain)
      cat "$OUTPUT_DIR/$COMMON_NAME.pem" "$OUTPUT_DIR/$COMMON_NAME-chain.pem" > "$OUTPUT_DIR/$COMMON_NAME-bundle.pem"

      # Secure permissions
      chmod 600 "$OUTPUT_DIR/$COMMON_NAME-key.pem"
      chmod 644 "$OUTPUT_DIR/$COMMON_NAME.pem" "$OUTPUT_DIR/$COMMON_NAME-chain.pem" "$OUTPUT_DIR/$COMMON_NAME-bundle.pem"

      # Clean up JSON
      rm "$OUTPUT_DIR/$COMMON_NAME.json"

      echo ""
      echo "Server certificate issued:"
      echo "  Certificate: $OUTPUT_DIR/$COMMON_NAME.pem"
      echo "  Private key: $OUTPUT_DIR/$COMMON_NAME-key.pem"
      echo "  CA chain:    $OUTPUT_DIR/$COMMON_NAME-chain.pem"
      echo "  Bundle:      $OUTPUT_DIR/$COMMON_NAME-bundle.pem"
      echo ""
      echo "Expires: $(${pkgs.openssl}/bin/openssl x509 -in "$OUTPUT_DIR/$COMMON_NAME.pem" -noout -enddate)"
    '';

  # Script to issue a client certificate (mTLS)
  mkIssueClientCertScript = { outputDir ? "./certs" }:
    pkgs.writeShellScriptBin "barbican-cert-client" ''
      set -euo pipefail

      COMMON_NAME="''${1:?Usage: barbican-cert-client <name>}"
      TTL="''${2:-720h}"
      OUTPUT_DIR="${outputDir}/client"

      : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
      : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

      mkdir -p "$OUTPUT_DIR"

      echo "Issuing client certificate for: $COMMON_NAME"

      # Issue certificate
      ${pkgs.vault}/bin/vault write -format=json pki_int/issue/client \
        common_name="$COMMON_NAME" \
        ttl="$TTL" \
        | tee "$OUTPUT_DIR/$COMMON_NAME.json"

      # Extract components
      ${pkgs.jq}/bin/jq -r '.data.certificate' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME.pem"
      ${pkgs.jq}/bin/jq -r '.data.private_key' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-key.pem"
      ${pkgs.jq}/bin/jq -r '.data.ca_chain[]' "$OUTPUT_DIR/$COMMON_NAME.json" > "$OUTPUT_DIR/$COMMON_NAME-chain.pem"

      # Secure permissions
      chmod 600 "$OUTPUT_DIR/$COMMON_NAME-key.pem"
      chmod 644 "$OUTPUT_DIR/$COMMON_NAME.pem" "$OUTPUT_DIR/$COMMON_NAME-chain.pem"

      # Clean up JSON
      rm "$OUTPUT_DIR/$COMMON_NAME.json"

      echo ""
      echo "Client certificate issued:"
      echo "  Certificate: $OUTPUT_DIR/$COMMON_NAME.pem"
      echo "  Private key: $OUTPUT_DIR/$COMMON_NAME-key.pem"
      echo "  CA chain:    $OUTPUT_DIR/$COMMON_NAME-chain.pem"
      echo ""
      echo "Expires: $(${pkgs.openssl}/bin/openssl x509 -in "$OUTPUT_DIR/$COMMON_NAME.pem" -noout -enddate)"
    '';

  # Script to issue PostgreSQL certificate
  mkIssuePostgresCertScript = { outputDir ? "./certs" }:
    pkgs.writeShellScriptBin "barbican-cert-postgres" ''
      set -euo pipefail

      COMMON_NAME="''${1:-postgres.local}"
      TTL="''${2:-8760h}"
      OUTPUT_DIR="${outputDir}/postgres"

      : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
      : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

      mkdir -p "$OUTPUT_DIR"

      echo "Issuing PostgreSQL certificate for: $COMMON_NAME"

      # Issue certificate
      ${pkgs.vault}/bin/vault write -format=json pki_int/issue/postgres \
        common_name="$COMMON_NAME" \
        alt_names="localhost,postgres" \
        ip_sans="127.0.0.1,::1" \
        ttl="$TTL" \
        | tee "$OUTPUT_DIR/server.json"

      # Extract components
      ${pkgs.jq}/bin/jq -r '.data.certificate' "$OUTPUT_DIR/server.json" > "$OUTPUT_DIR/server.crt"
      ${pkgs.jq}/bin/jq -r '.data.private_key' "$OUTPUT_DIR/server.json" > "$OUTPUT_DIR/server.key"
      ${pkgs.jq}/bin/jq -r '.data.ca_chain[]' "$OUTPUT_DIR/server.json" > "$OUTPUT_DIR/root.crt"

      # Secure permissions (PostgreSQL is strict about key permissions)
      chmod 600 "$OUTPUT_DIR/server.key"
      chmod 644 "$OUTPUT_DIR/server.crt" "$OUTPUT_DIR/root.crt"

      # Clean up JSON
      rm "$OUTPUT_DIR/server.json"

      echo ""
      echo "PostgreSQL certificates issued:"
      echo "  Server cert: $OUTPUT_DIR/server.crt"
      echo "  Server key:  $OUTPUT_DIR/server.key"
      echo "  CA cert:     $OUTPUT_DIR/root.crt"
      echo ""
      echo "PostgreSQL configuration:"
      echo "  ssl = on"
      echo "  ssl_cert_file = '$OUTPUT_DIR/server.crt'"
      echo "  ssl_key_file = '$OUTPUT_DIR/server.key'"
      echo "  ssl_ca_file = '$OUTPUT_DIR/root.crt'  # For client cert verification"
      echo ""
      echo "pg_hba.conf for mTLS:"
      echo "  hostssl all all 0.0.0.0/0 cert clientcert=verify-ca"
      echo ""
      echo "Expires: $(${pkgs.openssl}/bin/openssl x509 -in "$OUTPUT_DIR/server.crt" -noout -enddate)"
    '';

  # Script to display certificate info
  mkShowCertsScript = { outputDir ? "./certs" }:
    pkgs.writeShellScriptBin "barbican-cert-show" ''
      set -euo pipefail

      CERT_PATH="''${1:-}"
      OUTPUT_DIR="${outputDir}"

      show_cert() {
        local cert="$1"
        if [ -f "$cert" ]; then
          echo "=== $cert ==="
          ${pkgs.openssl}/bin/openssl x509 -in "$cert" -noout \
            -subject -issuer -dates -ext subjectAltName 2>/dev/null || true
          echo ""
        fi
      }

      if [ -n "$CERT_PATH" ]; then
        show_cert "$CERT_PATH"
      else
        echo "Certificates in $OUTPUT_DIR:"
        echo ""
        find "$OUTPUT_DIR" -name "*.pem" -o -name "*.crt" 2>/dev/null | while read -r cert; do
          show_cert "$cert"
        done
      fi
    '';

  # Script to get CA chain
  mkGetCaChainScript = { outputDir ? "./certs" }:
    pkgs.writeShellScriptBin "barbican-ca-chain" ''
      set -euo pipefail

      OUTPUT_DIR="${outputDir}/ca"

      : "''${VAULT_ADDR:?VAULT_ADDR must be set}"
      : "''${VAULT_TOKEN:?VAULT_TOKEN must be set}"

      mkdir -p "$OUTPUT_DIR"

      echo "Fetching CA chain from Vault..."

      # Get root CA
      ${pkgs.vault}/bin/vault read -field=certificate pki/cert/ca > "$OUTPUT_DIR/root-ca.pem"

      # Get intermediate CA
      ${pkgs.vault}/bin/vault read -field=certificate pki_int/cert/ca > "$OUTPUT_DIR/intermediate-ca.pem"

      # Create full chain (intermediate + root, order matters)
      cat "$OUTPUT_DIR/intermediate-ca.pem" "$OUTPUT_DIR/root-ca.pem" > "$OUTPUT_DIR/ca-chain.pem"

      chmod 644 "$OUTPUT_DIR"/*.pem

      echo ""
      echo "CA certificates saved:"
      echo "  Root CA:         $OUTPUT_DIR/root-ca.pem"
      echo "  Intermediate CA: $OUTPUT_DIR/intermediate-ca.pem"
      echo "  Full chain:      $OUTPUT_DIR/ca-chain.pem"
      echo ""
      echo "Use ca-chain.pem for client trust stores"
    '';

  # Collect all scripts into a set
  mkPkiScripts = { outputDir ? "./certs" }: {
    issueServer = mkIssueServerCertScript { inherit outputDir; };
    issueClient = mkIssueClientCertScript { inherit outputDir; };
    issuePostgres = mkIssuePostgresCertScript { inherit outputDir; };
    showCerts = mkShowCertsScript { inherit outputDir; };
    getCaChain = mkGetCaChainScript { inherit outputDir; };
  };
}
