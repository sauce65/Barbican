# Barbican Keycloak VM Module
#
# Deploys a FedRAMP-compliant, FAPI 2.0-compliant Keycloak instance.
# Designed for immutable infrastructure with Vault-based secret injection.
#
# Features:
#   - Native NixOS Keycloak service (not containerized)
#   - FAPI 2.0 Security Profile with MTLS
#   - TLS certificates from Vault PKI
#   - Declarative realm configuration baked into image
#   - Secrets injected from Vault at boot
#   - FedRAMP audit logging
#
# NIST 800-53 Controls:
#   - IA-2: Identification and Authentication
#   - IA-2(1): Multi-Factor Authentication
#   - IA-5: Authenticator Management
#   - AC-2: Account Management
#   - AC-7: Unsuccessful Logon Attempts
#   - AU-2, AU-3: Audit Events
#   - SC-8: Transmission Confidentiality (TLS)
#   - SC-13: Cryptographic Protection
#
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.keycloak;

  # Import libraries
  fapiLib = import ../lib/keycloak-fapi.nix { inherit lib; };
  realmLib = import ../lib/keycloak-realm-json.nix { inherit lib; };

  # Generate realm JSON from configuration
  realmJsons = mapAttrs (realmName: realmCfg:
    realmLib.mkRealmJson ({
      name = realmName;
      profile = cfg.profile;
    } // realmCfg)
  ) cfg.realms;

  # Write realm JSON files
  realmFiles = mapAttrs (realmName: realmJson:
    pkgs.writeText "${realmName}-realm.json" (builtins.toJSON realmJson)
  ) realmJsons;

  # Combined realm import directory
  realmImportDir = pkgs.runCommand "keycloak-realms" {} ''
    mkdir -p $out
    ${concatStringsSep "\n" (mapAttrsToList (name: file: ''
      cp ${file} $out/${name}-realm.json
    '') realmFiles)}
  '';

  # Helper to safely convert nullable paths/strings to shell-safe values
  toShellPath = v: if v == null then "" else toString v;
  toShellStr = v: if v == null then "" else v;

  # Vault secret injection script
  vaultInjectScript = pkgs.writeShellScript "keycloak-vault-inject" ''
    set -euo pipefail

    REALM_DIR="/var/lib/keycloak/realms"
    VAULT_ADDR="${cfg.vault.address}"

    # Get Vault token (from file or AppRole)
    TOKEN_FILE="${toShellPath cfg.vault.tokenFile}"
    ROLE_ID="${toShellStr cfg.vault.roleId}"
    SECRET_ID_FILE="${toShellPath cfg.vault.secretIdFile}"

    if [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
      VAULT_TOKEN=$(cat "$TOKEN_FILE")
    elif [ -n "$ROLE_ID" ]; then
      # AppRole authentication
      SECRET_ID=$(cat "$SECRET_ID_FILE")
      VAULT_TOKEN=$(${pkgs.curl}/bin/curl -sf -X POST \
        "$VAULT_ADDR/v1/auth/approle/login" \
        -d "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}" \
        | ${pkgs.jq}/bin/jq -r '.auth.client_token')
    else
      echo "ERROR: No Vault authentication method configured"
      exit 1
    fi

    export VAULT_TOKEN

    # Copy realm files to writable location
    mkdir -p "$REALM_DIR"
    cp -r ${realmImportDir}/* "$REALM_DIR/"
    chmod -R u+w "$REALM_DIR"

    # Inject secrets into each realm file
    for realm_file in "$REALM_DIR"/*.json; do
      echo "Processing $realm_file..."

      # Find and replace VAULT: placeholders
      while IFS= read -r placeholder; do
        secret_path="''${placeholder#VAULT:}"
        echo "  Fetching: $secret_path"

        secret_value=$(${pkgs.curl}/bin/curl -sf \
          -H "X-Vault-Token: $VAULT_TOKEN" \
          "$VAULT_ADDR/v1/$secret_path" \
          | ${pkgs.jq}/bin/jq -r '.data.data.value // .data.value // empty')

        if [ -n "$secret_value" ]; then
          # Escape for sed
          escaped_value=$(printf '%s\n' "$secret_value" | sed 's/[&/\]/\\&/g')
          ${pkgs.gnused}/bin/sed -i "s|VAULT:$secret_path|$escaped_value|g" "$realm_file"
        else
          echo "  WARNING: Could not fetch $secret_path"
        fi
      done < <(${pkgs.gnugrep}/bin/grep -oh 'VAULT:[a-zA-Z0-9/_-]*' "$realm_file" 2>/dev/null | sort -u || true)
    done

    echo "Vault secret injection complete"
  '';

  # TLS certificate fetch script (from Vault PKI)
  tlsCertScript = pkgs.writeShellScript "keycloak-tls-certs" ''
    set -euo pipefail

    CERT_DIR="/var/lib/keycloak/certs"
    VAULT_ADDR="${cfg.vault.address}"

    mkdir -p "$CERT_DIR"

    # Get Vault token
    TOKEN_FILE="${toShellPath cfg.vault.tokenFile}"
    if [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
      VAULT_TOKEN=$(cat "$TOKEN_FILE")
    else
      echo "ERROR: Vault token not available"
      exit 1
    fi

    # Request certificate from Vault PKI
    CERT_RESPONSE=$(${pkgs.curl}/bin/curl -sf -X POST \
      -H "X-Vault-Token: $VAULT_TOKEN" \
      "$VAULT_ADDR/v1/${cfg.tls.vaultPkiPath}" \
      -d '{
        "common_name": "${cfg.hostname}",
        "alt_names": "${concatStringsSep "," cfg.tls.altNames}",
        "ttl": "${cfg.tls.certTtl}",
        "format": "pem"
      }')

    # Extract and save certificates
    echo "$CERT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.certificate' > "$CERT_DIR/server.crt"
    echo "$CERT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.private_key' > "$CERT_DIR/server.key"
    echo "$CERT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.ca_chain[]' > "$CERT_DIR/ca-chain.crt"

    # Set permissions
    chmod 600 "$CERT_DIR/server.key"
    chmod 644 "$CERT_DIR/server.crt" "$CERT_DIR/ca-chain.crt"
    chown -R keycloak:keycloak "$CERT_DIR"

    ${optionalString cfg.tls.mtls.enable ''
      # Create truststore for client certificates
      TRUSTSTORE="$CERT_DIR/truststore.p12"
      rm -f "$TRUSTSTORE"

      # Import CA certificates for client verification
      ${pkgs.openssl}/bin/openssl pkcs12 -export \
        -in "$CERT_DIR/ca-chain.crt" \
        -nokeys \
        -out "$TRUSTSTORE" \
        -passout pass:${cfg.tls.mtls.truststorePassword}

      chmod 600 "$TRUSTSTORE"
      chown keycloak:keycloak "$TRUSTSTORE"
    ''}

    echo "TLS certificates configured"
  '';

in {
  options.barbican.keycloak = {
    enable = mkEnableOption "Barbican Keycloak OIDC Provider";

    profile = mkOption {
      type = types.enum [ "development" "fedramp-low" "fedramp-moderate" "fedramp-high" ];
      default = "fedramp-moderate";
      description = "Security profile (determines FAPI 2.0 strictness)";
    };

    version = mkOption {
      type = types.str;
      default = "26.0.0";
      description = "Keycloak version";
    };

    hostname = mkOption {
      type = types.str;
      default = "keycloak.local";
      description = "Keycloak hostname";
    };

    httpPort = mkOption {
      type = types.port;
      default = 8080;
      description = "HTTP port (used in development only)";
    };

    httpsPort = mkOption {
      type = types.port;
      default = 8443;
      description = "HTTPS port";
    };

    # Database configuration
    database = {
      type = mkOption {
        type = types.enum [ "postgres" "mariadb" ];
        default = "postgres";
        description = "Database type";
      };

      host = mkOption {
        type = types.str;
        default = "localhost";
        description = "Database host";
      };

      port = mkOption {
        type = types.port;
        default = 5432;
        description = "Database port";
      };

      name = mkOption {
        type = types.str;
        default = "keycloak";
        description = "Database name";
      };

      user = mkOption {
        type = types.str;
        default = "keycloak";
        description = "Database user";
      };

      passwordFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to file containing database password";
      };

      passwordFromVault = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Vault path for database password";
        example = "secret/keycloak/database";
      };
    };

    # Admin configuration
    admin = {
      user = mkOption {
        type = types.str;
        default = "admin";
        description = "Admin username";
      };

      passwordFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to file containing admin password";
      };

      passwordFromVault = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Vault path for admin password";
        example = "secret/keycloak/admin";
      };
    };

    # TLS configuration
    tls = {
      enable = mkOption {
        type = types.bool;
        default = cfg.profile != "development";
        description = "Enable TLS";
      };

      vaultPkiPath = mkOption {
        type = types.str;
        default = "pki/issue/keycloak";
        description = "Vault PKI path for certificate issuance";
      };

      altNames = mkOption {
        type = types.listOf types.str;
        default = [ "localhost" "keycloak" ];
        description = "Subject Alternative Names for TLS certificate";
      };

      certTtl = mkOption {
        type = types.str;
        default = "720h";
        description = "Certificate TTL";
      };

      mtls = {
        enable = mkOption {
          type = types.bool;
          default = cfg.profile == "fedramp-moderate" || cfg.profile == "fedramp-high";
          description = "Enable MTLS for client authentication";
        };

        truststorePassword = mkOption {
          type = types.str;
          default = "changeit";
          description = "Truststore password (should come from Vault in production)";
        };

        clientAuth = mkOption {
          type = types.enum [ "none" "request" "required" ];
          default = "request";
          description = "Client certificate authentication mode";
        };
      };
    };

    # Vault integration
    vault = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Vault integration for secrets";
      };

      address = mkOption {
        type = types.str;
        default = "http://vault:8200";
        description = "Vault server address";
      };

      tokenFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to Vault token file";
      };

      roleId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Vault AppRole role ID";
      };

      secretIdFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to Vault AppRole secret ID file";
      };
    };

    # Realm configuration (app-specific data)
    realms = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          displayName = mkOption {
            type = types.str;
            default = "";
            description = "Human-readable realm name";
          };

          roles = mkOption {
            type = types.attrsOf (types.submodule {
              options = {
                description = mkOption {
                  type = types.str;
                  default = "";
                };
                composite = mkOption {
                  type = types.bool;
                  default = false;
                };
                compositeRoles = mkOption {
                  type = types.listOf types.str;
                  default = [];
                };
              };
            });
            default = {};
            description = "Realm roles";
          };

          clients = mkOption {
            type = types.attrsOf (types.submodule {
              options = {
                name = mkOption {
                  type = types.str;
                  description = "Client display name";
                };
                secret = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = "Client secret (use secretFromVault in production)";
                };
                secretFromVault = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = "Vault path for client secret";
                };
                public = mkOption {
                  type = types.bool;
                  default = false;
                };
                redirectUris = mkOption {
                  type = types.listOf types.str;
                  default = [];
                };
                webOrigins = mkOption {
                  type = types.listOf types.str;
                  default = [];
                };
                directAccessGrantsEnabled = mkOption {
                  type = types.bool;
                  default = false;
                };
                serviceAccountsEnabled = mkOption {
                  type = types.bool;
                  default = false;
                };
                mtls = mkOption {
                  type = types.bool;
                  default = cfg.tls.mtls.enable;
                  description = "Enable MTLS for this client";
                };
                fapi = mkOption {
                  type = types.bool;
                  default = cfg.profile != "development";
                  description = "Enable FAPI 2.0 compliance for this client";
                };
              };
            });
            default = {};
            description = "OIDC clients";
          };

          users = mkOption {
            type = types.attrsOf (types.submodule {
              options = {
                email = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                };
                firstName = mkOption {
                  type = types.str;
                  default = "";
                };
                lastName = mkOption {
                  type = types.str;
                  default = "";
                };
                password = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = "Password (development only)";
                };
                passwordFromVault = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = "Vault path for password";
                };
                roles = mkOption {
                  type = types.listOf types.str;
                  default = [ "user" ];
                };
                enabled = mkOption {
                  type = types.bool;
                  default = true;
                };
              };
            });
            default = {};
            description = "Users (typically only for development/test)";
          };

          accessTokenLifespan = mkOption {
            type = types.int;
            default = 300;
            description = "Access token lifespan in seconds";
          };

          refreshTokenLifespan = mkOption {
            type = types.int;
            default = 1800;
            description = "Refresh token lifespan in seconds";
          };
        };
      });
      default = {};
      description = "Realm configurations";
    };

    # JVM options
    jvmOptions = mkOption {
      type = types.listOf types.str;
      default = [
        "-Xms512m"
        "-Xmx2048m"
        "-XX:+UseG1GC"
        "-Djava.security.egd=file:/dev/urandom"
      ];
      description = "JVM options for Keycloak";
    };
  };

  config = mkIf cfg.enable {
    # Use NixOS native Keycloak service
    services.keycloak = {
      enable = true;

      settings = {
        hostname = cfg.hostname;
        http-port = cfg.httpPort;
        https-port = cfg.httpsPort;

        # Production mode unless development
        http-enabled = cfg.profile == "development";
        hostname-strict = cfg.profile != "development";
        hostname-strict-https = cfg.tls.enable;

        # Database
        db = cfg.database.type;
        db-url-host = cfg.database.host;
        db-url-port = toString cfg.database.port;
        db-url-database = cfg.database.name;
        db-username = cfg.database.user;

        # TLS
        https-certificate-file = mkIf cfg.tls.enable "/var/lib/keycloak/certs/server.crt";
        https-certificate-key-file = mkIf cfg.tls.enable "/var/lib/keycloak/certs/server.key";

        # MTLS
        https-client-auth = mkIf cfg.tls.mtls.enable cfg.tls.mtls.clientAuth;
        https-trust-store-file = mkIf cfg.tls.mtls.enable "/var/lib/keycloak/certs/truststore.p12";
        https-trust-store-password = mkIf cfg.tls.mtls.enable cfg.tls.mtls.truststorePassword;

        # Features
        features = "token-exchange,admin-fine-grained-authz,dpop";

        # Health and metrics
        health-enabled = true;
        metrics-enabled = true;

        # Logging (AU-2, AU-3)
        log-level = if cfg.profile == "development" then "INFO" else "INFO";
        log-format = "json";
      };

      # Database password
      database.passwordFile = cfg.database.passwordFile;

      # Initial admin (only used on first boot)
      initialAdminPassword = mkIf (cfg.admin.passwordFile == null) "admin";
    };

    # Systemd overrides for Vault integration
    systemd.services.keycloak = {
      wants = [ "network-online.target" ];
      after = [ "network-online.target" "vault-agent.service" ];

      preStart = mkIf cfg.vault.enable ''
        # Inject secrets from Vault
        ${vaultInjectScript}

        # Fetch TLS certificates
        ${optionalString cfg.tls.enable tlsCertScript}
      '';

      environment = {
        JAVA_OPTS = concatStringsSep " " cfg.jvmOptions;
        KC_DIR = "/var/lib/keycloak/realms";
      };
    };

    # Firewall
    networking.firewall.allowedTCPPorts =
      (optional (cfg.profile == "development") cfg.httpPort)
      ++ (optional cfg.tls.enable cfg.httpsPort);

    # Required packages
    environment.systemPackages = with pkgs; [
      curl
      jq
      openssl
    ];

    # Assertions
    assertions = [
      {
        assertion = cfg.profile == "development" || cfg.tls.enable;
        message = "TLS must be enabled for non-development profiles";
      }
      {
        assertion = cfg.vault.enable -> (cfg.vault.tokenFile != null || cfg.vault.roleId != null);
        message = "Vault integration requires either tokenFile or roleId";
      }
      {
        assertion = cfg.database.passwordFile != null || cfg.database.passwordFromVault != null || cfg.profile == "development";
        message = "Database password must be configured for non-development profiles";
      }
    ];
  };
}
