# Barbican Security Module: Vault PKI Service
#
# Provides HashiCorp Vault with PKI secrets engine for certificate management.
# Supports both development (dev mode) and production (HA) deployments.
#
# NIST 800-53 Controls:
# - SC-12: Cryptographic Key Establishment and Management
# - SC-12(1): Availability (via HA mode)
# - SC-17: Public Key Infrastructure Certificates
# - AU-2, AU-12: Audit logging via Vault audit device
# - IA-5(2): PKI-based authentication
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.vault;

  # Import the PKI library
  vaultPki = import ../lib/vault-pki.nix { inherit lib pkgs; };

  # Build the PKI setup script based on config
  pkiSetupScript = vaultPki.mkPkiSetupScript {
    config = {
      rootCaTtl = cfg.pki.rootCaTtl;
      intermediateCaTtl = cfg.pki.intermediateCaTtl;
      defaultCertTtl = cfg.pki.defaultCertTtl;
      maxCertTtl = cfg.pki.maxCertTtl;
      keyType = cfg.pki.keyType;
      keyBits = cfg.pki.keyBits;
      organization = cfg.pki.organization;
    };
    roles = cfg.pki.roles;
    enableAudit = cfg.audit.enable;
  };

  # Role submodule type
  roleType = types.submodule {
    options = {
      allowedDomains = mkOption {
        type = types.listOf types.str;
        default = [ "localhost" "local" ];
        description = "Domains allowed for this role";
      };

      allowSubdomains = mkOption {
        type = types.bool;
        default = true;
        description = "Allow subdomains of allowed_domains";
      };

      allowBareDomains = mkOption {
        type = types.bool;
        default = true;
        description = "Allow bare domain names (no subdomain)";
      };

      allowAnyName = mkOption {
        type = types.bool;
        default = false;
        description = "Allow any common name (useful for client certs)";
      };

      allowIpSans = mkOption {
        type = types.bool;
        default = true;
        description = "Allow IP SANs in certificates";
      };

      enforceHostnames = mkOption {
        type = types.bool;
        default = true;
        description = "Enforce valid hostnames in CN (disable for usernames like dpe_user)";
      };

      serverFlag = mkOption {
        type = types.bool;
        default = false;
        description = "Mark certificates for server authentication";
      };

      clientFlag = mkOption {
        type = types.bool;
        default = false;
        description = "Mark certificates for client authentication";
      };

      keyUsage = mkOption {
        type = types.listOf types.str;
        default = [ "DigitalSignature" ];
        description = "Key usage flags";
      };

      extKeyUsage = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Extended key usage flags";
      };

      maxTtl = mkOption {
        type = types.str;
        default = "8760h";
        description = "Maximum TTL for certificates";
      };
    };
  };

in {
  options.barbican.vault = {
    enable = mkEnableOption "Barbican Vault PKI service";

    mode = mkOption {
      type = types.enum [ "dev" "production" ];
      default = "dev";
      description = ''
        Deployment mode:
        - dev: Single-node, unsealed, in-memory storage (for development)
        - production: Persistent storage, requires manual unseal or auto-unseal
      '';
    };

    address = mkOption {
      type = types.str;
      default = "0.0.0.0:8200";
      description = ''
        Address for Vault to listen on.
        Defaults to 0.0.0.0:8200 to support VM/container port forwarding.
        In production with proper network segmentation, consider 127.0.0.1:8200.
      '';
    };

    apiAddr = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8200";
      description = "Full URL for Vault API (used for CA URLs in certificates)";
    };

    # PKI Configuration
    pki = {
      rootCaTtl = mkOption {
        type = types.str;
        default = "87600h";  # 10 years
        description = "TTL for root CA certificate";
      };

      intermediateCaTtl = mkOption {
        type = types.str;
        default = "43800h";  # 5 years
        description = "TTL for intermediate CA certificate";
      };

      defaultCertTtl = mkOption {
        type = types.str;
        default = "720h";  # 30 days
        description = "Default TTL for issued certificates";
      };

      maxCertTtl = mkOption {
        type = types.str;
        default = "8760h";  # 1 year
        description = "Maximum TTL for issued certificates";
      };

      keyType = mkOption {
        type = types.enum [ "ec" "rsa" ];
        default = "ec";
        description = "Key type for generated keys";
      };

      keyBits = mkOption {
        type = types.int;
        default = 384;  # P-384 curve for EC
        description = "Key size (384 for EC P-384, 4096 for RSA)";
      };

      organization = mkOption {
        type = types.str;
        default = "Barbican";
        description = "Organization name in CA certificates";
      };

      roles = mkOption {
        type = types.attrsOf roleType;
        default = vaultPki.defaultRoles;
        description = "PKI roles for certificate issuance";
      };
    };

    # Audit Configuration
    audit = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Vault audit logging (AU-2, AU-12)";
      };

      logPath = mkOption {
        type = types.path;
        default = "/var/log/vault/audit.log";
        description = "Path for audit log file";
      };
    };

    # Production HA Configuration
    ha = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable High Availability mode";
      };

      backend = mkOption {
        type = types.enum [ "raft" "consul" ];
        default = "raft";
        description = "HA storage backend";
      };

      nodeId = mkOption {
        type = types.str;
        default = config.networking.hostName;
        description = "Unique node ID for this Vault instance";
      };

      clusterAddr = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Address for cluster communication (required for HA)";
        example = "https://vault1.internal:8201";
      };

      retryJoin = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "List of Vault nodes to join for Raft cluster";
        example = [ "vault1.internal:8201" "vault2.internal:8201" ];
      };
    };

    # Auto-unseal Configuration
    autoUnseal = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable auto-unseal (required for production)";
      };

      type = mkOption {
        type = types.enum [ "awskms" "gcpkms" "azurekeyvault" "transit" ];
        default = "awskms";
        description = "Auto-unseal provider type";
      };

      # AWS KMS options
      awsKmsKeyId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "AWS KMS key ID for auto-unseal";
      };

      awsRegion = mkOption {
        type = types.str;
        default = "us-east-1";
        description = "AWS region for KMS";
      };
    };

    # Storage path for production mode
    storagePath = mkOption {
      type = types.path;
      default = "/var/lib/vault";
      description = "Data storage path for production mode";
    };

    # Client mode - connect to external Vault instead of running local server
    client = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable Vault PKI client mode (connect to external Vault)";
      };

      address = mkOption {
        type = types.str;
        default = "http://10.0.2.2:18200";
        description = "Address of external Vault server";
        example = "http://10.0.2.2:18200";
      };

      tokenFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to file containing Vault token";
        example = "/run/secrets/vault-token";
      };

      caChain = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Fetch CA chain from external Vault";
        };

        outputDir = mkOption {
          type = types.path;
          default = "/var/lib/vault/certs/ca";
          description = "Directory to write CA files";
        };
      };

      # Certificate submodule type for client mode
      certificates = mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            role = mkOption {
              type = types.str;
              description = "PKI role to use for certificate issuance";
              example = "postgres";
            };

            commonName = mkOption {
              type = types.str;
              description = "Common name for the certificate";
              example = "localhost";
            };

            altNames = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Subject Alternative Names";
              example = [ "localhost" "postgres" ];
            };

            ipSans = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "IP SANs";
              example = [ "127.0.0.1" "::1" ];
            };

            outputDir = mkOption {
              type = types.path;
              description = "Directory to write certificate files";
              example = "/var/lib/postgres/certs";
            };

            certFile = mkOption {
              type = types.str;
              default = "server.crt";
              description = "Certificate file name";
            };

            keyFile = mkOption {
              type = types.str;
              default = "server.key";
              description = "Private key file name";
            };

            owner = mkOption {
              type = types.str;
              default = "root";
              description = "Owner of certificate files";
            };

            group = mkOption {
              type = types.str;
              default = "root";
              description = "Group of certificate files";
            };

            ttl = mkOption {
              type = types.str;
              default = "8760h";
              description = "Certificate TTL";
            };

            wantedBy = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Services that require this certificate";
              example = [ "postgresql.service" ];
            };
          };
        });
        default = {};
        description = "Certificates to fetch from external Vault";
      };
    };
  };

  config = mkMerge [
    # =========================================================================
    # Server Mode Configuration
    # Run a local Vault server with PKI
    # =========================================================================
    (mkIf cfg.enable {
      # Ensure Vault package is available
      environment.systemPackages = [ pkgs.vault ];

    # Create directories
    systemd.tmpfiles.rules = [
      "d /var/log/vault 0750 vault vault -"
      "d ${cfg.storagePath} 0700 vault vault -"
    ];

    # Vault service configuration
    services.vault = mkMerge [
      # Common configuration
      {
        enable = true;
        package = pkgs.vault;
        address = cfg.address;
      }

      # Dev mode configuration
      (mkIf (cfg.mode == "dev") {
        dev = true;
        devRootTokenID = "barbican-dev";
      })

      # Production mode configuration
      (mkIf (cfg.mode == "production") {
        storageBackend = if cfg.ha.enable && cfg.ha.backend == "raft" then "raft" else "file";

        storagePath = cfg.storagePath;

        storageConfig = mkIf (cfg.ha.enable && cfg.ha.backend == "raft") ''
          node_id = "${cfg.ha.nodeId}"
          ${optionalString (cfg.ha.retryJoin != []) ''
          ${concatMapStringsSep "\n" (addr: ''
          retry_join {
            leader_api_addr = "https://${addr}"
          }
          '') cfg.ha.retryJoin}
          ''}
        '';

        extraConfig = ''
          ui = true
          api_addr = "${cfg.apiAddr}"
          ${optionalString (cfg.ha.clusterAddr != null) ''
          cluster_addr = "${cfg.ha.clusterAddr}"
          ''}

          ${optionalString cfg.autoUnseal.enable (
            if cfg.autoUnseal.type == "awskms" then ''
          seal "awskms" {
            region     = "${cfg.autoUnseal.awsRegion}"
            kms_key_id = "${cfg.autoUnseal.awsKmsKeyId}"
          }
            '' else ""
          )}
        '';
      })
    ];

    # Override systemd service to add -dev-listen-address in dev mode
    # The NixOS vault module doesn't pass this flag, so Vault binds to 127.0.0.1:8200
    # by default in dev mode, ignoring cfg.address. This override fixes that.
    systemd.services.vault.serviceConfig.ExecStart = mkIf (cfg.mode == "dev") (
      let
        vaultPackage = pkgs.vault;
      in mkForce "${vaultPackage}/bin/vault server -dev -dev-root-token-id=barbican-dev -dev-listen-address=${cfg.address}"
    );

    # PKI setup service (runs after Vault starts)
    systemd.services.vault-pki-setup = mkIf (cfg.mode == "dev") {
      description = "Barbican Vault PKI Setup";
      after = [ "vault.service" ];
      wants = [ "vault.service" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        VAULT_ADDR = cfg.apiAddr;
        VAULT_TOKEN = "barbican-dev";  # Only for dev mode
      };

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkiSetupScript}";
        User = "vault";
        Group = "vault";
      };
    };

    # Firewall rules for Vault
    networking.firewall = mkIf cfg.ha.enable {
      allowedTCPPorts = [
        8200  # API
        8201  # Cluster
      ];
    };

    # Security assertions
    assertions = [
      {
        assertion = cfg.mode == "dev" || cfg.autoUnseal.enable || !cfg.ha.enable;
        message = "Production HA mode requires auto-unseal to be configured";
      }
      {
        assertion = !cfg.autoUnseal.enable || cfg.autoUnseal.type != "awskms" || cfg.autoUnseal.awsKmsKeyId != null;
        message = "AWS KMS auto-unseal requires awsKmsKeyId to be set";
      }
      {
        assertion = !cfg.ha.enable || cfg.ha.clusterAddr != null;
        message = "HA mode requires clusterAddr to be set";
      }
    ];
  })

    # =========================================================================
    # Client Mode Configuration
    # Connect to external Vault instead of running local server
    # =========================================================================
    (mkIf cfg.client.enable {
    # Ensure Vault CLI is available
    environment.systemPackages = [ pkgs.vault pkgs.jq pkgs.curl ];

    # Create directories for certificates
    systemd.tmpfiles.rules = [
      "d ${cfg.client.caChain.outputDir} 0755 root root -"
    ] ++ (mapAttrsToList (name: certCfg:
      "d ${certCfg.outputDir} 0755 ${certCfg.owner} ${certCfg.group} -"
    ) cfg.client.certificates);

    # Create systemd services for client mode (CA chain + certificate fetchers)
    systemd.services = (optionalAttrs cfg.client.caChain.enable {
      # Service to fetch CA chain from external Vault
      vault-fetch-ca = {
        description = "Fetch CA chain from external Vault";
        wantedBy = [ "multi-user.target" ];

        environment = {
          VAULT_ADDR = cfg.client.address;
        };

        path = [ pkgs.vault pkgs.curl ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };

        script = ''
          set -euo pipefail

          CA_DIR="${cfg.client.caChain.outputDir}"
          mkdir -p "$CA_DIR"

          ${optionalString (cfg.client.tokenFile != null) ''
          export VAULT_TOKEN=$(cat ${cfg.client.tokenFile})
          ''}

          # Wait for Vault to be reachable
          echo "Waiting for Vault at $VAULT_ADDR..."
          TIMEOUT=120
          ELAPSED=0
          until curl -sf "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; do
            if [ $ELAPSED -ge $TIMEOUT ]; then
              echo "ERROR: Timeout waiting for Vault at $VAULT_ADDR"
              exit 1
            fi
            sleep 2
            ELAPSED=$((ELAPSED + 2))
          done

          # Wait for PKI to be configured (intermediate CA exists)
          echo "Waiting for PKI setup..."
          ELAPSED=0
          until vault read pki_int/cert/ca > /dev/null 2>&1; do
            if [ $ELAPSED -ge $TIMEOUT ]; then
              echo "ERROR: Timeout waiting for PKI setup"
              exit 1
            fi
            sleep 2
            ELAPSED=$((ELAPSED + 2))
          done

          echo "Fetching CA chain from Vault..."
          vault read -field=certificate pki/cert/ca > "$CA_DIR/root-ca.pem"
          vault read -field=certificate pki_int/cert/ca > "$CA_DIR/intermediate-ca.pem"

          # Build CA chain with root CA first, then intermediate
          # This order is required by native-tls/OpenSSL when verifying certificate chains
          {
            cat "$CA_DIR/root-ca.pem"
            echo ""
            cat "$CA_DIR/intermediate-ca.pem"
            echo ""
          } > "$CA_DIR/ca-chain.pem"

          chmod 644 "$CA_DIR"/*.pem
          echo "CA chain fetched successfully"
        '';
      };
    }) // (mapAttrs' (name: certCfg: nameValuePair "vault-fetch-cert-${name}" {
      description = "Fetch ${name} certificate from external Vault";
      after = [ "vault-fetch-ca.service" ];
      wants = [ "vault-fetch-ca.service" ];
      wantedBy = certCfg.wantedBy;
      before = certCfg.wantedBy;

      environment = {
        VAULT_ADDR = cfg.client.address;
      };

      path = [ pkgs.vault pkgs.jq pkgs.coreutils ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };

      script = ''
        set -euo pipefail

        CERT_DIR="${certCfg.outputDir}"
        mkdir -p "$CERT_DIR"

        ${optionalString (cfg.client.tokenFile != null) ''
        export VAULT_TOKEN=$(cat ${cfg.client.tokenFile})
        ''}

        # Wait for CA chain to be ready
        until [ -f "${cfg.client.caChain.outputDir}/ca-chain.pem" ]; do
          echo "Waiting for CA chain..."
          sleep 1
        done

        echo "Issuing ${name} certificate from role ${certCfg.role}..."
        vault write -format=json pki_int/issue/${certCfg.role} \
          common_name="${certCfg.commonName}" \
          ${optionalString (certCfg.altNames != []) ''alt_names="${concatStringsSep "," certCfg.altNames}"''} \
          ${optionalString (certCfg.ipSans != []) ''ip_sans="${concatStringsSep "," certCfg.ipSans}"''} \
          ttl="${certCfg.ttl}" \
          private_key_format=pkcs8 \
          > "$CERT_DIR/cert.json"

        jq -r '.data.certificate' "$CERT_DIR/cert.json" > "$CERT_DIR/${certCfg.certFile}"
        jq -r '.data.private_key' "$CERT_DIR/cert.json" > "$CERT_DIR/${certCfg.keyFile}"
        jq -r '.data.ca_chain[]' "$CERT_DIR/cert.json" >> "$CERT_DIR/${certCfg.certFile}"

        chmod 600 "$CERT_DIR/${certCfg.keyFile}"
        chmod 644 "$CERT_DIR/${certCfg.certFile}"
        chown ${certCfg.owner}:${certCfg.group} "$CERT_DIR/${certCfg.keyFile}" "$CERT_DIR/${certCfg.certFile}"

        rm -f "$CERT_DIR/cert.json"
        echo "${name} certificate issued successfully"
      '';
    }) cfg.client.certificates);

    # Assertion: client mode and server mode are mutually exclusive
    assertions = [
      {
        assertion = !cfg.enable || !cfg.client.enable;
        message = "Vault server mode (enable) and client mode (client.enable) are mutually exclusive";
      }
      {
        assertion = !cfg.client.enable || cfg.client.tokenFile != null;
        message = "Client mode requires tokenFile to be set";
      }
    ];
  })
  ];
}
