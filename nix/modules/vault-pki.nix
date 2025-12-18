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
      default = "127.0.0.1:8200";
      description = "Address for Vault to listen on";
    };

    apiAddr = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8200";
      description = "Full URL for Vault API (used for CA URLs)";
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
  };

  config = mkIf cfg.enable {
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
  };
}
