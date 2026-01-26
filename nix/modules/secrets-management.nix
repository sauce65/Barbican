# Barbican Security Module: Secrets Management
# Addresses: CRT-004 (hardcoded passwords), CRT-005 (Grafana password)
# Standards: NIST IA-5(1), SC-28, PCI DSS 8.2.1
#
# Provides declarative secrets management with sops-nix integration.
# Consumers define secrets via barbican.secrets.secrets and this module
# generates the corresponding sops.secrets entries.
#
# The consumer must import sops-nix.nixosModules.sops alongside this module.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.secrets;
in {
  options.barbican.secrets = {
    enable = mkEnableOption "Barbican secrets management";

    provider = mkOption {
      type = types.enum [ "sops-nix" "vault-kv" ];
      default = "sops-nix";
      description = "Secrets provider backend";
    };

    ageKeyFile = mkOption {
      type = types.path;
      default = "/var/lib/sops-nix/key.txt";
      description = "Path to the age private key for decryption";
    };

    defaultSopsFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Default sops-encrypted secrets file. Individual secrets can override
        this with their own sopsFile option.
      '';
    };

    secrets = mkOption {
      type = types.attrsOf (types.submodule ({ name, ... }: {
        options = {
          sopsFile = mkOption {
            type = types.nullOr types.path;
            default = null;
            description = ''
              Path to the sops-encrypted file containing this secret.
              Defaults to barbican.secrets.defaultSopsFile if not set.
            '';
          };

          key = mkOption {
            type = types.str;
            default = "";
            description = ''
              Key within the sops file to extract. Empty string means
              use the secret attribute name.
            '';
          };

          owner = mkOption {
            type = types.str;
            default = "root";
            description = "Owner of the decrypted secret file";
          };

          group = mkOption {
            type = types.str;
            default = "root";
            description = "Group of the decrypted secret file";
          };

          mode = mkOption {
            type = types.str;
            default = "0400";
            description = "File permissions for the decrypted secret";
          };

          path = mkOption {
            type = types.path;
            readOnly = true;
            default = "/run/secrets/${name}";
            description = "Path where the decrypted secret will be available (read-only)";
          };

          restartUnits = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Systemd units to restart when this secret changes";
          };
        };
      }));
      default = {};
      description = ''
        Attribute set of secrets to manage. Each secret maps to a
        sops.secrets entry with the configured ownership and permissions.
      '';
    };
  };

  config = mkIf cfg.enable (mkMerge [
    # sops-nix provider
    (mkIf (cfg.provider == "sops-nix") {
      # Set sops age key file
      sops.age.keyFile = cfg.ageKeyFile;

      # Set default sops file if configured
      sops.defaultSopsFile = mkIf (cfg.defaultSopsFile != null) cfg.defaultSopsFile;

      # Generate sops.secrets entries from barbican.secrets.secrets
      sops.secrets = mapAttrs (name: secretCfg: {
        inherit (secretCfg) owner group mode restartUnits;
        sopsFile = mkIf (secretCfg.sopsFile != null) secretCfg.sopsFile;
        key = mkIf (secretCfg.key != "") secretCfg.key;
      }) cfg.secrets;
    })

    # Common configuration for all providers
    {
      # Ensure the key directory exists with proper permissions
      systemd.tmpfiles.rules = [
        "d /var/lib/sops-nix 0700 root root -"
      ];

      # Warn if no secrets file is configured
      warnings = optional (cfg.defaultSopsFile == null && cfg.secrets == {}) ''
        barbican.secrets is enabled but no defaultSopsFile or secrets are configured.
        Secrets will not be automatically decrypted.
      '';
    }
  ]);
}
