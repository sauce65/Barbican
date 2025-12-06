# Barbican Security Module: Secrets Management
# Addresses: CRT-004 (hardcoded passwords), CRT-005 (Grafana password)
# Standards: NIST IA-5(1), SC-28, PCI DSS 8.2.1
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.secrets;
in {
  options.barbican.secrets = {
    enable = mkEnableOption "Barbican secrets management";

    ageKeyFile = mkOption {
      type = types.path;
      default = "/var/lib/sops-nix/key.txt";
      description = "Path to the age private key for decryption";
    };

    secretsFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the sops-encrypted secrets file";
    };
  };

  config = mkIf cfg.enable {
    # Note: This module provides configuration options.
    # The actual sops-nix import must happen in the consuming flake
    # because it requires the sops-nix input.
    #
    # Example usage in consuming flake:
    #
    # imports = [
    #   sops-nix.nixosModules.sops
    #   barbican.nixosModules.secretsManagement
    # ];
    #
    # sops = {
    #   defaultSopsFile = ./secrets/secrets.yaml;
    #   age.keyFile = config.barbican.secrets.ageKeyFile;
    #   secrets.postgres_password = {};
    #   secrets.grafana_admin_password = {};
    # };
    #
    # barbican.securePostgres.passwordFile = config.sops.secrets.postgres_password.path;

    # Ensure the key directory exists with proper permissions
    systemd.tmpfiles.rules = [
      "d /var/lib/sops-nix 0700 root root -"
    ];

    # Warn if secrets file is not configured
    warnings = optional (cfg.secretsFile == null) ''
      barbican.secrets is enabled but no secretsFile is configured.
      Secrets will not be automatically decrypted.
    '';
  };
}
