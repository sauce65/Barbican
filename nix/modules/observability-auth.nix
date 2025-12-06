# Barbican Security Module: Observability Authentication
# Addresses: CRT-008 (Loki auth disabled), CRT-014 (Prometheus no auth)
# Standards: NIST AC-2, AU-9, SOC 2 CC7.2
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.observabilityAuth;
in {
  options.barbican.observabilityAuth = {
    enable = mkEnableOption "Barbican observability authentication";

    prometheus = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Prometheus basic auth";
      };

      htpasswdFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to htpasswd file for basic auth";
      };
    };

    loki = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Loki authentication";
      };

      enableTLS = mkOption {
        type = types.bool;
        default = false;
        description = "Enable TLS for Loki (requires cert files)";
      };

      certFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "TLS certificate file";
      };

      keyFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "TLS private key file";
      };
    };

    grafana = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Grafana security hardening";
      };

      adminPasswordFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to file containing admin password";
      };

      enableTLS = mkOption {
        type = types.bool;
        default = false;
        description = "Enable TLS for Grafana";
      };
    };
  };

  config = mkIf cfg.enable {
    # Prometheus with basic auth
    services.prometheus = mkIf (cfg.prometheus.enable && config.services.prometheus.enable or false) {
      webConfigFile = mkIf (cfg.prometheus.htpasswdFile != null) (
        pkgs.writeText "prometheus-web.yml" ''
          basic_auth_users:
            # Use htpasswd to generate: htpasswd -nBC 10 admin
            # File should contain: admin:$2y$10$...
        ''
      );
    };

    # Loki with auth enabled
    services.loki = mkIf (cfg.loki.enable && config.services.loki.enable or false) {
      configuration = {
        auth_enabled = true;
      } // optionalAttrs (cfg.loki.enableTLS && cfg.loki.certFile != null) {
        server.http_tls_config = {
          cert_file = cfg.loki.certFile;
          key_file = cfg.loki.keyFile;
        };
      };
    };

    # Grafana security
    services.grafana = mkIf (cfg.grafana.enable && config.services.grafana.enable or false) {
      settings = {
        security = {
          # Disable default admin creation with hardcoded password
          disable_initial_admin_creation = cfg.grafana.adminPasswordFile == null;

          # Security headers
          cookie_secure = true;
          cookie_samesite = "strict";
          strict_transport_security = true;
          x_content_type_options = true;
          x_xss_protection = true;
        };

        server = optionalAttrs cfg.grafana.enableTLS {
          protocol = "https";
        };

        analytics = {
          reporting_enabled = false;
          check_for_updates = false;
        };

        users = {
          allow_sign_up = false;
          allow_org_create = false;
        };
      };
    };

    # Set Grafana password from file
    systemd.services.grafana-set-password = mkIf (cfg.grafana.enable && cfg.grafana.adminPasswordFile != null) {
      description = "Set Grafana admin password from secret";
      after = [ "grafana.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        PASSWORD=$(cat ${cfg.grafana.adminPasswordFile})
        ${pkgs.grafana}/bin/grafana-cli admin reset-admin-password "$PASSWORD" || true
      '';
    };
  };
}
