# Barbican Security Module: Centralized Log Forwarding
#
# NIST 800-53 Controls:
# - AU-4: Audit Log Storage Capacity
# - AU-6: Audit Record Review, Analysis, and Reporting
# - SI-4: Information System Monitoring
#
# Forwards journal entries and file-based logs to a central Loki instance
# via Promtail (or Vector). Profile-dependent defaults control scrape
# intervals and TLS requirements.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.logForwarding;

  # Profile-dependent defaults
  profileDefaults = {
    development = { positionsSyncTime = "30s"; requireTls = false; };
    low         = { positionsSyncTime = "15s"; requireTls = false; };
    moderate    = { positionsSyncTime = "10s"; requireTls = false; };
    high        = { positionsSyncTime = "5s";  requireTls = true; };
  };

  currentProfile = profileDefaults.${cfg.profile};

  # Generate Promtail configuration
  promtailConfig = {
    server = {
      http_listen_port = 0;  # Disable HTTP server
      grpc_listen_port = 0;
    };

    positions = {
      filename = "/var/lib/promtail/positions.yaml";
      sync_period = currentProfile.positionsSyncTime;
    };

    clients = [{
      url = "${cfg.lokiUrl}/loki/api/v1/push";
    } // optionalAttrs cfg.tls.enable {
      tls_config = {
        ca_file = toString cfg.tls.caCertFile;
      };
    }];

    scrape_configs =
      # Journal scraping
      (optional cfg.journal.enable {
        job_name = "journal";
        journal = {
          max_age = cfg.journal.maxAge;
          labels = {
            job = "systemd-journal";
            host = cfg.hostname;
          };
        };
        relabel_configs = [{
          source_labels = [ "__journal__systemd_unit" ];
          target_label = "unit";
        }];
      })
      # File-based scrapes
      ++ (mapAttrsToList (name: scrapeCfg: {
        job_name = name;
        static_configs = [{
          targets = [ "localhost" ];
          labels = {
            job = name;
            host = cfg.hostname;
            __path__ = scrapeCfg.path;
          } // scrapeCfg.labels;
        }];
      }) cfg.fileScrapes);
  };

  promtailConfigFile = pkgs.writeText "promtail-config.yaml"
    (builtins.toJSON promtailConfig);

in {
  options.barbican.logForwarding = {
    enable = mkEnableOption "Centralized log forwarding (AU-4, AU-6, SI-4)";

    agent = mkOption {
      type = types.enum [ "promtail" "vector" ];
      default = "promtail";
      description = "Log forwarding agent to use";
    };

    lokiUrl = mkOption {
      type = types.str;
      description = "URL of the Loki instance to forward logs to";
      example = "http://ao-observability:3100";
    };

    profile = mkOption {
      type = types.enum [ "development" "low" "moderate" "high" ];
      default = "moderate";
      description = "Security profile controlling scrape intervals and TLS requirements";
    };

    journal = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Forward systemd journal entries";
      };

      maxAge = mkOption {
        type = types.str;
        default = "12h";
        description = "Maximum age of journal entries to forward";
      };
    };

    fileScrapes = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          path = mkOption {
            type = types.str;
            description = "Path glob for log files to scrape";
            example = "/var/log/vault/audit.log";
          };

          labels = mkOption {
            type = types.attrsOf types.str;
            default = {};
            description = "Additional labels to attach to log entries";
          };
        };
      });
      default = {};
      description = "File-based log scrape targets";
    };

    tls = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable TLS for log transport";
      };

      caCertFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to CA certificate for TLS verification";
      };
    };

    hostname = mkOption {
      type = types.str;
      default = config.networking.hostName;
      description = "Hostname label for log entries";
    };
  };

  config = mkIf cfg.enable (mkMerge [
    # Promtail agent
    (mkIf (cfg.agent == "promtail") {
      services.promtail = {
        enable = true;
        configuration = promtailConfig;
      };

      # Ensure positions directory exists
      systemd.tmpfiles.rules = [
        "d /var/lib/promtail 0750 promtail promtail -"
      ];
    })

    # Assertions
    {
      assertions = [
        {
          assertion = !currentProfile.requireTls || cfg.tls.enable;
          message = "FedRAMP High profile requires TLS for log forwarding (AU-4)";
        }
        {
          assertion = !cfg.tls.enable || cfg.tls.caCertFile != null;
          message = "TLS log forwarding requires caCertFile to be set";
        }
      ];
    }
  ]);
}
