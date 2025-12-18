# Barbican Security Module: Resource Limits
# Addresses: HIGH-001 (no resource limits - DoS risk)
# Standards: NIST SC-5, SC-6
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.resourceLimits;
in {
  options.barbican.resourceLimits = {
    enable = mkEnableOption "Barbican resource limits";

    defaultMemoryMax = mkOption {
      type = types.str;
      default = "1G";
      description = "Default maximum memory for services";
    };

    defaultMemoryHigh = mkOption {
      type = types.str;
      default = "800M";
      description = "Default memory high watermark for services";
    };

    defaultCPUQuota = mkOption {
      type = types.str;
      default = "100%";
      description = "Default CPU quota for services";
    };

    defaultTasksMax = mkOption {
      type = types.int;
      default = 100;
      description = "Default maximum number of tasks";
    };

    limitCoredump = mkOption {
      type = types.bool;
      default = true;
      description = "Disable core dumps for security";
    };

    limitOpenFiles = mkOption {
      type = types.int;
      default = 65535;
      description = "Maximum open files limit";
    };
  };

  config = mkIf cfg.enable {
    # System-wide limits
    security.pam.loginLimits = [
      { domain = "*"; type = "soft"; item = "nofile"; value = toString cfg.limitOpenFiles; }
      { domain = "*"; type = "hard"; item = "nofile"; value = toString cfg.limitOpenFiles; }
    ] ++ optionals cfg.limitCoredump [
      { domain = "*"; type = "soft"; item = "core"; value = "0"; }
      { domain = "*"; type = "hard"; item = "core"; value = "0"; }
    ];

    # Disable core dumps via sysctl (use mkDefault to avoid conflict with kernel-hardening)
    boot.kernel.sysctl = mkIf cfg.limitCoredump {
      "kernel.core_pattern" = mkDefault "|/bin/false";
      "fs.suid_dumpable" = mkDefault 0;
    };

    # Default systemd service overrides
    systemd.services = {
      # Apply defaults to common services if they're enabled
      postgresql = mkIf (config.services.postgresql.enable or false) {
        serviceConfig = {
          MemoryMax = mkDefault cfg.defaultMemoryMax;
          MemoryHigh = mkDefault cfg.defaultMemoryHigh;
          CPUQuota = mkDefault cfg.defaultCPUQuota;
          TasksMax = mkDefault cfg.defaultTasksMax;
        };
      };

      grafana = mkIf (config.services.grafana.enable or false) {
        serviceConfig = {
          MemoryMax = mkDefault cfg.defaultMemoryMax;
          MemoryHigh = mkDefault cfg.defaultMemoryHigh;
          CPUQuota = mkDefault cfg.defaultCPUQuota;
          TasksMax = mkDefault cfg.defaultTasksMax;
        };
      };

      prometheus = mkIf (config.services.prometheus.enable or false) {
        serviceConfig = {
          MemoryMax = mkDefault "2G";
          MemoryHigh = mkDefault "1.5G";
          CPUQuota = mkDefault cfg.defaultCPUQuota;
          TasksMax = mkDefault cfg.defaultTasksMax;
        };
      };

      loki = mkIf (config.services.loki.enable or false) {
        serviceConfig = {
          MemoryMax = mkDefault "2G";
          MemoryHigh = mkDefault "1.5G";
          CPUQuota = mkDefault cfg.defaultCPUQuota;
          TasksMax = mkDefault cfg.defaultTasksMax;
        };
      };
    };
  };
}
