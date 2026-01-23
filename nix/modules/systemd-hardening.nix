# Barbican Security Module: Systemd Service Hardening
#
# STIG Implementation:
#   UBTU-22-232010: Restrict service capabilities (AC-6)
#   UBTU-22-232015: Enable NoNewPrivileges (AC-6)
#   UBTU-22-232020: Enable ProtectSystem strict mode (AC-6)
#   UBTU-22-232025: Isolate service namespaces (SC-39)
#
# NIST Controls: AC-6, SC-39, SI-3
# Legacy: MED-003
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.systemdHardening;

  # Standard hardening options for services
  hardeningOptions = {
    # Filesystem isolation
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    ProtectControlGroups = true;
    ProtectKernelLogs = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";

    # Process isolation
    NoNewPrivileges = true;
    PrivateDevices = true;
    PrivateUsers = true;

    # Network restrictions
    RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];

    # Syscall filtering
    SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";

    # Capabilities
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";

    # Memory protection
    MemoryDenyWriteExecute = true;

    # Misc hardening
    LockPersonality = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    RemoveIPC = true;

    # Ulimits
    LimitNOFILE = 65535;
    LimitNPROC = 512;
  };
in {
  options.barbican.systemdHardening = {
    enable = mkEnableOption "Barbican systemd service hardening";

    services = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "List of service names to harden";
    };

    allowNetwork = mkOption {
      type = types.bool;
      default = true;
      description = "Allow network access";
    };

    allowWritePaths = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional writable paths";
    };

    allowReadPaths = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional readable paths";
    };

    allowCapabilities = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Capabilities to allow";
    };
  };

  config = mkIf cfg.enable {
    # Note: This module provides a library function for hardening
    # Individual services should apply these settings explicitly

    # Export hardening presets for use in other modules
    # Usage in consuming flake:
    #
    # systemd.services.myservice.serviceConfig =
    #   config.barbican.systemdHardening.presets.standard // {
    #     ReadWritePaths = [ "/var/lib/myservice" ];
    #   };
  };

  # Add presets as module options
  options.barbican.systemdHardening.presets = {
    standard = mkOption {
      type = types.attrs;
      default = hardeningOptions;
      readOnly = true;
      description = "Standard hardening options";
    };

    networkService = mkOption {
      type = types.attrs;
      default = hardeningOptions // {
        PrivateNetwork = false;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      };
      readOnly = true;
      description = "Hardening for network services";
    };

    databaseService = mkOption {
      type = types.attrs;
      default = hardeningOptions // {
        PrivateNetwork = false;
        PrivateUsers = false;
        ProtectHome = "read-only";
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
      };
      readOnly = true;
      description = "Hardening for database services";
    };
  };
}
