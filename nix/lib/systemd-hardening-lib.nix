# Barbican Systemd Hardening Library
# Provides hardening presets for systemd services
{ lib }:

with lib;

rec {
  # Base hardening - maximum restrictions
  base = {
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

    # Syscall filtering
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";

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
  };

  # Network service preset
  networkService = base // {
    PrivateNetwork = false;
    RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
    SystemCallFilter = [ "@system-service" "@network-io" "~@privileged" ];
  };

  # Web service preset (HTTP/HTTPS)
  webService = networkService // {
    CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
    AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
  };

  # Database service preset
  databaseService = base // {
    PrivateNetwork = false;
    PrivateUsers = false;
    ProtectHome = "read-only";
    RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
    SystemCallFilter = [ "@system-service" "@network-io" "@io-event" "~@privileged" ];
    # Databases need more file access
    ReadWritePaths = [ "/var/lib/postgresql" ];
  };

  # Observability service preset (Prometheus, Loki, etc.)
  observabilityService = networkService // {
    # Need to scrape metrics and store data
    ReadWritePaths = [ "/var/lib/prometheus2" "/var/lib/loki" "/var/lib/grafana" ];
    SystemCallFilter = [ "@system-service" "@network-io" "~@privileged" ];
  };

  # Background worker preset
  workerService = base // {
    PrivateNetwork = true;
    RestrictAddressFamilies = [ "AF_UNIX" ];
    SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
  };

  # Helper to merge hardening with custom paths
  withPaths = preset: { read ? [], write ? [] }:
    preset // {
      ReadOnlyPaths = (preset.ReadOnlyPaths or []) ++ read;
      ReadWritePaths = (preset.ReadWritePaths or []) ++ write;
    };

  # Helper to add capabilities
  withCapabilities = preset: caps:
    preset // {
      CapabilityBoundingSet = (preset.CapabilityBoundingSet or []) ++ caps;
      AmbientCapabilities = (preset.AmbientCapabilities or []) ++ caps;
    };

  # Helper to relax specific restrictions
  relax = preset: relaxations:
    preset // relaxations;
}
