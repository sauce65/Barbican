# AUTO-GENERATED FROM barbican.toml - DO NOT EDIT
# Regenerate with: barbican generate nix
# Profile: FedRAMP Low
# Generated: 2025-12-30 19:24:47 UTC
#
# USAGE: Your flake.nix must import barbican's NixOS modules:
#   modules = [
#     barbican.nixosModules.all      # Provides the barbican.* options
#     ./nix/generated/barbican.nix   # This file (configuration values)
#   ];
{ config, lib, pkgs, ... }:

{

  # Database Configuration (SC-8, AU-2, IA-5)
  # Derived from profile: FedRAMP Low
  barbican.securePostgres = {
    enable = true;
    listenAddress = "127.0.0.1";
    allowedClients = [  ];
    database = "hello_fedramp_low";
    username = "hello_fedramp_low";
    passwordFile = config.age.secrets.db-password.path;

    # Transport Security (SC-8)
    enableSSL = true;
    enableClientCert = false;  # mTLS: not required for FedRAMP Low

    # Audit Logging (AU-2, AU-9)
    enableAuditLog = true;
    enablePgaudit = true;
    pgauditLogClasses = [ "write" "role" "ddl" ];
    logFileMode = "0600";

    # Connection Limits
    maxConnections = 50;

    # Process Isolation (SC-39)
    enableProcessIsolation = true;
  };

  # Firewall Configuration (SC-7, SC-7(5))
  barbican.vmFirewall = {
    enable = true;
    defaultPolicy = "drop";

    allowedInbound = [
    { port = 3000; from = "any"; proto = "tcp"; }
    ];

    # Egress Filtering: recommended for FedRAMP Low
    enableEgressFiltering = false;
    allowedOutbound = [
    ];

    logDropped = true;
  };

  # Kernel Hardening (SI-16)
  barbican.kernelHardening = {
    enable = true;
    enableNetworkHardening = true;
    enableMemoryProtection = true;
    enableProcessRestrictions = true;
    enableAudit = true;
  };

  # Intrusion Detection (SI-4, SI-7)
  barbican.intrusionDetection = {
    enable = true;
    enableAIDE = true;
    enableAuditd = true;
  };

  # Resource Limits (SC-5, SC-6)
  barbican.resourceLimits = {
    enable = true;
    defaultMemoryMax = "1G";
    defaultCPUQuota = "100%";
    limitCoredump = true;
  };

  # Application Service
  systemd.services.hello_fedramp_low = {
    description = "hello-fedramp-low";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" "postgresql.service" ];

    serviceConfig = config.barbican.systemdHardening.presets.networkService // {
      ExecStart = "${pkgs."hello-fedramp-low"}/bin/hello_fedramp_low";
      EnvironmentFile = config.age.secrets.hello_fedramp_low-env.path;

      # Resource Limits
      MemoryMax = "1G";
      CPUQuota = "100%";

      # Paths
      ReadWritePaths = [ "/var/lib/hello_fedramp_low" ];
    };
  };
}
