# AUTO-GENERATED FROM barbican.toml - DO NOT EDIT
# Regenerate with: barbican generate nix
# Profile: FedRAMP High
# Generated: 2025-12-30 19:20:18 UTC
#
# USAGE: Your flake.nix must import barbican's NixOS modules:
#   modules = [
#     barbican.nixosModules.all      # Provides the barbican.* options
#     ./nix/generated/barbican.nix   # This file (configuration values)
#   ];
{ config, lib, pkgs, ... }:

{

  # Database Configuration (SC-8, AU-2, IA-5)
  # Derived from profile: FedRAMP High
  barbican.securePostgres = {
    enable = true;
    listenAddress = "127.0.0.1";
    allowedClients = [  ];
    database = "hello_fedramp_high";
    username = "hello_fedramp_high";
    passwordFile = config.age.secrets.db-password.path;

    # Transport Security (SC-8)
    enableSSL = true;
    enableClientCert = true;  # mTLS: required for FedRAMP High

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
    { port = 3000; from = "10.0.0.0/8"; proto = "tcp"; }
    ];

    # Egress Filtering: required for FedRAMP High
    enableEgressFiltering = true;
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
  systemd.services.hello_fedramp_high = {
    description = "hello-fedramp-high";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" "postgresql.service" ];

    serviceConfig = config.barbican.systemdHardening.presets.networkService // {
      ExecStart = "${pkgs."hello-fedramp-high"}/bin/hello_fedramp_high";
      EnvironmentFile = config.age.secrets.hello_fedramp_high-env.path;

      # Resource Limits
      MemoryMax = "1G";
      CPUQuota = "100%";

      # Paths
      ReadWritePaths = [ "/var/lib/hello_fedramp_high" ];
    };
  };
}
