# Barbican Development Profile
#
# Minimal security for local development and testing environments.
# Provides basic security without impacting developer workflow.
#
# WARNING: Never use this profile in production. It intentionally relaxes
# security controls to enable rapid development iteration.
#
# This profile aligns with Barbican's Rust ComplianceProfile::Development
# and the *_for_profile() functions in src/integration.rs.
#
# Profile Settings (from integration.rs):
#   Session: 30 min idle, 12 hr max, unlimited concurrent (AC-10, AC-11, AC-12)
#   Lockout: 5 attempts, 10 min lockout (AC-7)
#   Password: 8 char min (IA-5)
#   SSL: Require (SC-8)
#   Encryption: Not required (SC-28)
#   Key Rotation: 365 days (SC-12)
#
# Relaxations from FedRAMP profiles:
#   - Password authentication allowed for SSH
#   - Root login allowed (with key)
#   - Kernel audit disabled
#   - Egress filtering disabled
#   - File integrity monitoring disabled
{ config, lib, pkgs, ... }:

{
  imports = [
    ../modules/secure-users.nix
    ../modules/time-sync.nix
  ];

  barbican = {
    secureUsers = {
      enable = true;
      # Allow empty authorized keys in development profile
    };

    timeSync.enable = true;
  };

  # Set environment variable so Rust code uses matching profile
  environment.variables.BARBICAN_COMPLIANCE_PROFILE = "development";

  # Basic firewall - allow common dev ports
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [
      22    # SSH
      80    # HTTP
      443   # HTTPS
      5432  # PostgreSQL
      8080  # Common dev server
      8443  # HTTPS dev server
      3000  # Node.js / React dev server
      9090  # Prometheus
      3100  # Loki
      3030  # Grafana dev
    ];
  };

  # Allow SSH for development access (relaxed settings)
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = lib.mkDefault true;   # Allow in dev
      PermitRootLogin = lib.mkDefault "prohibit-password";
      MaxAuthTries = 10;        # Relaxed for dev
      MaxSessions = 10;         # Relaxed for dev
      ClientAliveInterval = 0;  # No timeout in dev
    };
  };

  # Relaxed sudo for development
  security.sudo.wheelNeedsPassword = lib.mkDefault false;

  # Allow mutable users for easy testing
  users.mutableUsers = true;
}
