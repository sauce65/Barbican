# Barbican FedRAMP Low Security Profile
#
# NIST 800-53 Rev 5 Low baseline - basic security controls for systems where
# loss of confidentiality, integrity, or availability would have LIMITED
# adverse effect on organizational operations.
#
# This profile aligns with Barbican's Rust ComplianceProfile::FedRampLow
# and the *_for_profile() functions in src/integration.rs.
#
# Profile Settings (from integration.rs):
#   Session: 30 min idle, 12 hr max, 5 concurrent (AC-10, AC-11, AC-12)
#   Lockout: 5 attempts, 10 min lockout (AC-7)
#   Password: 8 char min (IA-5)
#   SSL: Require (SC-8)
#   Encryption: Not required (SC-28)
#   Key Rotation: 365 days (SC-12)
#
# Controls implemented:
#   AC-7, AC-10, AC-11, AC-12, AU-2, AU-8, IA-5, SC-7, SC-8, SI-16
{ config, lib, pkgs, ... }:

{
  imports = [
    ../modules/secure-users.nix
    ../modules/hardened-ssh.nix
    ../modules/kernel-hardening.nix
    ../modules/time-sync.nix
    ../modules/vm-firewall.nix
  ];

  barbican = {
    # AC-2: Account Management
    secureUsers = {
      enable = true;
      allowPasswordAuth = false;  # Key-based auth only
    };

    # AC-7: Unsuccessful Logon Attempts
    # Match lockout_policy_for_profile(FedRampLow): 5 attempts, 10 min lockout
    hardenedSSH = {
      enable = true;
      maxAuthTries = 5;           # AC-7: 5 attempts before disconnect
      maxSessions = 5;            # AC-10: Match max_concurrent_sessions
      clientAliveInterval = 1800; # AC-11: 30 min idle timeout
      enableFail2ban = true;
      fail2banMaxRetry = 5;       # AC-7: Match max_attempts
      fail2banBanTime = 600;      # AC-7: 10 min lockout (600 seconds)
    };

    # SI-16: Memory Protection
    kernelHardening = {
      enable = true;
      enableNetworkHardening = true;
      enableMemoryProtection = true;
      enableProcessRestrictions = true;
      enableAudit = false;        # Audit not required for Low
    };

    # AU-8: Time Stamps
    timeSync = {
      enable = true;
      servers = [
        "time.cloudflare.com"
        "time.google.com"
        "time.nist.gov"
      ];
    };

    # SC-7: Boundary Protection
    vmFirewall = {
      enable = true;
      defaultPolicy = "drop";
      enableEgressFiltering = false;  # Not required for Low
      logDropped = false;             # Minimal logging for Low
    };
  };

  # Set environment variable so Rust code uses matching profile
  environment.variables.BARBICAN_COMPLIANCE_PROFILE = "fedramp-low";

  # Basic hardening
  security.sudo.wheelNeedsPassword = true;

  # Disable unnecessary services
  services.avahi.enable = false;
  services.printing.enable = false;
}
