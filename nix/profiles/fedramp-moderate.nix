# Barbican FedRAMP Moderate Security Profile
#
# NIST 800-53 Rev 5 Moderate baseline - enhanced security controls for systems
# where loss of confidentiality, integrity, or availability would have SERIOUS
# adverse effect on organizational operations. This is the most common FedRAMP
# authorization level.
#
# This profile aligns with Barbican's Rust ComplianceProfile::FedRampModerate
# and the *_for_profile() functions in src/integration.rs.
#
# Profile Settings (from integration.rs):
#   Session: 15 min idle, 8 hr max, 3 concurrent (AC-10, AC-11, AC-12)
#   Lockout: 3 attempts, 15 min lockout, progressive (AC-7)
#   Password: 12 char min, check common passwords (IA-5)
#   SSL: VerifyCa (SC-8)
#   Encryption: Required, verify database (SC-28)
#   Key Rotation: 90 days (SC-12)
#
# Controls implemented:
#   AC-2, AC-6, AC-7, AC-10, AC-11, AC-12, AU-2, AU-8, AU-9,
#   IA-5, SC-7, SC-8, SC-12, SC-17, SC-28, SC-39, SI-4, SI-16
{ config, lib, pkgs, ... }:

{
  imports = [
    ../lib/profile-meta.nix
    ../modules/secure-users.nix
    ../modules/hardened-ssh.nix
    ../modules/secure-postgres.nix
    ../modules/kernel-hardening.nix
    ../modules/time-sync.nix
    ../modules/resource-limits.nix
    ../modules/vm-firewall.nix
    ../modules/intrusion-detection.nix
    ../modules/vault-pki.nix
  ];

  barbican = {
    profile = {
      name = "fedramp-moderate";
      includedModules = [
        "secure-users"
        "hardened-ssh"
        "secure-postgres"
        "kernel-hardening"
        "time-sync"
        "resource-limits"
        "vm-firewall"
        "intrusion-detection"
        "vault-pki"
      ];
    };

    # AC-2: Account Management
    secureUsers = {
      enable = true;
      allowPasswordAuth = false;  # Key-based auth only
    };

    # AC-7: Unsuccessful Logon Attempts
    # Match lockout_policy_for_profile(FedRampModerate): 3 attempts, 15 min lockout
    hardenedSSH = {
      enable = true;
      maxAuthTries = 3;           # AC-7: 3 attempts before disconnect
      maxSessions = 3;            # AC-10: Match max_concurrent_sessions
      clientAliveInterval = 900;  # AC-11: 15 min idle timeout (900 seconds)
      enableFail2ban = true;
      fail2banMaxRetry = 3;       # AC-7: Match max_attempts
      fail2banBanTime = 900;      # AC-7: 15 min lockout (900 seconds)
    };

    # SC-8, AU-2, SC-39: Secure PostgreSQL
    # Match ssl_mode_for_profile(FedRampModerate): VerifyCa
    securePostgres = {
      enable = lib.mkDefault false;  # Enable when database is needed
      enableSSL = true;              # SC-8: TLS required
      # sslMode configured by consumer based on verify-ca requirement
      enablePgaudit = true;          # AU-2: Audit events
      pgauditLogClasses = [          # AU-2: What to audit
        "write"
        "ddl"
        "role"
        "read"
      ];
      enableProcessIsolation = true; # SC-39: Process isolation
      enableAuditLog = true;         # AU-9: Audit log protection
    };

    # SI-16: Memory Protection
    kernelHardening = {
      enable = true;
      enableNetworkHardening = true;   # SC-7: Network hardening
      enableMemoryProtection = true;   # SI-16: ASLR, W^X
      enableProcessRestrictions = true; # SC-39: Process isolation
      enableAudit = true;              # AU-2: Kernel audit subsystem
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

    # AC-6: Least Privilege (resource limits)
    resourceLimits = {
      enable = true;
      limitCoredump = true;  # Prevent credential leaks in dumps
      defaultTasksMax = 100;
    };

    # SC-7: Boundary Protection
    vmFirewall = {
      enable = true;
      defaultPolicy = "drop";
      enableEgressFiltering = false;  # Not required for Moderate
      logDropped = true;              # AU-2: Log dropped packets
    };

    # SI-4: Information System Monitoring
    intrusionDetection = {
      enable = true;
      enableAIDE = true;              # SI-7: File integrity monitoring
      enableAuditd = true;            # AU-2: Audit daemon
      enableProcessAccounting = true; # AU-12: Process accounting
    };

    # SC-12, SC-17: Cryptographic Key Management / PKI
    vault = {
      enable = lib.mkDefault false;  # Enable when Vault is needed
      pki = {
        keyType = "ec";
        keyBits = 384;               # P-384 curve for Moderate
        defaultCertTtl = "720h";     # 30 days
        maxCertTtl = "2160h";        # 90 days (match key rotation)
      };
      audit.enable = true;           # AU-2: Vault audit logging
    };
  };

  # Set environment variable so Rust code uses matching profile
  environment.variables.BARBICAN_COMPLIANCE_PROFILE = "fedramp-moderate";

  # Strict password policy
  security.sudo.wheelNeedsPassword = true;

  # Disable unnecessary services
  services.avahi.enable = false;
  services.printing.enable = false;

  # No mutable users
  users.mutableUsers = false;
}
