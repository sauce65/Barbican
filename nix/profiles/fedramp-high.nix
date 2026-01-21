# Barbican FedRAMP High Security Profile
#
# NIST 800-53 Rev 5 High baseline - maximum security controls for systems where
# loss of confidentiality, integrity, or availability would have SEVERE or
# CATASTROPHIC adverse effect on organizational operations.
#
# This profile aligns with Barbican's Rust ComplianceProfile::FedRampHigh
# and the *_for_profile() functions in src/integration.rs.
#
# Profile Settings (from integration.rs):
#   Session: 10 min idle, 4 hr max, 1 concurrent (AC-10, AC-11, AC-12)
#   Lockout: 3 attempts, 30 min lockout, progressive, strict (AC-7)
#   Password: 15 char min, check common + breach database (IA-5)
#   SSL: VerifyFull (SC-8)
#   Encryption: Required, verify database + disk (SC-28)
#   Key Rotation: 30 days (SC-12)
#
# Controls implemented:
#   AC-2, AC-6, AC-7, AC-10, AC-11, AC-12, AU-2, AU-3, AU-8, AU-9,
#   IA-3, IA-5, IA-5(2), SC-7, SC-7(5), SC-8, SC-12, SC-17, SC-28, SC-39,
#   SI-4, SI-7, SI-16
{ config, lib, pkgs, ... }:

{
  imports = [
    ../modules/secure-users.nix
    ../modules/hardened-ssh.nix
    ../modules/secure-postgres.nix
    ../modules/kernel-hardening.nix
    ../modules/time-sync.nix
    ../modules/resource-limits.nix
    ../modules/vm-firewall.nix
    ../modules/intrusion-detection.nix
    ../modules/vault-pki.nix
    ../modules/systemd-hardening.nix
  ];

  barbican = {
    # AC-2: Account Management
    secureUsers = {
      enable = true;
      allowPasswordAuth = false;  # Key-based auth only
    };

    # AC-7: Unsuccessful Logon Attempts
    # Match lockout_policy_for_profile(FedRampHigh): 3 attempts, 30 min lockout, strict
    hardenedSSH = {
      enable = true;
      maxAuthTries = 2;           # AC-7: Stricter than Moderate (2 vs 3)
      maxSessions = 1;            # AC-10: Match max_concurrent_sessions (1 for High)
      clientAliveInterval = 600;  # AC-11: 10 min idle timeout (600 seconds)
      enableFail2ban = true;
      fail2banMaxRetry = 3;       # AC-7: Match max_attempts
      fail2banBanTime = 1800;     # AC-7: 30 min lockout (1800 seconds)
    };

    # SC-8, AU-2, SC-39, IA-5(2): Secure PostgreSQL with mTLS
    # Match ssl_mode_for_profile(FedRampHigh): VerifyFull
    securePostgres = {
      enable = lib.mkDefault false;  # Enable when database is needed
      enableSSL = true;              # SC-8: TLS required
      # sslMode configured by consumer based on verify-full requirement
      enableClientCert = true;       # IA-5(2): PKI-based authentication
      clientCertMode = "verify-full"; # SC-8: Full certificate verification
      enablePgaudit = true;          # AU-2: Audit events
      pgauditLogClasses = [          # AU-2: Comprehensive auditing for High
        "write"
        "ddl"
        "role"
        "read"
        "function"
        "misc"
      ];
      enableProcessIsolation = true; # SC-39: Process isolation
      enableAuditLog = true;         # AU-9: Audit log protection
    };

    # SI-16: Memory Protection (maximum hardening)
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
      # Tighter polling for High
      minPoll = 3;   # 8 seconds min
      maxPoll = 6;   # 64 seconds max
    };

    # AC-6: Least Privilege (strict resource limits)
    resourceLimits = {
      enable = true;
      limitCoredump = true;   # Prevent credential leaks in dumps
      defaultTasksMax = 50;   # Stricter than Moderate
    };

    # SC-7, SC-7(5): Boundary Protection with Egress Filtering
    vmFirewall = {
      enable = true;
      defaultPolicy = "drop";
      enableEgressFiltering = true;  # SC-7(5): Deny by default outbound
      logDropped = true;             # AU-3: Enhanced logging for High
      # Consumer must explicitly whitelist allowed outbound connections
    };

    # SI-4, SI-7: Information System Monitoring (comprehensive)
    intrusionDetection = {
      enable = true;
      enableAIDE = true;              # SI-7: File integrity monitoring
      aideScanSchedule = "02:00";     # More frequent scans
      enableAuditd = true;            # AU-2: Audit daemon
      enableProcessAccounting = true; # AU-12: Process accounting
    };

    # SC-12, SC-17: Cryptographic Key Management / PKI (strict)
    vault = {
      enable = lib.mkDefault false;  # Enable when Vault is needed
      pki = {
        keyType = "ec";
        keyBits = 384;               # P-384 curve minimum for High
        defaultCertTtl = "168h";     # 7 days (shorter for High)
        maxCertTtl = "720h";         # 30 days (match key rotation)
      };
      audit.enable = true;           # AU-2: Vault audit logging
    };

    # SC-39: Process Isolation (systemd hardening for all services)
    systemdHardening.enable = true;
  };

  # Set environment variable so Rust code uses matching profile
  environment.variables.BARBICAN_COMPLIANCE_PROFILE = "fedramp-high";

  # Strict password policy
  security.sudo.wheelNeedsPassword = true;

  # Disable all unnecessary services
  services.avahi.enable = false;
  services.printing.enable = false;

  # No mutable users
  users.mutableUsers = false;

  # Strict file permissions
  boot.specialFileSystems."/dev/shm".options = [ "noexec" "nodev" "nosuid" ];

  # Restrict kernel module loading after boot
  security.lockKernelModules = true;
}
