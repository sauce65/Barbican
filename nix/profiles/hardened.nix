# Barbican Hardened Security Profile
# For production environments with compliance requirements
# Maximum security posture - NIST 800-53 / FedRAMP aligned
{ config, lib, ... }:

{
  imports = [
    ../modules/secure-users.nix
    ../modules/hardened-ssh.nix
    ../modules/kernel-hardening.nix
    ../modules/time-sync.nix
    ../modules/resource-limits.nix
    ../modules/vm-firewall.nix
    ../modules/intrusion-detection.nix
    ../modules/systemd-hardening.nix
  ];

  barbican = {
    secureUsers = {
      enable = true;
      allowPasswordAuth = false;
    };

    hardenedSSH = {
      enable = true;
      enableFail2ban = true;
      maxAuthTries = 3;
      maxSessions = 2;
      fail2banMaxRetry = 3;
      fail2banBanTime = 7200;  # 2 hours
    };

    kernelHardening = {
      enable = true;
      enableNetworkHardening = true;
      enableMemoryProtection = true;
      enableProcessRestrictions = true;
      enableAudit = true;
    };

    timeSync = {
      enable = true;
      servers = [
        "time.cloudflare.com"
        "time.google.com"
        "time.nist.gov"
      ];
    };

    resourceLimits = {
      enable = true;
      limitCoredump = true;
      defaultTasksMax = 100;
    };

    vmFirewall = {
      enable = true;
      defaultPolicy = "drop";
      enableEgressFiltering = true;
      logDropped = true;
    };

    intrusionDetection = {
      enable = true;
      enableAIDE = true;
      enableAuditd = true;
      enableProcessAccounting = true;
    };

    systemdHardening.enable = true;
  };

  # Strict password policy
  security.sudo.wheelNeedsPassword = true;

  # Disable all unnecessary services
  services.avahi.enable = false;
  services.printing.enable = false;

  # No mutable users
  users.mutableUsers = false;

  # Strict file permissions
  boot.specialFileSystems."/dev/shm".options = [ "noexec" "nodev" "nosuid" ];
}
