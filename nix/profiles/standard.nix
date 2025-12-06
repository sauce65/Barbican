# Barbican Standard Security Profile
# For staging and internal production environments
# Balanced security with operational convenience
{ config, lib, ... }:

{
  imports = [
    ../modules/secure-users.nix
    ../modules/hardened-ssh.nix
    ../modules/kernel-hardening.nix
    ../modules/time-sync.nix
    ../modules/resource-limits.nix
    ../modules/vm-firewall.nix
  ];

  barbican = {
    secureUsers.enable = true;

    hardenedSSH = {
      enable = true;
      enableFail2ban = true;
      maxAuthTries = 5;
    };

    kernelHardening = {
      enable = true;
      enableNetworkHardening = true;
      enableMemoryProtection = true;
      enableProcessRestrictions = true;
      enableAudit = true;
    };

    timeSync.enable = true;

    resourceLimits = {
      enable = true;
      limitCoredump = true;
    };

    vmFirewall = {
      enable = true;
      defaultPolicy = "drop";
      logDropped = true;
    };
  };

  # Standard hardening
  security.sudo.wheelNeedsPassword = true;

  # Disable unnecessary services
  services.avahi.enable = false;
}
