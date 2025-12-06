# Barbican NixOS Modules Index
# NIST 800-53 Compliant Security Infrastructure
{
  secureUsers = import ./secure-users.nix;
  securePostgres = import ./secure-postgres.nix;
  hardenedSSH = import ./hardened-ssh.nix;
  secretsManagement = import ./secrets-management.nix;
  observabilityAuth = import ./observability-auth.nix;
  vmFirewall = import ./vm-firewall.nix;
  databaseBackup = import ./database-backup.nix;
  resourceLimits = import ./resource-limits.nix;
  kernelHardening = import ./kernel-hardening.nix;
  timeSync = import ./time-sync.nix;
  intrusionDetection = import ./intrusion-detection.nix;
  systemdHardening = import ./systemd-hardening.nix;
}
