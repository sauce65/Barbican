# Barbican NixOS Modules Index
# NIST 800-53 Compliant Security Infrastructure
{
  secureUsers = import ./secure-users.nix;
  securePostgres = import ./secure-postgres.nix;
  hardenedSSH = import ./hardened-ssh.nix;
  hardenedNginx = import ./hardened-nginx.nix;  # SC-8, IA-3: Reverse Proxy
  secretsManagement = import ./secrets-management.nix;
  observability = import ./observability.nix;  # SI-4, AU-6: Full observability stack
  observabilityAuth = import ./observability-auth.nix;
  vmFirewall = import ./vm-firewall.nix;
  databaseBackup = import ./database-backup.nix;
  resourceLimits = import ./resource-limits.nix;
  kernelHardening = import ./kernel-hardening.nix;
  timeSync = import ./time-sync.nix;
  intrusionDetection = import ./intrusion-detection.nix;
  systemdHardening = import ./systemd-hardening.nix;
  vaultPki = import ./vault-pki.nix;  # SC-12, SC-17: PKI/Key Management
  doctor = import ./doctor.nix;  # CM-4, SI-6: Diagnostic health checks
  oidcProvider = import ./oidc-provider.nix;  # IA-2, AC-2: OIDC/Keycloak
}
