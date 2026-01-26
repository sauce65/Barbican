{
  description = "Barbican - NIST 800-53 Compliant Security Infrastructure for Rust and NixOS";

  # =============================================================================
  # SECURITY: Flake Input Audit Trail
  # =============================================================================
  # All inputs are locked in flake.lock with content-addressed hashes (narHash)
  # which prevents MITM attacks and ensures reproducibility.
  #
  # Audit date: 2025-12-15
  # Auditor: Claude (automated security review)
  #
  # To update inputs: nix flake update
  # To update single input: nix flake lock --update-input nixpkgs
  # To verify: nix flake metadata
  # =============================================================================

  inputs = {
    # SECURITY: Using nixos-24.11 stable for production reliability
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-24.11";

    # Audited: github.com/numtide/flake-utils (1.2k+ stars)
    flake-utils.url = "github:numtide/flake-utils";

    # Audited: github.com/oxalica/rust-overlay (900+ stars)
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    let
      # =========================================================================
      # NixOS Modules (system-agnostic)
      # =========================================================================
      nixosModules = {
        # Individual security modules
        secureUsers = import ./nix/modules/secure-users.nix;
        securePostgres = import ./nix/modules/secure-postgres.nix;
        hardenedSSH = import ./nix/modules/hardened-ssh.nix;
        hardenedNginx = import ./nix/modules/hardened-nginx.nix;
        secretsManagement = import ./nix/modules/secrets-management.nix;
        observability = import ./nix/modules/observability.nix;        # SI-4, AU-6
        observabilityAuth = import ./nix/modules/observability-auth.nix;
        vmFirewall = import ./nix/modules/vm-firewall.nix;
        databaseBackup = import ./nix/modules/database-backup.nix;
        resourceLimits = import ./nix/modules/resource-limits.nix;
        kernelHardening = import ./nix/modules/kernel-hardening.nix;
        timeSync = import ./nix/modules/time-sync.nix;
        intrusionDetection = import ./nix/modules/intrusion-detection.nix;
        systemdHardening = import ./nix/modules/systemd-hardening.nix;
        vaultPki = import ./nix/modules/vault-pki.nix;
        doctor = import ./nix/modules/doctor.nix;                      # CM-4, SI-6
        oidcProvider = import ./nix/modules/oidc-provider.nix;         # IA-2, AC-2
        keycloakVm = import ./nix/modules/keycloak-vm.nix;            # IA-2, FAPI 2.0
        cluster = import ./nix/modules/cluster.nix;                    # SC-7, SC-32, AC-4
        clusterOutput = import ./nix/modules/cluster-output.nix;       # Cluster deployment artifacts
        usbProtection = import ./nix/modules/usb-protection.nix;       # CM-8, SC-41: USBguard
        mandatoryAccessControl = import ./nix/modules/mandatory-access-control.nix; # AC-3(3): AppArmor
        logForwarding = import ./nix/modules/log-forwarding.nix;      # AU-4, AU-6, SI-4
        vulnerabilityScanning = import ./nix/modules/vulnerability-scanning.nix; # RA-5, SI-2
        auditArchival = import ./nix/modules/audit-archival.nix;      # AU-9(2), AU-11

        # FedRAMP Security Profiles (align with Rust ComplianceProfile enum)
        # These profiles match the *_for_profile() functions in src/integration.rs
        fedrampLow = import ./nix/profiles/fedramp-low.nix;           # Basic security
        fedrampModerate = import ./nix/profiles/fedramp-moderate.nix; # Standard (most common)
        fedrampHigh = import ./nix/profiles/fedramp-high.nix;         # Maximum security
        development = import ./nix/profiles/development.nix;          # Local dev only

        # All modules combined (for easy import)
        all =
          { ... }:
          {
            imports = [
              ./nix/modules/secure-users.nix
              ./nix/modules/secure-postgres.nix
              ./nix/modules/hardened-ssh.nix
              ./nix/modules/hardened-nginx.nix
              ./nix/modules/secrets-management.nix
              ./nix/modules/observability.nix
              ./nix/modules/observability-auth.nix
              ./nix/modules/vm-firewall.nix
              ./nix/modules/database-backup.nix
              ./nix/modules/resource-limits.nix
              ./nix/modules/kernel-hardening.nix
              ./nix/modules/time-sync.nix
              ./nix/modules/intrusion-detection.nix
              ./nix/modules/systemd-hardening.nix
              ./nix/modules/vault-pki.nix
              ./nix/modules/doctor.nix
              ./nix/modules/oidc-provider.nix
              ./nix/modules/keycloak-vm.nix
              ./nix/modules/cluster.nix
              ./nix/modules/cluster-output.nix
              ./nix/modules/usb-protection.nix
              ./nix/modules/mandatory-access-control.nix
              ./nix/modules/log-forwarding.nix
              ./nix/modules/vulnerability-scanning.nix
              ./nix/modules/audit-archival.nix
            ];
          };
      };

      # Helper library (system-agnostic)
      lib = {
        networkZones = import ./nix/lib/network-zones.nix { lib = nixpkgs.lib; };
        pki = import ./nix/lib/pki.nix { lib = nixpkgs.lib; };
        systemdHardening = import ./nix/lib/systemd-hardening-lib.nix { lib = nixpkgs.lib; };

        # Keycloak FAPI 2.0 libraries
        keycloak = {
          fapi = import ./nix/lib/keycloak-fapi.nix { lib = nixpkgs.lib; };
          realm = import ./nix/lib/keycloak-realm-json.nix { lib = nixpkgs.lib; };
        };

        # Cluster orchestration libraries (VM-centric, for QEMU deployments)
        cluster = rec {
          constraints = import ./nix/lib/cluster-constraints.nix { lib = nixpkgs.lib; };
          images = import ./nix/lib/cluster-images.nix { lib = nixpkgs.lib; };
          resolver = import ./nix/lib/cluster-resolver.nix { lib = nixpkgs.lib; };
          builder = import ./nix/lib/cluster-mkCluster.nix { lib = nixpkgs.lib; };

          # Main entry point for creating clusters
          inherit (builder) mkCluster;
        };

        # Topology validation libraries (deployment-target agnostic)
        # Use these for validating EC2, bare-metal, or any multi-machine topology
        topology = import ./nix/lib/topology-validator.nix { lib = nixpkgs.lib; };
        isolation = import ./nix/lib/isolation-boundaries.nix { lib = nixpkgs.lib; };
      };

    in
    {
      inherit nixosModules lib;

      # Project templates
      templates = {
        microvm-stack = {
          path = ./templates/microvm-stack;
          description = "Secure MicroVM stack with Barbican hardening";
        };
      };
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];

        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfreePredicate = pkg: builtins.elem (nixpkgs.lib.getName pkg) [ "vault" ];
        };

        pkgsWithVault = pkgs; # Already has vault allowed

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
        };

        # Import modular components
        packages = import ./nix/package.nix { inherit pkgs; };

        checks = import ./nix/checks.nix {
          inherit pkgs pkgsWithVault;
          inherit (nixpkgs) lib;
          flakeLockPath = ./flake.lock;
          cargoLockPath = ./Cargo.lock;
        };

        apps = import ./nix/apps.nix {
          inherit pkgs self system;
          observabilityStackGenerator = packages.observability-stack-generator;
        };

      in
      {
        # Packages
        packages = {
          default = packages.default;
          barbican = packages.default;
          observability-stack-generator = packages.observability-stack-generator;
        };

        # Development shell
        devShells.default = import ./nix/devshell.nix { inherit pkgs rustToolchain; };

        # Security checks and VM tests
        inherit checks;

        # Runnable apps
        inherit apps;
      }
    );

  # =============================================================================
  # SECURITY: Binary Cache Trust Model
  # =============================================================================
  # By default, Nix trusts cache.nixos.org which is maintained by the NixOS
  # Foundation. All packages are built reproducibly and signed.
  #
  # For production deployments, consider:
  # 1. Running your own binary cache (nix-serve, cachix, attic)
  # 2. Building all packages locally (slower but no external trust)
  # 3. Explicitly configuring trusted substituters in nix.conf
  #
  # To build without binary cache: nix build --option substitute false
  # To verify cache signatures: nix path-info --sigs /nix/store/...
  # =============================================================================
}
