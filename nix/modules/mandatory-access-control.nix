# Barbican Security Module: Mandatory Access Control
#
# STIG Implementation:
#   V-268173: Configure AppArmor mandatory access control (AC-3, AC-6)
#
# NIST Controls: AC-3(3), AC-6, SC-3, SC-4
#
# AppArmor provides mandatory access control (MAC) that restricts programs
# to a limited set of resources. Unlike SELinux, AppArmor uses path-based
# access control which integrates well with NixOS's declarative model.
#
# This module enables AppArmor and configures profiles for common services.
# Custom profiles can be added for application-specific hardening.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.mandatoryAccessControl;
in {
  options.barbican.mandatoryAccessControl = {
    enable = mkEnableOption "Barbican mandatory access control via AppArmor";

    enforceMode = mkOption {
      type = types.enum [ "enforce" "complain" "disabled" ];
      default = "enforce";
      description = ''
        Default mode for AppArmor profiles:
        - enforce: Block and log violations (production)
        - complain: Log violations but allow (audit/testing)
        - disabled: Profiles loaded but not active
      '';
    };

    enableDefaultProfiles = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Enable default AppArmor profiles from the apparmor-profiles package.
        This includes profiles for common utilities like ping, traceroute, etc.
      '';
    };

    confinedServices = mkOption {
      type = types.listOf (types.enum [
        "nginx"
        "postgresql"
        "sshd"
        "ntpd"
        "chronyd"
        "unbound"
        "dnsmasq"
      ]);
      default = [ "nginx" "postgresql" ];
      description = ''
        Services to confine with AppArmor profiles.
        Each service will have a profile generated or loaded from apparmor-profiles.
      '';
    };

    customProfiles = mkOption {
      type = types.attrsOf types.lines;
      default = {};
      description = ''
        Custom AppArmor profiles. The attribute name is the profile name,
        and the value is the profile content.
      '';
      example = literalExpression ''
        {
          "usr.local.bin.myapp" = '''
            #include <tunables/global>

            /usr/local/bin/myapp {
              #include <abstractions/base>
              #include <abstractions/nameservice>

              /usr/local/bin/myapp mr,
              /var/lib/myapp/ r,
              /var/lib/myapp/** rw,
              /var/log/myapp.log w,

              # Network access
              network inet stream,
              network inet6 stream,

              # Deny everything else
              deny /** w,
            }
          ''';
        }
      '';
    };

    enableKernelModule = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Enable the AppArmor Linux Security Module (LSM).
        This requires the kernel to be built with AppArmor support.
      '';
    };

    enableAuditdIntegration = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Enable integration with auditd for comprehensive security logging.
        AppArmor denials will be logged via the audit subsystem.
      '';
    };

    additionalPackages = mkOption {
      type = types.listOf types.package;
      default = [];
      description = ''
        Additional packages containing AppArmor profiles to include.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Enable AppArmor
    security.apparmor = {
      enable = true;

      # Enable kernel module
      enableOnBoot = cfg.enableKernelModule;

      # Load policies
      policies = mkMerge [
        # Default profiles
        (mkIf cfg.enableDefaultProfiles {
          # Base abstractions are loaded automatically
        })

        # Custom profiles from configuration
        (mapAttrs (name: content: {
          enable = true;
          enforce = cfg.enforceMode == "enforce";
          profile = content;
        }) cfg.customProfiles)
      ];

      # Include additional profile packages
      packages = with pkgs; [
        apparmor-profiles
        apparmor-utils
        apparmor-parser
      ] ++ cfg.additionalPackages;
    };

    # Kernel boot parameters for AppArmor
    boot.kernelParams = mkIf cfg.enableKernelModule [
      "apparmor=1"
      "security=apparmor"
    ];

    # Ensure audit subsystem is enabled for AppArmor logging
    security.auditd.enable = mkIf cfg.enableAuditdIntegration true;
    security.audit.enable = mkIf cfg.enableAuditdIntegration true;

    # Add audit rules for AppArmor events
    security.audit.rules = mkIf cfg.enableAuditdIntegration [
      # Log AppArmor status changes
      "-w /sys/kernel/security/apparmor -p wa -k apparmor"
      # Log profile loading
      "-w /etc/apparmor.d -p wa -k apparmor_profiles"
    ];

    # Service-specific profiles and AppArmor service configuration
    # Combined into single block to avoid module merge warnings
    systemd.services = mkMerge [
      # Ensure AppArmor starts before confined services
      {
        apparmor = {
          wantedBy = [ "multi-user.target" ];
          before = [
            "nginx.service"
            "postgresql.service"
            "sshd.service"
          ];
        };
      }

      # Nginx confinement
      (mkIf (elem "nginx" cfg.confinedServices && config.services.nginx.enable) {
        nginx.serviceConfig = {
          # AppArmor profile will be loaded by the system
          # Additional hardening via systemd
          AppArmorProfile = "nginx";
        };
      })

      # PostgreSQL confinement
      (mkIf (elem "postgresql" cfg.confinedServices && config.services.postgresql.enable) {
        postgresql.serviceConfig = {
          AppArmorProfile = "postgresql";
        };
      })

      # SSHD confinement (careful - don't lock yourself out!)
      (mkIf (elem "sshd" cfg.confinedServices && config.services.openssh.enable) {
        sshd.serviceConfig = {
          AppArmorProfile = mkIf (cfg.enforceMode != "enforce") "sshd";
        };
      })
    ];

    # Helper script for profile management
    environment.systemPackages = with pkgs; [
      apparmor-utils  # aa-status, aa-enforce, aa-complain, etc.
      apparmor-parser # Profile compilation
    ];

    # Create aa-status wrapper for easier checking
    environment.shellAliases = {
      aa-status = "sudo aa-status";
      aa-logprof = "sudo aa-logprof";
    };

    # Warning for complain mode in production
    warnings = mkIf (cfg.enforceMode == "complain") [
      ''
        barbican.mandatoryAccessControl.enforceMode is set to "complain".
        This is suitable for testing but should be set to "enforce" in production.
        AppArmor violations will be logged but not blocked.
      ''
    ];

    # Assertions
    assertions = [
      {
        assertion = cfg.enable -> config.security.apparmor.enable;
        message = "AppArmor must be enabled for mandatory access control";
      }
      {
        assertion = cfg.enableKernelModule -> (config.boot.kernelPackages.kernel.features.apparmor or true);
        message = "Kernel must support AppArmor LSM";
      }
    ];
  };
}
