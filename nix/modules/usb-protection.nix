# Barbican Security Module: USB Device Protection
#
# STIG Implementation:
#   V-268139: Enable USBguard for device management (CM-8)
#   V-268139: Block unauthorized USB devices by default (CM-8(3))
#
# NIST Controls: CM-8, CM-8(3), SC-41
#
# USBguard provides USB device authorization control, protecting against:
# - BadUSB attacks (malicious firmware in USB devices)
# - Unauthorized data exfiltration via USB storage
# - Rubber Ducky / keystroke injection attacks
# - Unauthorized peripheral connections in secure environments
#
# This module is recommended for FedRAMP High and air-gapped deployments.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.usbProtection;

  # Generate policy rules from allowed devices list
  generateRules = devices: concatMapStringsSep "\n" (dev:
    let
      idPart = if dev.vendorId != null && dev.productId != null
        then "id ${dev.vendorId}:${dev.productId}"
        else "";
      namePart = if dev.name != null
        then "name \"${dev.name}\""
        else "";
      serialPart = if dev.serial != null
        then "serial \"${dev.serial}\""
        else "";
      hashPart = if dev.hash != null
        then "hash \"${dev.hash}\""
        else "";
      parts = filter (s: s != "") [ idPart namePart serialPart hashPart ];
    in
      if parts == []
      then "# Invalid device entry (no identifiers)"
      else "allow ${concatStringsSep " " parts}"
  ) devices;
in {
  options.barbican.usbProtection = {
    enable = mkEnableOption "Barbican USB device protection via USBguard";

    defaultPolicy = mkOption {
      type = types.enum [ "block" "allow" "reject" ];
      default = "block";
      description = ''
        Default policy for USB devices not matching any rule.
        - block: Silently block unauthorized devices (recommended for security)
        - reject: Block and notify user
        - allow: Allow all devices (not recommended)
      '';
    };

    allowedDevices = mkOption {
      type = types.listOf (types.submodule {
        options = {
          vendorId = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "1d6b";
            description = "USB vendor ID (4 hex digits)";
          };
          productId = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "0001";
            description = "USB product ID (4 hex digits)";
          };
          name = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "UHCI Host Controller";
            description = "Device name (from lsusb)";
          };
          serial = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Device serial number";
          };
          hash = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Device hash (from usbguard list-devices)";
          };
          description = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Human-readable description of why this device is allowed";
          };
        };
      });
      default = [];
      description = ''
        List of USB devices to allow. Devices not in this list will be
        blocked according to defaultPolicy.

        Use `usbguard list-devices` to enumerate connected devices.
        Use `usbguard generate-policy` to create initial allowlist.
      '';
      example = [
        {
          vendorId = "1d6b";
          productId = "0001";
          name = "UHCI Host Controller";
          description = "Virtual USB controller for QEMU";
        }
        {
          vendorId = "0627";
          productId = "0001";
          name = "QEMU USB Tablet";
          description = "Virtual input device for VM";
        }
      ];
    };

    allowHIDDevices = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Allow Human Interface Devices (keyboards, mice) by default.
        WARNING: Enabling this reduces protection against keystroke injection attacks.
        Only enable if you need to support dynamic keyboard/mouse connections.
      '';
    };

    allowHostControllers = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Allow USB host controllers (internal USB hubs).
        These are typically required for USB to function at all.
      '';
    };

    auditOnly = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Audit mode: log unauthorized devices but don't block them.
        Useful for initial deployment to build an allowlist.
      '';
    };

    customRules = mkOption {
      type = types.lines;
      default = "";
      description = ''
        Custom USBguard rules to append to the policy.
        See usbguard-rules.conf(5) for syntax.
      '';
      example = ''
        # Allow all devices from specific vendor
        allow id 046d:*
        # Block all mass storage devices
        reject with-interface equals { 08:*:* }
      '';
    };
  };

  config = mkIf cfg.enable {
    # Install USBguard
    services.usbguard = {
      enable = true;

      # Implicit policy target for devices not matching any rule
      implicitPolicyTarget = cfg.defaultPolicy;

      # Generate policy rules
      rules = concatStringsSep "\n" (filter (s: s != "") [
        "# Barbican USB Protection Policy"
        "# Generated from barbican.usbProtection configuration"
        ""
        (optionalString cfg.allowHostControllers ''
          # Allow USB host controllers (required for USB functionality)
          allow with-interface equals { 09:00:* }
        '')
        (optionalString cfg.allowHIDDevices ''
          # Allow HID devices (keyboards, mice)
          # WARNING: This reduces protection against keystroke injection
          allow with-interface one-of { 03:00:* 03:01:* }
        '')
        ""
        "# Explicitly allowed devices"
        (generateRules cfg.allowedDevices)
        ""
        (optionalString (cfg.customRules != "") ''
          # Custom rules
          ${cfg.customRules}
        '')
      ]);

      # Presentation policy (what happens when a device is blocked)
      presentDevicePolicy = if cfg.auditOnly then "allow" else cfg.defaultPolicy;
      presentControllerPolicy = if cfg.allowHostControllers then "allow" else cfg.defaultPolicy;
    };

    # Ensure USBguard is started early in boot
    systemd.services.usbguard = {
      wantedBy = [ "multi-user.target" ];
      before = [ "display-manager.service" "sshd.service" ];
    };

    # Add audit logging for blocked devices
    services.usbguard.IPCAllowedGroups = [ "wheel" ];

    # Log USB events to syslog for audit trail (AU-2)
    environment.etc."usbguard/usbguard-daemon.conf".text = mkAfter ''
      # Audit logging (AU-2, AU-3)
      AuditBackend=LinuxAudit
    '';
  };
}
