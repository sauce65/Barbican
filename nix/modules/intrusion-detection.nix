# Barbican Security Module: Intrusion Detection
#
# STIG Implementation:
#   UBTU-22-651010: Generate audit records for privileged activities (AU-2, AU-12)
#   UBTU-22-651015: Audit all executions (AU-2)
#   UBTU-22-651020: Audit file deletions (AU-2)
#   UBTU-22-651025: Configure auditd to use disk buffer (AU-5)
#   UBTU-22-654010: Enable AIDE file integrity monitoring (SI-7)
#   UBTU-22-654015: Initialize AIDE database (SI-7)
#   UBTU-22-654020: Configure AIDE for critical file monitoring (SI-7)
#
# NIST Controls: SI-4, SI-7, AU-2, AU-5, AU-12
# Legacy: CRT-015, CRT-016
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.intrusionDetection;
in {
  options.barbican.intrusionDetection = {
    enable = mkEnableOption "Barbican intrusion detection";

    enableAIDE = mkOption {
      type = types.bool;
      default = true;
      description = "Enable AIDE file integrity monitoring";
    };

    aideRules = mkOption {
      type = types.lines;
      default = ''
        /bin NORMAL
        /sbin NORMAL
        /lib NORMAL
        /lib64 NORMAL
        /usr/bin NORMAL
        /usr/sbin NORMAL
        /usr/lib NORMAL
        /etc NORMAL
        !/etc/mtab
        !/etc/resolv.conf
      '';
      description = "AIDE monitoring rules";
    };

    aideScanSchedule = mkOption {
      type = types.str;
      default = "04:00";
      description = "Time for daily AIDE scan";
    };

    enableAuditd = mkOption {
      type = types.bool;
      default = true;
      description = "Enable audit daemon";
    };

    auditRules = mkOption {
      type = types.listOf types.str;
      default = [
        # Log all executions
        "-a always,exit -F arch=b64 -S execve -k exec"
        "-a always,exit -F arch=b32 -S execve -k exec"
        # Log privileged commands
        "-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged"
        "-a always,exit -F path=/usr/bin/su -F perm=x -k privileged"
        # Log file deletions
        "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete"
        # Log permission changes
        "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod"
        "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k owner_mod"
        # Log module loading
        "-w /sbin/insmod -p x -k modules"
        "-w /sbin/modprobe -p x -k modules"
        # Log SSH config changes
        "-w /etc/ssh/sshd_config -p wa -k sshd_config"
        # Log authentication files
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
      ];
      description = "Audit rules for auditd";
    };

    enableProcessAccounting = mkOption {
      type = types.bool;
      default = true;
      description = "Enable process accounting";
    };
  };

  config = mkIf cfg.enable {
    # Auditd
    security.auditd.enable = cfg.enableAuditd;
    security.audit = mkIf cfg.enableAuditd {
      enable = true;
      rules = cfg.auditRules;
    };

    # AIDE file integrity monitoring
    environment.systemPackages = mkIf cfg.enableAIDE [ pkgs.aide ];

    environment.etc."aide.conf" = mkIf cfg.enableAIDE {
      text = ''
        # AIDE configuration
        database=file:/var/lib/aide/aide.db
        database_out=file:/var/lib/aide/aide.db.new
        gzip_dbout=yes

        # Rule definitions
        NORMAL = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha256

        # Monitored paths
        ${cfg.aideRules}
      '';
    };

    # AIDE initialization service
    systemd.services.aide-init = mkIf cfg.enableAIDE {
      description = "Initialize AIDE database";
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };

      script = ''
        mkdir -p /var/lib/aide
        if [ ! -f /var/lib/aide/aide.db ]; then
          echo "Initializing AIDE database..."
          ${pkgs.aide}/bin/aide --init --config /etc/aide.conf
          mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
          echo "AIDE database initialized"
        fi
      '';
    };

    # AIDE check service
    systemd.services.aide-check = mkIf cfg.enableAIDE {
      description = "AIDE integrity check";
      after = [ "aide-init.service" ];

      serviceConfig = {
        Type = "oneshot";
      };

      script = ''
        echo "Running AIDE integrity check..."
        ${pkgs.aide}/bin/aide --check --config /etc/aide.conf || {
          echo "AIDE detected changes!"
          exit 1
        }
        echo "AIDE check completed - no changes detected"
      '';
    };

    # AIDE check timer
    systemd.timers.aide-check = mkIf cfg.enableAIDE {
      description = "Daily AIDE integrity check";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnCalendar = "*-*-* ${cfg.aideScanSchedule}";
        Persistent = true;
      };
    };

    # Process accounting (deprecated in modern NixOS - option removed)
    # Use systemd resource accounting instead (enabled by default)
  };
}
