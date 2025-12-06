# Barbican Security Module: Kernel Hardening
# Addresses: MED-001 (kernel not hardened)
# Standards: NIST SI-16, CIS 1.5.x
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.kernelHardening;
in {
  options.barbican.kernelHardening = {
    enable = mkEnableOption "Barbican kernel hardening";

    enableNetworkHardening = mkOption {
      type = types.bool;
      default = true;
      description = "Enable network stack hardening";
    };

    enableMemoryProtection = mkOption {
      type = types.bool;
      default = true;
      description = "Enable memory protection features";
    };

    enableProcessRestrictions = mkOption {
      type = types.bool;
      default = true;
      description = "Enable process restrictions";
    };

    enableAudit = mkOption {
      type = types.bool;
      default = true;
      description = "Enable kernel audit subsystem";
    };
  };

  config = mkIf cfg.enable {
    boot.kernel.sysctl = {}
      // optionalAttrs cfg.enableNetworkHardening {
        # Network hardening
        "net.ipv4.conf.all.rp_filter" = 1;
        "net.ipv4.conf.default.rp_filter" = 1;
        "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
        "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
        "net.ipv4.conf.all.accept_source_route" = 0;
        "net.ipv4.conf.default.accept_source_route" = 0;
        "net.ipv4.conf.all.accept_redirects" = 0;
        "net.ipv4.conf.default.accept_redirects" = 0;
        "net.ipv4.conf.all.secure_redirects" = 0;
        "net.ipv4.conf.default.secure_redirects" = 0;
        "net.ipv4.conf.all.send_redirects" = 0;
        "net.ipv4.conf.default.send_redirects" = 0;
        "net.ipv4.tcp_syncookies" = 1;
        "net.ipv4.tcp_rfc1337" = 1;
        "net.ipv4.conf.all.log_martians" = 1;
        "net.ipv4.conf.default.log_martians" = 1;

        # IPv6 hardening
        "net.ipv6.conf.all.accept_redirects" = 0;
        "net.ipv6.conf.default.accept_redirects" = 0;
        "net.ipv6.conf.all.accept_source_route" = 0;
        "net.ipv6.conf.default.accept_source_route" = 0;
      }
      // optionalAttrs cfg.enableMemoryProtection {
        # Memory protection
        "kernel.randomize_va_space" = 2;
        "kernel.kptr_restrict" = 2;
        "kernel.dmesg_restrict" = 1;
        "kernel.perf_event_paranoid" = 3;
        "vm.mmap_min_addr" = 65536;
      }
      // optionalAttrs cfg.enableProcessRestrictions {
        # Process restrictions
        "fs.suid_dumpable" = 0;
        "kernel.yama.ptrace_scope" = 1;
        "fs.protected_hardlinks" = 1;
        "fs.protected_symlinks" = 1;
        "fs.protected_fifos" = 2;
        "fs.protected_regular" = 2;
      };

    boot.kernelParams = [
      "quiet"
    ] ++ optionals cfg.enableMemoryProtection [
      "slub_debug=F"
      "page_poison=1"
      "vsyscall=none"
      "debugfs=off"
    ] ++ optionals cfg.enableAudit [
      "audit=1"
    ];

    # Enable auditd
    security.auditd.enable = cfg.enableAudit;
    security.audit = mkIf cfg.enableAudit {
      enable = true;
      rules = [
        # Log all executions
        "-a always,exit -F arch=b64 -S execve -k exec"
        # Log privileged commands
        "-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged"
        # Log file deletions
        "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete"
      ];
    };
  };
}
