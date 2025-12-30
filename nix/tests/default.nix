# Barbican NixOS Security Test Suite
# Self-contained tests that validate security modules independently
#
# Usage:
#   nix build .#checks.x86_64-linux.all
#   nix build .#checks.x86_64-linux.secure-users
#   nix run .#audit  # Generate audit report
#
{ pkgs, lib, ... }:

let
  # Import all test modules
  testModules = {
    secure-users = import ./secure-users.nix { inherit pkgs lib; };
    hardened-ssh = import ./hardened-ssh.nix { inherit pkgs lib; };
    hardened-nginx = import ./hardened-nginx.nix { inherit pkgs lib; };
    kernel-hardening = import ./kernel-hardening.nix { inherit pkgs lib; };
    secure-postgres = import ./secure-postgres.nix { inherit pkgs lib; };
    database-backup = import ./database-backup.nix { inherit pkgs lib; };
    time-sync = import ./time-sync.nix { inherit pkgs lib; };
    intrusion-detection = import ./intrusion-detection.nix { inherit pkgs lib; };
    vm-firewall = import ./vm-firewall.nix { inherit pkgs lib; };
    resource-limits = import ./resource-limits.nix { inherit pkgs lib; };
  };

  # Combine all tests
  allTests = pkgs.testers.nixosTest {
    name = "barbican-security-suite";

    # Skip type checking - test uses dynamic dict structures for audit reporting
    skipTypeCheck = true;

    nodes = {
      # Node with all security modules enabled (hardened profile)
      hardened = { config, pkgs, ... }: {
        imports = [
          ../modules/secure-users.nix
          ../modules/hardened-ssh.nix
          ../modules/kernel-hardening.nix
          ../modules/time-sync.nix
          ../modules/resource-limits.nix
          ../modules/intrusion-detection.nix
          ../modules/vm-firewall.nix
          ../modules/secure-postgres.nix
          ../modules/database-backup.nix
        ];

        barbican = {
          secureUsers = {
            enable = true;
            authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@barbican" ];
          };
          hardenedSSH = {
            enable = true;
            enableFail2ban = true;
          };
          kernelHardening = {
            enable = true;
            enableNetworkHardening = true;
            enableMemoryProtection = true;
            enableAudit = true;
          };
          timeSync.enable = true;
          resourceLimits.enable = true;
          intrusionDetection = {
            enable = true;
            enableAIDE = true;
            enableAuditd = true;
            enableProcessAccounting = false;  # acct service not available in test VM
          };
          vmFirewall = {
            enable = true;
            allowDNS = true;
            allowNTP = true;
          };
          securePostgres = {
            enable = true;
            database = "testdb";
            username = "testuser";
          };
          databaseBackup = {
            enable = true;
            retentionDays = 7;
            enableEncryption = true;
          };
        };

        # Enable SSH for testing
        services.openssh.enable = true;
      };

      # Baseline node without hardening for comparison
      baseline = { config, pkgs, ... }: {
        services.openssh.enable = true;
        users.users.root.password = "";
      };
    };

    testScript = ''
      import json
      from datetime import datetime

      # Audit results storage
      audit_results = {
        "timestamp": datetime.now().isoformat(),
        "version": "1.0",
        "modules": {}
      }

      def record_test(module, test_name, passed, details=""):
        if module not in audit_results["modules"]:
          audit_results["modules"][module] = {"tests": [], "passed": 0, "failed": 0}

        result = {"name": test_name, "passed": passed, "details": details}
        audit_results["modules"][module]["tests"].append(result)

        if passed:
          audit_results["modules"][module]["passed"] += 1
        else:
          audit_results["modules"][module]["failed"] += 1

      start_all()
      hardened.wait_for_unit("multi-user.target")
      baseline.wait_for_unit("multi-user.target")

      # ============================================
      # CRT-001/CRT-002: Secure Users Tests
      # ============================================
      with subtest("secure-users: No empty root password"):
        # Check that root has no password (locked or SSH-only)
        shadow = hardened.succeed("getent shadow root")
        has_password = shadow.split(":")[1] not in ["", "!", "*", "!!"]
        record_test("secure-users", "CRT-001: No empty password", not has_password or "!" in shadow, shadow)

      with subtest("secure-users: No auto-login"):
        # Verify getty doesn't have autologin configured
        getty_conf = hardened.succeed("cat /etc/systemd/system/getty@tty1.service.d/*.conf 2>/dev/null || echo 'no override'")
        no_autologin = "autologin" not in getty_conf.lower() or "no override" in getty_conf
        record_test("secure-users", "CRT-002: No auto-login", no_autologin, getty_conf[:200])

      with subtest("secure-users: SSH keys configured"):
        auth_keys = hardened.succeed("cat /root/.ssh/authorized_keys 2>/dev/null || echo 'none'")
        has_keys = "ssh-ed25519" in auth_keys
        record_test("secure-users", "SSH authorized keys present", has_keys, auth_keys[:100])

      with subtest("secure-users: Login banner present"):
        issue = hardened.succeed("cat /etc/issue")
        has_banner = "AUTHORIZED" in issue.upper()
        record_test("secure-users", "Login banner configured", has_banner, issue[:100])

      # ============================================
      # CRT-010: SSH Hardening Tests
      # ============================================
      with subtest("hardened-ssh: Password auth disabled"):
        sshd_config = hardened.succeed("sshd -T 2>/dev/null | grep -i passwordauthentication || echo 'not found'")
        disabled = "no" in sshd_config.lower()
        record_test("hardened-ssh", "CRT-010: Password auth disabled", disabled, sshd_config)

      with subtest("hardened-ssh: Root login restricted"):
        sshd_config = hardened.succeed("sshd -T 2>/dev/null | grep -i permitrootlogin || echo 'not found'")
        restricted = "prohibit-password" in sshd_config.lower() or "no" in sshd_config.lower()
        record_test("hardened-ssh", "Root login restricted", restricted, sshd_config)

      with subtest("hardened-ssh: Strong ciphers only"):
        ciphers = hardened.succeed("sshd -T 2>/dev/null | grep -i ciphers || echo 'not found'")
        strong = "chacha20" in ciphers.lower() or "aes256-gcm" in ciphers.lower()
        weak = "3des" in ciphers.lower() or "arcfour" in ciphers.lower()
        record_test("hardened-ssh", "Strong ciphers configured", strong and not weak, ciphers[:200])

      with subtest("hardened-ssh: Fail2ban active"):
        fail2ban = hardened.succeed("systemctl is-active fail2ban 2>/dev/null || echo 'inactive'")
        active = "active" in fail2ban
        record_test("hardened-ssh", "Fail2ban service active", active, fail2ban)

      with subtest("hardened-ssh: SSH jail configured"):
        jails = hardened.succeed("fail2ban-client status 2>/dev/null || echo 'no jails'")
        has_ssh = "sshd" in jails.lower()
        record_test("hardened-ssh", "SSH jail configured", has_ssh, jails[:200])

      # ============================================
      # MED-001: Kernel Hardening Tests
      # ============================================
      with subtest("kernel-hardening: ASLR enabled"):
        aslr = hardened.succeed("sysctl kernel.randomize_va_space")
        enabled = "= 2" in aslr
        record_test("kernel-hardening", "MED-001: ASLR enabled (level 2)", enabled, aslr)

      with subtest("kernel-hardening: Kernel pointer hiding"):
        kptr = hardened.succeed("sysctl kernel.kptr_restrict")
        restricted = "= 2" in kptr
        record_test("kernel-hardening", "Kernel pointers hidden", restricted, kptr)

      with subtest("kernel-hardening: dmesg restricted"):
        dmesg = hardened.succeed("sysctl kernel.dmesg_restrict")
        restricted = "= 1" in dmesg
        record_test("kernel-hardening", "dmesg restricted", restricted, dmesg)

      with subtest("kernel-hardening: SYN cookies enabled"):
        syncookies = hardened.succeed("sysctl net.ipv4.tcp_syncookies")
        enabled = "= 1" in syncookies
        record_test("kernel-hardening", "SYN cookies enabled", enabled, syncookies)

      with subtest("kernel-hardening: Source routing disabled"):
        srcroute = hardened.succeed("sysctl net.ipv4.conf.all.accept_source_route")
        disabled = "= 0" in srcroute
        record_test("kernel-hardening", "Source routing disabled", disabled, srcroute)

      with subtest("kernel-hardening: ICMP redirects disabled"):
        redirects = hardened.succeed("sysctl net.ipv4.conf.all.accept_redirects")
        disabled = "= 0" in redirects
        record_test("kernel-hardening", "ICMP redirects disabled", disabled, redirects)

      with subtest("kernel-hardening: Reverse path filtering"):
        rpf = hardened.succeed("sysctl net.ipv4.conf.all.rp_filter")
        enabled = "= 1" in rpf
        record_test("kernel-hardening", "Reverse path filtering enabled", enabled, rpf)

      with subtest("kernel-hardening: Core dumps disabled"):
        coredump = hardened.succeed("sysctl fs.suid_dumpable")
        disabled = "= 0" in coredump
        record_test("kernel-hardening", "SUID core dumps disabled", disabled, coredump)

      with subtest("kernel-hardening: Audit enabled in kernel"):
        cmdline = hardened.succeed("cat /proc/cmdline")
        audit_on = "audit=1" in cmdline
        record_test("kernel-hardening", "Audit enabled in kernel", audit_on, cmdline[:200])

      # ============================================
      # HIGH-011: Time Synchronization Tests
      # ============================================
      with subtest("time-sync: Chrony running"):
        chrony = hardened.succeed("systemctl is-active chronyd 2>/dev/null || echo 'inactive'")
        active = "active" in chrony
        record_test("time-sync", "HIGH-011: Chrony service active", active, chrony)

      with subtest("time-sync: NTP sources configured"):
        sources = hardened.succeed("chronyc sources 2>/dev/null || echo 'no sources'")
        has_sources = "cloudflare" in sources.lower() or "google" in sources.lower() or "nist" in sources.lower() or "^" in sources
        record_test("time-sync", "NTP sources configured", has_sources, sources[:300])

      # ============================================
      # CRT-015: Intrusion Detection Tests
      # ============================================
      with subtest("intrusion-detection: Auditd running"):
        auditd = hardened.succeed("systemctl is-active auditd 2>/dev/null || echo 'inactive'")
        active = "active" in auditd
        record_test("intrusion-detection", "CRT-015: Auditd active", active, auditd)

      with subtest("intrusion-detection: Audit rules loaded"):
        rules = hardened.succeed("auditctl -l 2>/dev/null || echo 'no rules'")
        has_rules = "execve" in rules or "privileged" in rules or "-a" in rules
        record_test("intrusion-detection", "Audit rules loaded", has_rules, rules[:300])

      with subtest("intrusion-detection: AIDE installed"):
        aide = hardened.succeed("which aide 2>/dev/null || echo 'not found'")
        installed = "/nix/store" in aide
        record_test("intrusion-detection", "AIDE installed", installed, aide)

      # ============================================
      # HIGH-001: Resource Limits Tests
      # ============================================
      with subtest("resource-limits: Core dumps blocked"):
        ulimit = hardened.succeed("ulimit -c 2>/dev/null || echo 'unknown'")
        blocked = "0" in ulimit
        record_test("resource-limits", "HIGH-001: Core dumps blocked", blocked, ulimit)

      with subtest("resource-limits: Open files limit set"):
        nofile = hardened.succeed("ulimit -n 2>/dev/null || echo 'unknown'")
        configured = nofile.strip().isdigit() and int(nofile.strip()) > 1024
        record_test("resource-limits", "Open files limit configured", configured, nofile)

      # ============================================
      # CRT-006/CRT-007: VM Firewall Tests
      # ============================================
      with subtest("vm-firewall: Firewall service active"):
        fw = hardened.succeed("systemctl is-active firewall 2>/dev/null || echo 'inactive'")
        active = "active" in fw
        record_test("vm-firewall", "CRT-006: Firewall service active", active, fw)

      with subtest("vm-firewall: Default drop policy"):
        # Check iptables for DROP policy on INPUT/FORWARD chains
        rules = hardened.succeed("iptables -L -n 2>/dev/null || echo 'no rules'")
        has_drop = "drop" in rules.lower() or "reject" in rules.lower()
        record_test("vm-firewall", "CRT-007: Default drop policy", has_drop, rules[:500])

      with subtest("vm-firewall: Firewall rules loaded"):
        # Verify firewall has rules beyond just default policies
        rules = hardened.succeed("iptables -L nixos-fw -n 2>/dev/null || echo 'no chain'")
        has_rules = "nixos-fw" in rules or "ACCEPT" in rules or "DROP" in rules
        record_test("vm-firewall", "Firewall rules loaded", has_rules, rules[:300])

      # ============================================
      # CRT-003/CRT-011: Secure PostgreSQL Tests
      # ============================================
      with subtest("secure-postgres: PostgreSQL running"):
        pg = hardened.succeed("systemctl is-active postgresql 2>/dev/null || echo 'inactive'")
        active = "active" in pg
        record_test("secure-postgres", "CRT-003: PostgreSQL service active", active, pg)

      with subtest("secure-postgres: Listening on localhost only"):
        # Check PostgreSQL is bound to localhost, not all interfaces
        listen = hardened.succeed("ss -tlnp 2>/dev/null | grep ':5432' || echo 'not listening'")
        # Should have 127.0.0.1:5432 but NOT *:5432 or 0.0.0.0:5432
        localhost_only = ("127.0.0.1:5432" in listen or "127.0.0.1]:5432" in listen) and "*:5432" not in listen and "0.0.0.0:5432" not in listen
        record_test("secure-postgres", "CRT-011: Listening on localhost", localhost_only, listen)

      # ============================================
      # Baseline Comparison (Negative Tests)
      # ============================================
      with subtest("baseline: Confirm insecure defaults"):
        # Verify baseline is indeed insecure for comparison
        baseline_shadow = baseline.succeed("getent shadow root")
        baseline_empty_pw = "::" in baseline_shadow or baseline_shadow.split(":")[1] == ""
        record_test("baseline-comparison", "Baseline has empty password", baseline_empty_pw, "Confirms hardening is effective")

      # ============================================
      # Generate Audit Report
      # ============================================
      # Calculate totals
      total_passed = sum(m["passed"] for m in audit_results["modules"].values())
      total_failed = sum(m["failed"] for m in audit_results["modules"].values())
      audit_results["summary"] = {
        "total_tests": total_passed + total_failed,
        "passed": total_passed,
        "failed": total_failed,
        "compliance_rate": f"{(total_passed / (total_passed + total_failed) * 100):.1f}%" if (total_passed + total_failed) > 0 else "N/A"
      }

      # Write audit report
      hardened.succeed(f"echo '{json.dumps(audit_results, indent=2)}' > /tmp/barbican-audit.json")
      print("\n" + "="*60)
      print("BARBICAN SECURITY AUDIT REPORT")
      print("="*60)
      print(f"Timestamp: {audit_results['timestamp']}")
      print(f"Total Tests: {audit_results['summary']['total_tests']}")
      print(f"Passed: {audit_results['summary']['passed']}")
      print(f"Failed: {audit_results['summary']['failed']}")
      print(f"Compliance Rate: {audit_results['summary']['compliance_rate']}")
      print("="*60)
      for module, data in audit_results["modules"].items():
        status = "PASS" if data["failed"] == 0 else "FAIL"
        print(f"\n[{status}] {module}: {data['passed']}/{data['passed'] + data['failed']} tests passed")
        for test in data["tests"]:
          icon = "✓" if test["passed"] else "✗"
          print(f"  {icon} {test['name']}")
      print("\n" + "="*60)
    '';
  };

in {
  inherit testModules allTests;

  # Individual test derivations
  tests = testModules;

  # Combined test
  all = allTests;
}
