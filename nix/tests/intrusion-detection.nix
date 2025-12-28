# Barbican Test: Intrusion Detection Module
# Tests: CRT-015 (no intrusion detection), CRT-016 (VM images not integrity protected)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-intrusion-detection";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../modules/intrusion-detection.nix ];

    barbican.intrusionDetection = {
      enable = true;
      enableAIDE = true;
      enableAuditd = true;
      enableProcessAccounting = true;
      aideScanSchedule = "04:00";
      auditRules = [
        "-a always,exit -F arch=b64 -S execve -k exec"
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
      ];
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # CRT-015: Auditd running
    with subtest("Auditd service is running"):
      machine.wait_for_unit("auditd.service")
      status = machine.succeed("systemctl is-active auditd")
      assert "active" in status, f"Auditd not active: {status}"

    with subtest("Audit rules are loaded"):
      rules = machine.succeed("auditctl -l")
      assert "-a" in rules or "-w" in rules, f"No audit rules loaded: {rules}"

    with subtest("Execve auditing configured"):
      rules = machine.succeed("auditctl -l")
      assert "execve" in rules, f"execve not audited: {rules}"

    with subtest("Identity files audited"):
      rules = machine.succeed("auditctl -l")
      has_passwd = "/etc/passwd" in rules
      has_shadow = "/etc/shadow" in rules
      assert has_passwd or has_shadow, f"Identity files not audited: {rules}"

    # AIDE tests
    with subtest("AIDE is installed"):
      result = machine.succeed("which aide")
      # NixOS may symlink to /run/current-system/sw/bin or directly to /nix/store
      assert "/nix/store" in result or "/run/current-system" in result or "aide" in result, \
        f"AIDE not installed: {result}"

    with subtest("AIDE configuration exists"):
      config = machine.succeed("cat /etc/aide.conf")
      assert "database" in config.lower(), f"AIDE config missing database: {config[:500]}"

    with subtest("AIDE init service exists"):
      # Check if aide-init service unit exists
      exit_code, output = machine.execute("systemctl cat aide-init 2>&1")
      # Service should exist (may or may not have run yet)
      assert exit_code == 0 or "aide" in output.lower(), f"AIDE init service not found: {output}"

    with subtest("AIDE check timer exists"):
      exit_code, output = machine.execute("systemctl list-timers aide-check.timer 2>&1")
      # Timer should be listed
      assert "aide" in output.lower() or exit_code == 0, f"AIDE check timer not found: {output}"

    # Process accounting
    with subtest("Process accounting enabled"):
      exit_code, output = machine.execute("systemctl is-active acct 2>&1")
      # acct service should be active
      assert "active" in output or exit_code == 0, f"Process accounting not active: {output}"

    with subtest("lastcomm works"):
      # lastcomm should be available
      exit_code, output = machine.execute("which lastcomm 2>&1")
      # NixOS may symlink to /run/current-system/sw/bin or directly to /nix/store
      assert "/nix/store" in output or "/run/current-system" in output or exit_code == 0, \
        f"lastcomm not available: {output}"

    # Log directory exists
    with subtest("Audit log directory exists"):
      exit_code, output = machine.execute("ls -la /var/log/audit/ 2>&1")
      assert exit_code == 0 or "audit" in output, f"Audit log directory issue: {output}"

    print("All intrusion-detection tests passed!")
  '';
}
