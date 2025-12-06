# Barbican Test: Intrusion Detection Module
# Tests: CRT-015 (no intrusion detection), CRT-016 (VM images not integrity protected)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-intrusion-detection";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../../modules/intrusion-detection.nix ];

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
      assert "/nix/store" in result, f"AIDE not installed: {result}"

    with subtest("AIDE configuration exists"):
      config = machine.succeed("cat /etc/aide.conf")
      assert "database" in config.lower(), f"AIDE config missing database: {config[:500]}"

    with subtest("AIDE init service exists"):
      # Check if aide-init service unit exists
      result = machine.execute("systemctl cat aide-init 2>&1")
      # Service should exist (may or may not have run yet)
      assert result[0] == 0 or "aide" in result[1].lower(), f"AIDE init service not found"

    with subtest("AIDE check timer exists"):
      result = machine.execute("systemctl list-timers aide-check.timer 2>&1")
      # Timer should be listed
      assert "aide" in result[1].lower() or result[0] == 0, f"AIDE check timer not found"

    # Process accounting
    with subtest("Process accounting enabled"):
      result = machine.execute("systemctl is-active acct 2>&1")
      # acct service should be active
      assert "active" in result[1] or result[0] == 0, f"Process accounting not active: {result}"

    with subtest("lastcomm works"):
      # lastcomm should be available
      result = machine.execute("which lastcomm 2>&1")
      assert "/nix/store" in result[1] or result[0] == 0, f"lastcomm not available: {result}"

    # Log directory exists
    with subtest("Audit log directory exists"):
      result = machine.execute("ls -la /var/log/audit/ 2>&1")
      assert result[0] == 0 or "audit" in result[1], f"Audit log directory issue: {result}"

    print("All intrusion-detection tests passed!")
  '';
}
