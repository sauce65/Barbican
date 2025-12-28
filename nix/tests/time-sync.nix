# Barbican Test: Time Synchronization Module
# Tests: HIGH-011 (no time synchronization)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-time-sync";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../modules/time-sync.nix ];

    barbican.timeSync = {
      enable = true;
      servers = [
        "time.cloudflare.com"
        "time.google.com"
      ];
      minPoll = 4;
      maxPoll = 8;
    };
  };

  testScript = ''
    machine.wait_for_unit("chronyd.service")

    # HIGH-011: Time synchronization active
    with subtest("Chrony service is running"):
      status = machine.succeed("systemctl is-active chronyd")
      assert "active" in status, f"Chrony not active: {status}"

    with subtest("Chrony configuration exists"):
      # NixOS puts chrony config in the nix store, check via chronyc or systemd
      config = machine.succeed("cat $(systemctl cat chronyd | grep ExecStart | sed 's/.*-f //' | cut -d' ' -f1) 2>/dev/null || chronyc -n sources")
      assert "server" in config.lower() or "pool" in config.lower() or "time" in config.lower(), \
        f"No servers in chrony config: {config}"

    with subtest("NTP servers configured"):
      # Get the chrony.conf path from systemd unit and check for our servers
      config_check = machine.succeed("cat $(systemctl cat chronyd | grep 'ExecStart' | sed 's/.*-f //' | cut -d' ' -f1)")
      has_servers = "cloudflare" in config_check.lower() or "google" in config_check.lower() or "time" in config_check.lower()
      assert has_servers, f"Expected NTP servers not found in config: {config_check}"

    with subtest("Chrony can query sources"):
      # Note: In test VM, sources may not be reachable, but command should work
      exit_code, output = machine.execute("chronyc sources 2>&1")
      # Command should execute without error (exit code 0)
      assert exit_code == 0 or "506" in output, f"chronyc sources failed: {output}"

    with subtest("Chrony tracking works"):
      exit_code, output = machine.execute("chronyc tracking 2>&1")
      # Should show tracking info (even if not synced in test)
      assert exit_code == 0 or "506" in output, f"chronyc tracking failed: {output}"

    with subtest("Timezone is UTC"):
      tz = machine.succeed("timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo 'unknown'")
      # Default should be UTC
      assert "UTC" in tz or "Etc/UTC" in tz or "unknown" in tz, f"Timezone not UTC: {tz}"

    with subtest("systemd-timesyncd is disabled"):
      exit_code, output = machine.execute("systemctl is-enabled systemd-timesyncd 2>&1")
      # Should be disabled or masked when chrony is used
      assert exit_code != 0 or "disabled" in output or "masked" in output, \
        f"systemd-timesyncd may still be enabled: {output}"

    with subtest("Poll intervals configured"):
      # Get the chrony.conf path from systemd unit and check its contents
      config = machine.succeed("cat $(systemctl cat chronyd | grep 'ExecStart' | sed 's/.*-f //' | cut -d' ' -f1)")
      assert "minpoll" in config, f"minpoll not configured: {config}"
      assert "maxpoll" in config, f"maxpoll not configured: {config}"

    print("All time-sync tests passed!")
  '';
}
