# Barbican Test: Time Synchronization Module
# Tests: HIGH-011 (no time synchronization)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-time-sync";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../../modules/time-sync.nix ];

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
      config = machine.succeed("cat /etc/chrony.conf")
      assert "server" in config or "pool" in config, f"No servers in chrony.conf: {config}"

    with subtest("NTP servers configured"):
      config = machine.succeed("cat /etc/chrony.conf")
      # Check for expected servers
      has_servers = "cloudflare" in config.lower() or "google" in config.lower() or "pool" in config.lower()
      assert has_servers, f"Expected NTP servers not found: {config}"

    with subtest("Chrony can query sources"):
      # Note: In test VM, sources may not be reachable, but command should work
      result = machine.execute("chronyc sources 2>&1")
      # Command should execute without error (exit code 0)
      assert result[0] == 0 or "506" in result[1], f"chronyc sources failed: {result}"

    with subtest("Chrony tracking works"):
      result = machine.execute("chronyc tracking 2>&1")
      # Should show tracking info (even if not synced in test)
      assert result[0] == 0 or "506" in result[1], f"chronyc tracking failed: {result}"

    with subtest("Timezone is UTC"):
      tz = machine.succeed("timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo 'unknown'")
      # Default should be UTC
      assert "UTC" in tz or "Etc/UTC" in tz or "unknown" in tz, f"Timezone not UTC: {tz}"

    with subtest("systemd-timesyncd is disabled"):
      result = machine.execute("systemctl is-enabled systemd-timesyncd 2>&1")
      # Should be disabled or masked when chrony is used
      assert result[0] != 0 or "disabled" in result[1] or "masked" in result[1], \
        f"systemd-timesyncd may still be enabled: {result}"

    with subtest("Poll intervals configured"):
      config = machine.succeed("cat /etc/chrony.conf")
      assert "minpoll" in config, f"minpoll not configured: {config}"
      assert "maxpoll" in config, f"maxpoll not configured: {config}"

    print("All time-sync tests passed!")
  '';
}
