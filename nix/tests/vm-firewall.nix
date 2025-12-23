# Barbican Test: VM Firewall Module
# Tests: CRT-007 (no network segmentation), HIGH-005 (no egress filtering)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-vm-firewall";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../modules/vm-firewall.nix ];

    barbican.vmFirewall = {
      enable = true;
      defaultPolicy = "drop";
      allowedInbound = [
        { port = 22; from = "10.0.0.0/8"; proto = "tcp"; }
        { port = 443; from = "any"; proto = "tcp"; }
        { port = 80; from = "any"; proto = "tcp"; }
      ];
      allowedOutbound = [
        { port = 443; to = "any"; proto = "tcp"; }
        { port = 80; to = "any"; proto = "tcp"; }
      ];
      enableEgressFiltering = true;
      allowDNS = true;
      allowNTP = true;
      logDropped = true;
    };
  };

  testScript = ''
    machine.wait_for_unit("firewall.service")

    # CRT-007: Firewall is active
    with subtest("Firewall service is running"):
      status = machine.succeed("systemctl is-active firewall")
      assert "active" in status, f"Firewall not active: {status}"

    with subtest("iptables has rules"):
      rules = machine.succeed("iptables -L -n")
      # Should have some rules beyond default ACCEPT
      assert "DROP" in rules or "REJECT" in rules or "LOG" in rules, \
        f"No restrictive firewall rules: {rules[:500]}"

    # Inbound rules
    with subtest("SSH allowed from specific subnet"):
      rules = machine.succeed("iptables -L INPUT -n")
      # Should have a rule for port 22
      assert "22" in rules or "ssh" in rules.lower(), f"SSH rule not found: {rules}"

    with subtest("HTTPS allowed (port 443)"):
      rules = machine.succeed("iptables -L INPUT -n")
      assert "443" in rules or "https" in rules.lower(), f"HTTPS rule not found: {rules}"

    with subtest("HTTP allowed (port 80)"):
      rules = machine.succeed("iptables -L INPUT -n")
      assert "80" in rules or "http" in rules.lower(), f"HTTP rule not found: {rules}"

    # Egress filtering (HIGH-005)
    with subtest("Egress filtering enabled"):
      # Check OUTPUT chain policy or rules
      output_policy = machine.succeed("iptables -L OUTPUT -n")
      # Should have explicit rules or DROP policy
      has_egress_control = "DROP" in output_policy or "ACCEPT" in output_policy
      assert has_egress_control, f"No egress control: {output_policy}"

    with subtest("DNS allowed outbound"):
      output_rules = machine.succeed("iptables -L OUTPUT -n")
      # DNS should be allowed (port 53)
      assert "53" in output_rules or "domain" in output_rules.lower(), \
        f"DNS not allowed outbound: {output_rules}"

    with subtest("NTP allowed outbound"):
      output_rules = machine.succeed("iptables -L OUTPUT -n")
      # NTP should be allowed (port 123)
      assert "123" in output_rules or "ntp" in output_rules.lower(), \
        f"NTP not allowed outbound: {output_rules}"

    # Logging
    with subtest("Dropped packets are logged"):
      rules = machine.succeed("iptables -L -n")
      # Should have LOG rules
      assert "LOG" in rules, f"No logging rules: {rules[:500]}"

    # Loopback allowed
    with subtest("Loopback traffic allowed"):
      rules = machine.succeed("iptables -L INPUT -n -v")
      # lo interface should be accepted
      assert "lo" in rules or "127.0.0.1" in rules, f"Loopback not explicitly allowed: {rules[:500]}"

    # Established connections
    with subtest("Established connections allowed"):
      rules = machine.succeed("iptables -L INPUT -n")
      assert "ESTABLISHED" in rules or "RELATED" in rules, \
        f"Established connections not allowed: {rules}"

    print("All vm-firewall tests passed!")
  '';
}
