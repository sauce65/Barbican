# Barbican Test: Secure Users Module
# Tests: CRT-001 (empty password), CRT-002 (auto-login)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-secure-users";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../modules/secure-users.nix ];

    barbican.secureUsers = {
      enable = true;
      authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@barbican" ];
      loginBanner = "AUTHORIZED ACCESS ONLY - TEST ENVIRONMENT";
    };

    services.openssh.enable = true;
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # CRT-001: Verify no empty root password
    with subtest("Root password is not empty"):
      shadow = machine.succeed("getent shadow root")
      # Password field should be locked (!, *, !!) or contain a hash
      pw_field = shadow.split(":")[1]
      assert pw_field in ["!", "*", "!!"] or len(pw_field) > 10, \
        f"Root password appears empty or weak: {pw_field[:20]}"

    # CRT-002: Verify no auto-login
    with subtest("Auto-login is disabled"):
      # Check if autologin is configured
      exit_code, output = machine.execute("grep -r 'autologin' /etc/systemd/system/getty* 2>/dev/null || echo 'not found'")
      assert "not found" in output or exit_code != 0, \
        "Auto-login appears to be configured"

    # Verify SSH keys are set
    with subtest("SSH authorized keys configured"):
      keys = machine.succeed("cat /root/.ssh/authorized_keys")
      assert "ssh-ed25519" in keys, "SSH key not found in authorized_keys"
      assert "TestKey" in keys, "Expected test key not found"

    # Verify login banner
    with subtest("Login banner is set"):
      issue = machine.succeed("cat /etc/issue")
      assert "AUTHORIZED" in issue, f"Banner not found in /etc/issue: {issue}"

    with subtest("Network issue banner is set"):
      issue_net = machine.succeed("cat /etc/issue.net")
      assert "AUTHORIZED" in issue_net, "Banner not found in /etc/issue.net"

    print("All secure-users tests passed!")
  '';
}
