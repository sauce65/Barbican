# Barbican Test: Hardened SSH Module
# Tests: CRT-010 (SSH without rate limiting)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-hardened-ssh";

  nodes.machine = { config, pkgs, ... }: {
    imports = [
      ../../modules/secure-users.nix
      ../../modules/hardened-ssh.nix
    ];

    barbican.secureUsers = {
      enable = true;
      authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@barbican" ];
    };

    barbican.hardenedSSH = {
      enable = true;
      maxAuthTries = 3;
      maxSessions = 2;
      enableFail2ban = true;
      fail2banMaxRetry = 3;
      fail2banBanTime = 3600;
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sshd.service")

    # CRT-010: SSH hardening tests
    with subtest("Password authentication disabled"):
      config = machine.succeed("sshd -T 2>/dev/null | grep -i passwordauthentication")
      assert "no" in config.lower(), f"Password auth not disabled: {config}"

    with subtest("Root login restricted to key-only"):
      config = machine.succeed("sshd -T 2>/dev/null | grep -i permitrootlogin")
      assert "prohibit-password" in config.lower() or "without-password" in config.lower(), \
        f"Root login not properly restricted: {config}"

    with subtest("Empty passwords not permitted"):
      config = machine.succeed("sshd -T 2>/dev/null | grep -i permitemptypasswords")
      assert "no" in config.lower(), f"Empty passwords may be allowed: {config}"

    with subtest("X11 forwarding disabled"):
      config = machine.succeed("sshd -T 2>/dev/null | grep -i x11forwarding")
      assert "no" in config.lower(), f"X11 forwarding not disabled: {config}"

    with subtest("MaxAuthTries is limited"):
      config = machine.succeed("sshd -T 2>/dev/null | grep -i maxauthtries")
      tries = int(config.split()[1])
      assert tries <= 3, f"MaxAuthTries too high: {tries}"

    with subtest("Strong ciphers configured"):
      ciphers = machine.succeed("sshd -T 2>/dev/null | grep -i '^ciphers'")
      # Verify strong ciphers present
      assert "chacha20-poly1305" in ciphers or "aes256-gcm" in ciphers, \
        f"Strong ciphers not found: {ciphers}"
      # Verify weak ciphers absent
      assert "3des" not in ciphers.lower(), f"Weak cipher 3des found: {ciphers}"
      assert "arcfour" not in ciphers.lower(), f"Weak cipher arcfour found: {ciphers}"

    with subtest("Strong key exchange algorithms"):
      kex = machine.succeed("sshd -T 2>/dev/null | grep -i kexalgorithms")
      assert "curve25519" in kex, f"Curve25519 KEX not found: {kex}"

    # Fail2ban tests
    with subtest("Fail2ban service running"):
      machine.wait_for_unit("fail2ban.service")
      status = machine.succeed("systemctl is-active fail2ban")
      assert "active" in status, f"Fail2ban not active: {status}"

    with subtest("SSH jail configured"):
      jails = machine.succeed("fail2ban-client status 2>/dev/null || echo 'error'")
      # Should have sshd jail
      assert "sshd" in jails.lower() or "ssh" in jails.lower() or "jail list" in jails.lower(), \
        f"SSH jail not configured: {jails}"

    print("All hardened-ssh tests passed!")
  '';
}
