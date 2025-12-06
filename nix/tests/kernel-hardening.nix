# Barbican Test: Kernel Hardening Module
# Tests: MED-001 (kernel not hardened)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-kernel-hardening";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../../modules/kernel-hardening.nix ];

    barbican.kernelHardening = {
      enable = true;
      enableNetworkHardening = true;
      enableMemoryProtection = true;
      enableProcessRestrictions = true;
      enableAudit = true;
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # Memory protection tests
    with subtest("ASLR fully enabled (level 2)"):
      aslr = machine.succeed("sysctl -n kernel.randomize_va_space")
      assert aslr.strip() == "2", f"ASLR not at level 2: {aslr}"

    with subtest("Kernel pointers restricted"):
      kptr = machine.succeed("sysctl -n kernel.kptr_restrict")
      assert kptr.strip() == "2", f"kptr_restrict not 2: {kptr}"

    with subtest("dmesg restricted"):
      dmesg = machine.succeed("sysctl -n kernel.dmesg_restrict")
      assert dmesg.strip() == "1", f"dmesg not restricted: {dmesg}"

    with subtest("perf_event paranoid"):
      perf = machine.succeed("sysctl -n kernel.perf_event_paranoid")
      assert int(perf.strip()) >= 2, f"perf_event_paranoid too low: {perf}"

    # Network hardening tests
    with subtest("SYN cookies enabled"):
      syn = machine.succeed("sysctl -n net.ipv4.tcp_syncookies")
      assert syn.strip() == "1", f"SYN cookies not enabled: {syn}"

    with subtest("Source routing disabled (all)"):
      srcroute = machine.succeed("sysctl -n net.ipv4.conf.all.accept_source_route")
      assert srcroute.strip() == "0", f"Source routing not disabled: {srcroute}"

    with subtest("ICMP redirects disabled (all)"):
      redirects = machine.succeed("sysctl -n net.ipv4.conf.all.accept_redirects")
      assert redirects.strip() == "0", f"ICMP redirects not disabled: {redirects}"

    with subtest("ICMP redirects disabled (default)"):
      redirects = machine.succeed("sysctl -n net.ipv4.conf.default.accept_redirects")
      assert redirects.strip() == "0", f"Default ICMP redirects not disabled: {redirects}"

    with subtest("Reverse path filtering enabled"):
      rpf = machine.succeed("sysctl -n net.ipv4.conf.all.rp_filter")
      assert rpf.strip() == "1", f"Reverse path filtering not enabled: {rpf}"

    with subtest("Send redirects disabled"):
      send = machine.succeed("sysctl -n net.ipv4.conf.all.send_redirects")
      assert send.strip() == "0", f"Send redirects not disabled: {send}"

    with subtest("Broadcast ICMP ignored"):
      broadcast = machine.succeed("sysctl -n net.ipv4.icmp_echo_ignore_broadcasts")
      assert broadcast.strip() == "1", f"Broadcast ICMP not ignored: {broadcast}"

    with subtest("Martian packets logged"):
      martians = machine.succeed("sysctl -n net.ipv4.conf.all.log_martians")
      assert martians.strip() == "1", f"Martians not logged: {martians}"

    # IPv6 hardening
    with subtest("IPv6 redirects disabled"):
      v6redir = machine.succeed("sysctl -n net.ipv6.conf.all.accept_redirects")
      assert v6redir.strip() == "0", f"IPv6 redirects not disabled: {v6redir}"

    # Process restrictions
    with subtest("SUID core dumps disabled"):
      suid = machine.succeed("sysctl -n fs.suid_dumpable")
      assert suid.strip() == "0", f"SUID dumpable not 0: {suid}"

    with subtest("ptrace scope restricted"):
      ptrace = machine.succeed("sysctl -n kernel.yama.ptrace_scope")
      assert int(ptrace.strip()) >= 1, f"ptrace_scope too low: {ptrace}"

    with subtest("Hardlinks protected"):
      hardlinks = machine.succeed("sysctl -n fs.protected_hardlinks")
      assert hardlinks.strip() == "1", f"Hardlinks not protected: {hardlinks}"

    with subtest("Symlinks protected"):
      symlinks = machine.succeed("sysctl -n fs.protected_symlinks")
      assert symlinks.strip() == "1", f"Symlinks not protected: {symlinks}"

    # Audit
    with subtest("Audit enabled in kernel cmdline"):
      cmdline = machine.succeed("cat /proc/cmdline")
      assert "audit=1" in cmdline, f"Audit not in cmdline: {cmdline}"

    with subtest("Auditd service running"):
      machine.wait_for_unit("auditd.service")
      status = machine.succeed("systemctl is-active auditd")
      assert "active" in status, f"Auditd not active: {status}"

    print("All kernel-hardening tests passed!")
  '';
}
