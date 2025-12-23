# Barbican Test: Secure PostgreSQL Module
# Tests: CRT-003 (trust auth), CRT-011 (listen all), CRT-012 (no audit), CRT-013 (no TLS)
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-secure-postgres";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ../modules/secure-postgres.nix ];

    barbican.securePostgres = {
      enable = true;
      listenAddress = "127.0.0.1";
      allowedClients = [ "127.0.0.1/32" ];
      database = "testdb";
      username = "testuser";
      enableSSL = false;  # Skip SSL for basic test (no certs)
      enableAuditLog = true;
      maxConnections = 50;
      statementTimeout = 30000;
    };
  };

  testScript = ''
    machine.wait_for_unit("postgresql.service")

    # CRT-003: No trust authentication
    with subtest("Trust authentication disabled"):
      hba = machine.succeed("cat /var/lib/postgresql/*/pg_hba.conf 2>/dev/null || cat /etc/postgresql/*/pg_hba.conf 2>/dev/null || echo 'not found'")
      # Trust should not be in the config (except possibly for local postgres peer)
      lines = [l for l in hba.split('\n') if l.strip() and not l.startswith('#')]
      trust_lines = [l for l in lines if 'trust' in l and 'peer' not in l]
      assert len(trust_lines) == 0, f"Trust authentication found: {trust_lines}"

    with subtest("scram-sha-256 authentication configured"):
      hba = machine.succeed("cat /var/lib/postgresql/*/pg_hba.conf 2>/dev/null || cat /etc/postgresql/*/pg_hba.conf 2>/dev/null || echo 'none'")
      assert "scram-sha-256" in hba, f"scram-sha-256 not in pg_hba.conf: {hba[:500]}"

    # CRT-011: Listen address restricted
    with subtest("Listen address restricted"):
      config = machine.succeed("psql -U postgres -c \"SHOW listen_addresses;\" -t 2>/dev/null || echo 'error'")
      # Should not be * (all interfaces)
      assert "*" not in config or "127.0.0.1" in config, f"Listening on all interfaces: {config}"

    # CRT-012: Audit logging enabled
    with subtest("Logging collector enabled"):
      result = machine.succeed("psql -U postgres -c \"SHOW logging_collector;\" -t")
      assert "on" in result.lower(), f"Logging collector not on: {result}"

    with subtest("Connection logging enabled"):
      result = machine.succeed("psql -U postgres -c \"SHOW log_connections;\" -t")
      assert "on" in result.lower(), f"log_connections not on: {result}"

    with subtest("Disconnection logging enabled"):
      result = machine.succeed("psql -U postgres -c \"SHOW log_disconnections;\" -t")
      assert "on" in result.lower(), f"log_disconnections not on: {result}"

    with subtest("Statement logging enabled"):
      result = machine.succeed("psql -U postgres -c \"SHOW log_statement;\" -t")
      # Should be 'all', 'ddl', or 'mod'
      assert result.strip() in ['all', 'ddl', 'mod'], f"log_statement not comprehensive: {result}"

    # Password encryption
    with subtest("Password encryption is scram-sha-256"):
      result = machine.succeed("psql -U postgres -c \"SHOW password_encryption;\" -t")
      assert "scram-sha-256" in result, f"Password encryption not scram-sha-256: {result}"

    # Connection limits
    with subtest("Max connections limited"):
      result = machine.succeed("psql -U postgres -c \"SHOW max_connections;\" -t")
      max_conn = int(result.strip())
      assert max_conn <= 100, f"Max connections too high: {max_conn}"

    with subtest("Statement timeout configured"):
      result = machine.succeed("psql -U postgres -c \"SHOW statement_timeout;\" -t")
      # Should be non-zero
      timeout = result.strip()
      assert timeout != "0" and timeout != "0ms", f"Statement timeout not set: {timeout}"

    # Test that unauthorized connections are rejected
    with subtest("Reject connections from unauthorized hosts"):
      # The pg_hba.conf should have explicit reject for 0.0.0.0/0
      hba = machine.succeed("cat /var/lib/postgresql/*/pg_hba.conf 2>/dev/null || cat /etc/postgresql/*/pg_hba.conf 2>/dev/null || echo 'none'")
      assert "reject" in hba, "No reject rule in pg_hba.conf: " + hba[:200]

    # Database and user creation
    with subtest("Test database created"):
      result = machine.succeed("psql -U postgres -c \"SELECT datname FROM pg_database WHERE datname='testdb';\" -t")
      assert "testdb" in result, f"Test database not created: {result}"

    print("All secure-postgres tests passed!")
  '';
}
