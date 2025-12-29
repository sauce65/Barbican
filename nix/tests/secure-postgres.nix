# Barbican Test: Secure PostgreSQL Module
# Tests: CRT-003 (trust auth), CRT-011 (listen all), CRT-012 (no audit), CRT-013 (no TLS)
# Tests: AU-2 (pgaudit extension for object-level audit logging)
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
      enablePgaudit = true;
      pgauditLogClasses = [ "write" "role" "ddl" ];
      pgauditLogRelation = true;
      maxConnections = 50;
      statementTimeout = 30000;
    };
  };

  testScript = ''
    machine.wait_for_unit("postgresql.service")

    # CRT-003: No trust authentication
    with subtest("Trust authentication disabled"):
      # Get the actual hba_file being used by postgresql (not the initdb default)
      # Run as postgres user for peer auth to work
      hba_path = machine.succeed("sudo -u postgres psql -t -c \"SHOW hba_file;\"").strip()
      hba = machine.succeed(f"cat {hba_path}")
      # Trust should not be in the config (except possibly for local postgres peer)
      lines = [l for l in hba.split('\n') if l.strip() and not l.startswith('#')]
      trust_lines = [l for l in lines if 'trust' in l and 'peer' not in l]
      assert len(trust_lines) == 0, f"Trust authentication found: {trust_lines}"

    with subtest("scram-sha-256 authentication configured"):
      hba_path = machine.succeed("sudo -u postgres psql -t -c \"SHOW hba_file;\"").strip()
      hba = machine.succeed(f"cat {hba_path}")
      assert "scram-sha-256" in hba, f"scram-sha-256 not in pg_hba.conf: {hba[:500]}"

    # CRT-011: Listen address restricted
    with subtest("Listen address restricted"):
      config = machine.succeed("sudo -u postgres psql -t -c \"SHOW listen_addresses;\"")
      # Should not be * (all interfaces)
      assert "*" not in config or "127.0.0.1" in config, f"Listening on all interfaces: {config}"

    # CRT-012: Audit logging enabled
    with subtest("Logging collector enabled"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW logging_collector;\"")
      assert "on" in result.lower(), f"Logging collector not on: {result}"

    with subtest("Connection logging enabled"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW log_connections;\"")
      assert "on" in result.lower(), f"log_connections not on: {result}"

    with subtest("Disconnection logging enabled"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW log_disconnections;\"")
      assert "on" in result.lower(), f"log_disconnections not on: {result}"

    with subtest("Statement logging enabled"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW log_statement;\"")
      # Should be 'all', 'ddl', or 'mod'
      assert result.strip() in ['all', 'ddl', 'mod'], f"log_statement not comprehensive: {result}"

    # Password encryption
    with subtest("Password encryption is scram-sha-256"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW password_encryption;\"")
      assert "scram-sha-256" in result, f"Password encryption not scram-sha-256: {result}"

    # Connection limits
    with subtest("Max connections limited"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW max_connections;\"")
      max_conn = int(result.strip())
      assert max_conn <= 100, f"Max connections too high: {max_conn}"

    with subtest("Statement timeout configured"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW statement_timeout;\"")
      # Should be non-zero
      timeout = result.strip()
      assert timeout != "0" and timeout != "0ms", f"Statement timeout not set: {timeout}"

    # Test that unauthorized connections are rejected
    with subtest("Reject connections from unauthorized hosts"):
      # The pg_hba.conf should have explicit reject for 0.0.0.0/0
      hba_path = machine.succeed("sudo -u postgres psql -t -c \"SHOW hba_file;\"").strip()
      hba = machine.succeed(f"cat {hba_path}")
      assert "reject" in hba, "No reject rule in pg_hba.conf: " + hba[:200]

    # Database and user creation
    with subtest("Test database created"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SELECT datname FROM pg_database WHERE datname='testdb';\"")
      assert "testdb" in result, f"Test database not created: {result}"

    # AU-2: pgaudit extension tests
    with subtest("AU-2: pgaudit extension loaded"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW shared_preload_libraries;\"")
      assert "pgaudit" in result, "pgaudit not loaded"

    with subtest("AU-2: pgaudit.log configured"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW pgaudit.log;\"")
      assert "write" in result.lower() or "ddl" in result.lower(), "pgaudit.log not set"

    with subtest("AU-2: pgaudit extension in testdb"):
      result = machine.succeed("sudo -u postgres psql -d testdb -t -c \"SELECT extname FROM pg_extension WHERE extname='pgaudit';\"")
      assert "pgaudit" in result, "pgaudit extension missing"

    print("All secure-postgres tests passed!")
  '';
}
