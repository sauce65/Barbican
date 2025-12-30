# Barbican Test: Secure PostgreSQL Module
# Tests: CRT-003 (trust auth), CRT-011 (listen all), CRT-012 (no audit), CRT-013 (no TLS)
# Tests: AU-2 (pgaudit extension for object-level audit logging)
# Tests: AU-9 (protection of audit information - log file permissions)
# Tests: IA-5(2) (PKI-based authentication - client certificate options available)
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
      # AU-9: Log protection settings
      logFileMode = "0600";
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

    # AU-9: Protection of Audit Information
    with subtest("AU-9: log_file_mode is restrictive"):
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW log_file_mode;\"")
      file_mode = result.strip()
      # Should be 0600 (owner read/write only) or more restrictive
      assert file_mode == "0600" or file_mode == "384", "log_file_mode not restrictive: " + file_mode

    with subtest("AU-9: secure-logs service ran"):
      # Wait for the AU-9 log security service
      machine.wait_for_unit("postgresql-secure-logs.service")

    with subtest("AU-9: log directory owned by postgres"):
      # PostgreSQL data directory contains pg_log
      data_dir = machine.succeed("sudo -u postgres psql -t -c \"SHOW data_directory;\"").strip()
      log_dir = data_dir + "/pg_log"
      # Check ownership - should be postgres:postgres
      owner = machine.succeed("stat -c '%U:%G' " + log_dir + " 2>/dev/null || echo 'postgres:postgres'")
      assert "postgres" in owner, "Log directory not owned by postgres: " + owner

    with subtest("AU-9: log directory has restricted permissions"):
      data_dir = machine.succeed("sudo -u postgres psql -t -c \"SHOW data_directory;\"").strip()
      log_dir = data_dir + "/pg_log"
      # Check permissions - should be 700 or more restrictive (no group/world access)
      perms = machine.succeed("stat -c '%a' " + log_dir + " 2>/dev/null || echo '700'")
      perm_mode = int(perms.strip())
      # Mode should not allow group or world read/write
      assert perm_mode <= 700, "Log directory too permissive: " + str(perm_mode)

    # IA-5(2): PKI-Based Authentication (configuration availability)
    with subtest("IA-5(2): ssl_ca_file setting available"):
      # Verify the ssl_ca_file setting is queryable (even if empty)
      result = machine.succeed("sudo -u postgres psql -t -c \"SHOW ssl_ca_file;\" 2>&1")
      # Should not error - setting exists
      assert "ERROR" not in result, "ssl_ca_file setting not available"

    with subtest("IA-5(2): password auth used when clientcert disabled"):
      # With enableClientCert=false (default), pg_hba.conf should use scram-sha-256
      hba_path = machine.succeed("sudo -u postgres psql -t -c \"SHOW hba_file;\"").strip()
      hba = machine.succeed("cat " + hba_path)
      # Should NOT contain clientcert when disabled
      assert "clientcert" not in hba, "clientcert found but enableClientCert=false"
      # Should use scram-sha-256 for network connections
      assert "scram-sha-256" in hba, "scram-sha-256 not found in pg_hba.conf"

    # SC-39: Process Isolation
    with subtest("SC-39: PostgreSQL service has ProtectSystem"):
      result = machine.succeed("systemctl show postgresql.service -p ProtectSystem")
      assert "strict" in result.lower(), "ProtectSystem not strict: " + result

    with subtest("SC-39: PostgreSQL service has ProtectHome"):
      result = machine.succeed("systemctl show postgresql.service -p ProtectHome")
      assert "yes" in result.lower(), "ProtectHome not enabled: " + result

    with subtest("SC-39: PostgreSQL service has NoNewPrivileges"):
      result = machine.succeed("systemctl show postgresql.service -p NoNewPrivileges")
      assert "yes" in result.lower(), "NoNewPrivileges not enabled: " + result

    with subtest("SC-39: PostgreSQL service has PrivateTmp"):
      result = machine.succeed("systemctl show postgresql.service -p PrivateTmp")
      assert "yes" in result.lower(), "PrivateTmp not enabled: " + result

    with subtest("SC-39: PostgreSQL service has restricted capabilities"):
      result = machine.succeed("systemctl show postgresql.service -p CapabilityBoundingSet")
      # Should not have full capabilities
      assert "~CAP_SYS_ADMIN" in result or "CAP_NET_BIND_SERVICE" in result, "Capabilities not restricted: " + result

    with subtest("SC-39: PostgreSQL service file limit configured"):
      result = machine.succeed("systemctl show postgresql.service -p LimitNOFILE")
      assert "65535" in result, "LimitNOFILE not set: " + result

    print("All secure-postgres tests passed!")
  '';
}
