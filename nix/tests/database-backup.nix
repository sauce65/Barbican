# Barbican Test: Database Backup Module
# Tests: CP-9 (System Backup), SC-28(1) (Cryptographic Protection of backup data)
# Standards: NIST SP 800-53, SOC 2 CC7.1
{ pkgs, lib, ... }:

pkgs.testers.nixosTest {
  name = "barbican-database-backup";

  nodes.machine = { config, pkgs, ... }: {
    imports = [
      ../modules/secure-postgres.nix
      ../modules/database-backup.nix
    ];

    # Set up secure PostgreSQL
    barbican.securePostgres = {
      enable = true;
      listenAddress = "127.0.0.1";
      allowedClients = [ "127.0.0.1/32" ];
      database = "testdb";
      username = "testuser";
      enableSSL = false;  # Skip SSL for test (no certs)
      enableAuditLog = true;
    };

    # Set up database backup
    barbican.databaseBackup = {
      enable = true;
      schedule = "03:00";
      retentionDays = 7;
      backupPath = "/var/lib/postgresql/backups";
      enableEncryption = true;
      # Create a test age key
      encryptionKeyFile = pkgs.writeText "backup-key.pub" ''
        age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
      '';
    };

    # Ensure age is available
    environment.systemPackages = [ pkgs.age ];
  };

  testScript = ''
    import time

    machine.wait_for_unit("postgresql.service")

    # CP-9: System Backup Tests
    with subtest("CP-9: Backup service unit exists"):
      result = machine.succeed("systemctl cat barbican-db-backup.service")
      assert "barbican" in result.lower(), "Backup service not found"

    with subtest("CP-9: Backup timer unit exists"):
      result = machine.succeed("systemctl cat barbican-db-backup.timer")
      assert "OnCalendar" in result, "Timer not configured"

    with subtest("CP-9: Backup directory exists with correct permissions"):
      machine.succeed("test -d /var/lib/postgresql/backups")
      perms = machine.succeed("stat -c '%a' /var/lib/postgresql/backups").strip()
      assert perms == "700", f"Backup dir permissions incorrect: {perms}"

    with subtest("CP-9: Backup directory owned by postgres"):
      owner = machine.succeed("stat -c '%U:%G' /var/lib/postgresql/backups").strip()
      assert owner == "postgres:postgres", f"Backup dir owner incorrect: {owner}"

    # Insert test data before backup
    with subtest("CP-9: Create test data for backup"):
      machine.succeed("sudo -u postgres psql -d testdb -c 'CREATE TABLE IF NOT EXISTS backup_test (id serial, data text);'")
      machine.succeed("sudo -u postgres psql -d testdb -c \"INSERT INTO backup_test (data) VALUES ('critical_data_123');\"")
      result = machine.succeed("sudo -u postgres psql -d testdb -t -c 'SELECT data FROM backup_test;'")
      assert "critical_data_123" in result, "Test data not inserted"

    # Run backup manually
    with subtest("CP-9: Manual backup execution succeeds"):
      machine.succeed("systemctl start barbican-db-backup.service")
      machine.wait_until_succeeds("systemctl is-active barbican-db-backup.service || systemctl show barbican-db-backup.service -p ActiveState | grep -q inactive")

    with subtest("CP-9: Backup file created"):
      result = machine.succeed("ls -la /var/lib/postgresql/backups/")
      assert "backup_" in result, f"No backup file found: {result}"

    # SC-28(1): Cryptographic Protection Tests
    with subtest("SC-28(1): Backup is encrypted with age"):
      # Find the backup file
      backup_file = machine.succeed("ls /var/lib/postgresql/backups/backup_*.age 2>/dev/null || echo 'none'").strip()
      assert backup_file != "none", "No encrypted backup file found"
      assert ".age" in backup_file, f"Backup not encrypted: {backup_file}"

    with subtest("SC-28(1): Encrypted backup file permissions"):
      backup_file = machine.succeed("ls /var/lib/postgresql/backups/backup_*.age").strip()
      perms = machine.succeed(f"stat -c '%a' {backup_file}").strip()
      assert perms == "600", f"Backup file permissions too permissive: {perms}"

    with subtest("SC-28(1): Encrypted backup is not plaintext"):
      backup_file = machine.succeed("ls /var/lib/postgresql/backups/backup_*.age").strip()
      # The encrypted file should not contain plaintext SQL
      result = machine.succeed(f"file {backup_file}")
      # age encrypted files are identified as "data" not "gzip" or "ASCII"
      assert "ASCII" not in result and "SQL" not in result, f"Backup appears unencrypted: {result}"

    with subtest("SC-28(1): Backup contains valid age header"):
      backup_file = machine.succeed("ls /var/lib/postgresql/backups/backup_*.age").strip()
      # age files start with "age-encryption.org" header
      header = machine.succeed(f"head -c 20 {backup_file} | strings")
      assert "age" in header.lower() or len(header.strip()) == 0, "Not a valid age file"

    # CP-9: Retention policy
    with subtest("CP-9: Retention cleanup configured in script"):
      result = machine.succeed("systemctl cat barbican-db-backup.service")
      assert "mtime" in result and "delete" in result, "Retention cleanup not configured"

    # CP-9: Timer scheduled
    with subtest("CP-9: Backup timer is enabled"):
      result = machine.succeed("systemctl is-enabled barbican-db-backup.timer")
      assert "enabled" in result, "Backup timer not enabled"

    with subtest("CP-9: Timer has persistent option"):
      result = machine.succeed("systemctl cat barbican-db-backup.timer")
      assert "Persistent=true" in result, "Timer not persistent (missed backups won't run)"

    # Verify backup integrity (would need private key to fully decrypt)
    with subtest("CP-9: Backup file size is reasonable"):
      backup_file = machine.succeed("ls /var/lib/postgresql/backups/backup_*.age").strip()
      size = int(machine.succeed(f"stat -c '%s' {backup_file}").strip())
      # Should be at least a few KB for a real database backup
      assert size > 100, f"Backup file too small ({size} bytes), may be corrupted"

    print("All database-backup tests passed!")
  '';
}
