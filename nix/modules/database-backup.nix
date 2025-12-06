# Barbican Security Module: Database Backup
# Addresses: CRT-009 (no backup configuration)
# Standards: NIST CP-9, CP-9(1), SOC 2 CC7.1
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.databaseBackup;
in {
  options.barbican.databaseBackup = {
    enable = mkEnableOption "Barbican database backup";

    schedule = mkOption {
      type = types.str;
      default = "02:00";
      description = "Time for daily backups (HH:MM format)";
    };

    retentionDays = mkOption {
      type = types.int;
      default = 30;
      description = "Number of days to retain backups";
    };

    backupPath = mkOption {
      type = types.path;
      default = "/var/lib/postgresql/backups";
      description = "Directory for backup storage";
    };

    enableEncryption = mkOption {
      type = types.bool;
      default = true;
      description = "Encrypt backups with age";
    };

    encryptionKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to age public key file for backup encryption";
    };

    databases = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Specific databases to backup (empty = all)";
    };
  };

  config = mkIf (cfg.enable && config.services.postgresql.enable or false) {
    # Backup service
    systemd.services.barbican-db-backup = {
      description = "Barbican PostgreSQL Backup";
      after = [ "postgresql.service" ];

      serviceConfig = {
        Type = "oneshot";
        User = "postgres";
        Group = "postgres";
      };

      script = let
        backupCmd = if cfg.databases == [] then
          "${pkgs.postgresql_16}/bin/pg_dumpall --clean --if-exists"
        else
          concatMapStringsSep "; " (db:
            "${pkgs.postgresql_16}/bin/pg_dump --clean --if-exists ${db}"
          ) cfg.databases;
      in ''
        set -euo pipefail

        BACKUP_DIR="${cfg.backupPath}"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_FILE="$BACKUP_DIR/backup_$TIMESTAMP.sql"

        # Ensure backup directory exists
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"

        # Create backup
        ${backupCmd} > "$BACKUP_FILE"

        # Compress
        ${pkgs.gzip}/bin/gzip -9 "$BACKUP_FILE"
        BACKUP_FILE="$BACKUP_FILE.gz"

        ${optionalString (cfg.enableEncryption && cfg.encryptionKeyFile != null) ''
          # Encrypt with age
          ${pkgs.age}/bin/age -R ${cfg.encryptionKeyFile} -o "$BACKUP_FILE.age" "$BACKUP_FILE"
          rm "$BACKUP_FILE"
          BACKUP_FILE="$BACKUP_FILE.age"
        ''}

        # Set permissions
        chmod 600 "$BACKUP_FILE"

        # Cleanup old backups
        find "$BACKUP_DIR" -name "backup_*.sql.gz*" -mtime +${toString cfg.retentionDays} -delete

        # Log success
        echo "Backup completed: $BACKUP_FILE"
        ls -lh "$BACKUP_FILE"
      '';
    };

    # Timer for scheduled backups
    systemd.timers.barbican-db-backup = {
      description = "Barbican PostgreSQL Backup Timer";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnCalendar = "*-*-* ${cfg.schedule}";
        Persistent = true;
        RandomizedDelaySec = "5m";
      };
    };

    # Ensure backup directory exists
    systemd.tmpfiles.rules = [
      "d ${cfg.backupPath} 0700 postgres postgres -"
    ];
  };
}
