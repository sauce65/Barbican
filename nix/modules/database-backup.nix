# Barbican Security Module: Database Backup
# Addresses: CRT-009 (no backup configuration)
# Standards: NIST CP-9, CP-9(1), MP-5, SC-28(1), SOC 2 CC7.1
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
      description = "Encrypt backups with age (SC-28(1))";
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

    # MP-5: Offsite backup transport
    enableOffsiteBackup = mkOption {
      type = types.bool;
      default = false;
      description = "Enable offsite backup transport (MP-5)";
    };

    offsiteType = mkOption {
      type = types.enum [ "s3" "rclone" ];
      default = "s3";
      description = "Offsite backup method: s3 (direct) or rclone (flexible)";
    };

    offsiteBucket = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "S3 bucket or rclone remote path for offsite storage";
      example = "my-backup-bucket/postgres";
    };

    offsiteEndpoint = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "S3-compatible endpoint URL (for MinIO, Backblaze, etc.)";
      example = "https://s3.us-west-2.amazonaws.com";
    };

    offsiteCredentialsFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to file containing S3 credentials (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)";
    };

    rcloneConfigFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to rclone config file (for rclone offsite type)";
    };

    offsiteRetentionDays = mkOption {
      type = types.int;
      default = 90;
      description = "Number of days to retain offsite backups";
    };

    verifyOffsiteUpload = mkOption {
      type = types.bool;
      default = true;
      description = "Verify backup integrity after offsite upload";
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

      path = [ pkgs.gzip pkgs.coreutils pkgs.findutils ]
        ++ optional cfg.enableEncryption pkgs.age
        ++ optional (cfg.enableOffsiteBackup && cfg.offsiteType == "s3") pkgs.awscli2
        ++ optional (cfg.enableOffsiteBackup && cfg.offsiteType == "rclone") pkgs.rclone;

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
        gzip -9 "$BACKUP_FILE"
        BACKUP_FILE="$BACKUP_FILE.gz"

        ${optionalString (cfg.enableEncryption && cfg.encryptionKeyFile != null) ''
          # SC-28(1): Encrypt with age
          ${pkgs.age}/bin/age -R ${cfg.encryptionKeyFile} -o "$BACKUP_FILE.age" "$BACKUP_FILE"
          rm "$BACKUP_FILE"
          BACKUP_FILE="$BACKUP_FILE.age"
        ''}

        # Set permissions
        chmod 600 "$BACKUP_FILE"

        # Cleanup old local backups
        find "$BACKUP_DIR" -name "backup_*.sql.gz*" -mtime +${toString cfg.retentionDays} -delete

        # Log success
        echo "Local backup completed: $BACKUP_FILE"
        ls -lh "$BACKUP_FILE"

        ${optionalString cfg.enableOffsiteBackup ''
          # MP-5: Offsite backup transport
          echo "Starting offsite backup upload..."
          BACKUP_FILENAME=$(basename "$BACKUP_FILE")

          ${if cfg.offsiteType == "s3" then ''
            # Load S3 credentials
            ${optionalString (cfg.offsiteCredentialsFile != null) ''
              source ${cfg.offsiteCredentialsFile}
              export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
            ''}

            # Upload to S3
            ${pkgs.awscli2}/bin/aws s3 cp "$BACKUP_FILE" \
              "s3://${cfg.offsiteBucket}/$BACKUP_FILENAME" \
              ${optionalString (cfg.offsiteEndpoint != null) "--endpoint-url ${cfg.offsiteEndpoint}"} \
              --no-progress

            ${optionalString cfg.verifyOffsiteUpload ''
              # Verify upload by checking object exists and size matches
              LOCAL_SIZE=$(stat -c %s "$BACKUP_FILE")
              REMOTE_SIZE=$(${pkgs.awscli2}/bin/aws s3api head-object \
                --bucket "${cfg.offsiteBucket}" \
                --key "$BACKUP_FILENAME" \
                ${optionalString (cfg.offsiteEndpoint != null) "--endpoint-url ${cfg.offsiteEndpoint}"} \
                --query 'ContentLength' --output text 2>/dev/null || echo "0")

              if [ "$LOCAL_SIZE" != "$REMOTE_SIZE" ]; then
                echo "ERROR: Offsite backup verification failed! Size mismatch."
                exit 1
              fi
              echo "Offsite backup verified: size matches ($LOCAL_SIZE bytes)"
            ''}

            # Cleanup old offsite backups
            echo "Cleaning up offsite backups older than ${toString cfg.offsiteRetentionDays} days..."
            CUTOFF_DATE=$(date -d "${toString cfg.offsiteRetentionDays} days ago" +%Y-%m-%d)
            ${pkgs.awscli2}/bin/aws s3 ls "s3://${cfg.offsiteBucket}/" \
              ${optionalString (cfg.offsiteEndpoint != null) "--endpoint-url ${cfg.offsiteEndpoint}"} \
              | while read -r line; do
                FILE_DATE=$(echo "$line" | awk '{print $1}')
                FILE_NAME=$(echo "$line" | awk '{print $4}')
                if [[ "$FILE_DATE" < "$CUTOFF_DATE" && "$FILE_NAME" == backup_* ]]; then
                  echo "Deleting old offsite backup: $FILE_NAME"
                  ${pkgs.awscli2}/bin/aws s3 rm "s3://${cfg.offsiteBucket}/$FILE_NAME" \
                    ${optionalString (cfg.offsiteEndpoint != null) "--endpoint-url ${cfg.offsiteEndpoint}"} \
                    --quiet || true
                fi
              done
          '' else ''
            # Use rclone for flexible offsite backup
            ${optionalString (cfg.rcloneConfigFile != null) ''
              export RCLONE_CONFIG=${cfg.rcloneConfigFile}
            ''}

            ${pkgs.rclone}/bin/rclone copy "$BACKUP_FILE" "${cfg.offsiteBucket}/" \
              --progress=false

            ${optionalString cfg.verifyOffsiteUpload ''
              # Verify with rclone check
              if ! ${pkgs.rclone}/bin/rclone check "$BACKUP_FILE" "${cfg.offsiteBucket}/$BACKUP_FILENAME" --one-way 2>/dev/null; then
                echo "ERROR: Offsite backup verification failed!"
                exit 1
              fi
              echo "Offsite backup verified successfully"
            ''}

            # Cleanup old offsite backups
            echo "Cleaning up offsite backups older than ${toString cfg.offsiteRetentionDays} days..."
            ${pkgs.rclone}/bin/rclone delete "${cfg.offsiteBucket}/" \
              --min-age ${toString cfg.offsiteRetentionDays}d \
              --include "backup_*.sql.gz*" || true
          ''}

          echo "Offsite backup completed successfully"
        ''}
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
