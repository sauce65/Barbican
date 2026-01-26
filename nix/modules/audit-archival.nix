# Barbican Security Module: Audit Log Export & Archival
#
# NIST 800-53 Controls:
# - AU-9(2): Audit Storage on Separate System
# - AU-11: Audit Record Retention
#
# Archives audit log sources with age encryption and HMAC-SHA256 tamper
# detection. Follows the database-backup.nix pattern for S3 offsite upload.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.auditArchival;

  # Source submodule
  sourceType = types.submodule {
    options = {
      path = mkOption {
        type = types.str;
        description = "Path to audit log file or directory to archive";
        example = "/var/log/vault/audit.log";
      };

      label = mkOption {
        type = types.str;
        default = "";
        description = "Label for this source in the archive filename";
      };
    };
  };

  archiveScript = pkgs.writeShellScript "barbican-audit-archive" ''
    set -euo pipefail

    ARCHIVE_DIR="${cfg.archivePath}"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    mkdir -p "$ARCHIVE_DIR"
    chmod 700 "$ARCHIVE_DIR"

    echo "=== Barbican Audit Archival ==="
    echo "Time: $(date -Iseconds)"

    ${concatMapStringsSep "\n" (source: let
      label = if source.label != "" then source.label
              else replaceStrings ["/"] ["_"] (removePrefix "/" source.path);
    in ''
      # Archive: ${source.path}
      if [ -e "${source.path}" ]; then
        ARCHIVE_FILE="$ARCHIVE_DIR/audit_${label}_$TIMESTAMP.tar.gz"
        echo "Archiving ${source.path} -> $ARCHIVE_FILE"

        tar czf "$ARCHIVE_FILE" -C "$(dirname "${source.path}")" "$(basename "${source.path}")" 2>/dev/null || {
          echo "WARNING: Failed to archive ${source.path}"
        }

        if [ -f "$ARCHIVE_FILE" ]; then
          ${optionalString cfg.enableEncryption ''
            # SC-28: Encrypt with age
            ${pkgs.age}/bin/age -R ${toString cfg.encryptionKeyFile} \
              -o "$ARCHIVE_FILE.age" "$ARCHIVE_FILE"
            rm -f "$ARCHIVE_FILE"
            ARCHIVE_FILE="$ARCHIVE_FILE.age"
          ''}

          ${optionalString cfg.enableHmacSigning ''
            # AU-9: HMAC-SHA256 tamper detection
            HMAC_KEY=$(cat ${toString cfg.hmacKeyFile})
            echo -n "$HMAC_KEY" | ${pkgs.openssl}/bin/openssl dgst -sha256 -hmac "$(cat ${toString cfg.hmacKeyFile})" \
              -binary "$ARCHIVE_FILE" | ${pkgs.coreutils}/bin/base64 > "$ARCHIVE_FILE.hmac"
            echo "HMAC signature: $ARCHIVE_FILE.hmac"
          ''}

          chmod 600 "$ARCHIVE_FILE"*
          echo "Archived: $ARCHIVE_FILE"
        fi
      else
        echo "SKIP: ${source.path} does not exist"
      fi
    '') cfg.sources}

    ${optionalString cfg.enableOffsiteArchival ''
      # AU-9(2): Upload to offsite storage
      echo "Uploading archives to offsite storage..."
      for archive in "$ARCHIVE_DIR"/audit_*_$TIMESTAMP.*; do
        [ -f "$archive" ] || continue
        FILENAME=$(basename "$archive")
        ${pkgs.awscli2}/bin/aws s3 cp "$archive" \
          "s3://${cfg.offsiteBucket}/$FILENAME" \
          --no-progress || echo "WARNING: Failed to upload $FILENAME"
      done
      echo "Offsite upload complete"
    ''}

    # AU-11: Retention cleanup
    echo "Cleaning up archives older than ${toString cfg.retentionDays} days..."
    find "$ARCHIVE_DIR" -name "audit_*" -mtime +${toString cfg.retentionDays} -delete 2>/dev/null || true

    echo "=== Archival Complete ==="
  '';

in {
  options.barbican.auditArchival = {
    enable = mkEnableOption "Audit log archival (AU-9(2), AU-11)";

    schedule = mkOption {
      type = types.str;
      default = "01:00";
      description = "Time for daily archival (HH:MM format)";
    };

    sources = mkOption {
      type = types.listOf sourceType;
      default = [];
      description = "Audit log sources to archive";
      example = literalExpression ''
        [
          { path = "/var/log/vault/audit.log"; label = "vault"; }
          { path = "/var/log/audit"; label = "auditd"; }
        ]
      '';
    };

    enableEncryption = mkOption {
      type = types.bool;
      default = true;
      description = "Encrypt archives with age (SC-28)";
    };

    encryptionKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to age public key file for archive encryption";
    };

    enableHmacSigning = mkOption {
      type = types.bool;
      default = true;
      description = "Sign archives with HMAC-SHA256 for tamper detection (AU-9)";
    };

    hmacKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to HMAC signing key file";
    };

    enableOffsiteArchival = mkOption {
      type = types.bool;
      default = false;
      description = "Upload archives to offsite S3 storage (AU-9(2))";
    };

    offsiteBucket = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "S3 bucket for offsite archive storage";
      example = "my-audit-archives/barbican";
    };

    retentionDays = mkOption {
      type = types.int;
      default = 365;
      description = "Number of days to retain local archives (AU-11)";
    };

    archivePath = mkOption {
      type = types.path;
      default = "/var/lib/barbican/audit-archives";
      description = "Local directory for audit archives";
    };
  };

  config = mkIf cfg.enable {
    # Archive service (oneshot)
    systemd.services.barbican-audit-archive = {
      description = "Barbican Audit Log Archival (AU-9, AU-11)";
      after = [ "network-online.target" ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${archiveScript}";
      };

      path = [ pkgs.gzip pkgs.gnutar pkgs.coreutils pkgs.findutils ]
        ++ optional cfg.enableEncryption pkgs.age
        ++ optional cfg.enableHmacSigning pkgs.openssl
        ++ optional cfg.enableOffsiteArchival pkgs.awscli2;
    };

    # Archive timer
    systemd.timers.barbican-audit-archive = {
      description = "Barbican Audit Archive Timer";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnCalendar = "*-*-* ${cfg.schedule}";
        Persistent = true;
        RandomizedDelaySec = "5m";
      };
    };

    # Ensure archive directory exists
    systemd.tmpfiles.rules = [
      "d ${cfg.archivePath} 0700 root root -"
    ];

    assertions = [
      {
        assertion = !cfg.enableEncryption || cfg.encryptionKeyFile != null;
        message = "Audit archival encryption requires encryptionKeyFile to be set";
      }
      {
        assertion = !cfg.enableHmacSigning || cfg.hmacKeyFile != null;
        message = "Audit archival HMAC signing requires hmacKeyFile to be set";
      }
      {
        assertion = !cfg.enableOffsiteArchival || cfg.offsiteBucket != null;
        message = "Offsite archival requires offsiteBucket to be set";
      }
    ];
  };
}
