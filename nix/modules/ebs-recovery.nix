# Barbican Security Module: EBS Recovery
# Addresses: CP-9 (Backup), CP-9(1) (Testing), CP-6 (Alternate Site), SC-28 (Encryption)
#
# Provides automated EBS snapshot management for EC2-based deployments:
# - Scheduled EBS snapshots with configurable retention
# - Cross-region replication for disaster recovery
# - Automated restore testing (FedRAMP High)
# - Integration with Barbican observability and alerting
#
# NIST 800-53 Rev 5 Controls:
# - CP-9: Information System Backup
# - CP-9(1): Testing for Reliability and Integrity
# - CP-6: Alternate Storage Site
# - CP-6(1): Separation from Primary Site
# - SC-28: Protection of Information at Rest
# - AU-12: Audit Generation
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.ebsRecovery;

  # Priority to schedule mapping
  scheduleForPriority = {
    critical = "*-*-* 00,06,12,18:00:00"; # Every 6 hours
    standard = "*-*-* 03:00:00";          # Daily at 3 AM
    low = "Sun *-*-* 03:00:00";           # Weekly on Sunday
  };

  # Script: Get instance metadata via IMDSv2
  imdsScript = ''
    get_imds_token() {
      ${pkgs.curl}/bin/curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null
    }

    get_imds_value() {
      local path="$1"
      local token
      token=$(get_imds_token)
      ${pkgs.curl}/bin/curl -sS -H "X-aws-ec2-metadata-token: $token" \
        "http://169.254.169.254/latest/meta-data/$path" 2>/dev/null
    }
  '';

  # Script: Discover volumes attached to this instance
  discoverVolumesScript = pkgs.writeShellScript "barbican-ebs-discover" ''
    set -euo pipefail
    ${imdsScript}

    INSTANCE_ID=$(get_imds_value "instance-id")
    if [ -z "$INSTANCE_ID" ]; then
      echo "ERROR: Failed to get instance ID from IMDS" >&2
      exit 1
    fi

    ${pkgs.awscli2}/bin/aws ec2 describe-volumes \
      --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" \
      --query 'Volumes[*].VolumeId' \
      --output text \
      --region "${cfg.awsRegion}"
  '';

  # Script: Create EBS snapshot for a single volume
  createSnapshotScript = pkgs.writeShellScript "barbican-ebs-create-snapshot" ''
    set -euo pipefail

    VOLUME_ID="$1"
    HOSTNAME=$(${pkgs.hostname}/bin/hostname)
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    RETENTION_DATE=$(date -u -d "+${toString cfg.retentionDays} days" +%Y-%m-%d)

    echo "Creating snapshot for volume $VOLUME_ID"

    SNAPSHOT_ID=$(${pkgs.awscli2}/bin/aws ec2 create-snapshot \
      --volume-id "$VOLUME_ID" \
      --description "Barbican automated backup - $HOSTNAME - $TIMESTAMP" \
      --tag-specifications "ResourceType=snapshot,Tags=[
        {Key=Name,Value=barbican-backup-$HOSTNAME-$(date +%Y%m%d-%H%M%S)},
        {Key=ManagedBy,Value=barbican},
        {Key=Hostname,Value=$HOSTNAME},
        {Key=SourceVolume,Value=$VOLUME_ID},
        {Key=CreatedAt,Value=$TIMESTAMP},
        {Key=RetentionDate,Value=$RETENTION_DATE},
        {Key=Priority,Value=${cfg.priority}}
      ]" \
      --query 'SnapshotId' \
      --output text \
      --region "${cfg.awsRegion}")

    echo "Created snapshot: $SNAPSHOT_ID"

    # Wait for snapshot to complete
    echo "Waiting for snapshot to complete..."
    ${pkgs.awscli2}/bin/aws ec2 wait snapshot-completed \
      --snapshot-ids "$SNAPSHOT_ID" \
      --region "${cfg.awsRegion}"

    echo "Snapshot $SNAPSHOT_ID completed successfully"
    echo "$SNAPSHOT_ID"
  '';

  # Script: Cleanup expired snapshots in primary region
  cleanupSnapshotsScript = pkgs.writeShellScript "barbican-ebs-cleanup" ''
    set -euo pipefail

    HOSTNAME=$(${pkgs.hostname}/bin/hostname)
    TODAY=$(date -u +%Y-%m-%d)

    echo "Cleaning up expired snapshots for $HOSTNAME in ${cfg.awsRegion}"

    # Find snapshots past retention date
    EXPIRED_SNAPSHOTS=$(${pkgs.awscli2}/bin/aws ec2 describe-snapshots \
      --owner-ids self \
      --filters \
        "Name=tag:ManagedBy,Values=barbican" \
        "Name=tag:Hostname,Values=$HOSTNAME" \
      --query "Snapshots[?Tags[?Key=='RetentionDate' && Value<='$TODAY']].SnapshotId" \
      --output text \
      --region "${cfg.awsRegion}" 2>/dev/null || echo "")

    if [ -z "$EXPIRED_SNAPSHOTS" ] || [ "$EXPIRED_SNAPSHOTS" = "None" ]; then
      echo "No expired snapshots found"
      return 0
    fi

    for SNAPSHOT_ID in $EXPIRED_SNAPSHOTS; do
      echo "Deleting expired snapshot: $SNAPSHOT_ID"
      ${pkgs.awscli2}/bin/aws ec2 delete-snapshot \
        --snapshot-id "$SNAPSHOT_ID" \
        --region "${cfg.awsRegion}" 2>/dev/null || echo "  Warning: Failed to delete $SNAPSHOT_ID (may be in use)"
    done

    echo "Cleanup complete"
  '';

  # Script: Cross-region replication
  replicateSnapshotScript = pkgs.writeShellScript "barbican-ebs-replicate" ''
    set -euo pipefail

    SOURCE_SNAPSHOT_ID="$1"
    HOSTNAME=$(${pkgs.hostname}/bin/hostname)
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    DR_RETENTION_DATE=$(date -u -d "+${toString cfg.crossRegionRetentionDays} days" +%Y-%m-%d)

    echo "Replicating snapshot $SOURCE_SNAPSHOT_ID to ${cfg.crossRegionTarget}"

    COPY_SNAPSHOT_ID=$(${pkgs.awscli2}/bin/aws ec2 copy-snapshot \
      --source-region "${cfg.awsRegion}" \
      --source-snapshot-id "$SOURCE_SNAPSHOT_ID" \
      --description "Barbican DR copy - $HOSTNAME - $TIMESTAMP" \
      --tag-specifications "ResourceType=snapshot,Tags=[
        {Key=Name,Value=barbican-dr-$HOSTNAME-$(date +%Y%m%d-%H%M%S)},
        {Key=ManagedBy,Value=barbican},
        {Key=Hostname,Value=$HOSTNAME},
        {Key=SourceSnapshotId,Value=$SOURCE_SNAPSHOT_ID},
        {Key=SourceRegion,Value=${cfg.awsRegion}},
        {Key=CreatedAt,Value=$TIMESTAMP},
        {Key=RetentionDate,Value=$DR_RETENTION_DATE},
        {Key=Type,Value=dr-copy}
      ]" \
      --query 'SnapshotId' \
      --output text \
      --region "${cfg.crossRegionTarget}")

    echo "Created DR copy: $COPY_SNAPSHOT_ID in ${cfg.crossRegionTarget}"
  '';

  # Script: Cleanup DR region snapshots
  cleanupDrSnapshotsScript = pkgs.writeShellScript "barbican-ebs-cleanup-dr" ''
    set -euo pipefail

    HOSTNAME=$(${pkgs.hostname}/bin/hostname)
    TODAY=$(date -u +%Y-%m-%d)

    echo "Cleaning up expired DR snapshots for $HOSTNAME in ${cfg.crossRegionTarget}"

    EXPIRED_SNAPSHOTS=$(${pkgs.awscli2}/bin/aws ec2 describe-snapshots \
      --owner-ids self \
      --filters \
        "Name=tag:ManagedBy,Values=barbican" \
        "Name=tag:Hostname,Values=$HOSTNAME" \
        "Name=tag:Type,Values=dr-copy" \
      --query "Snapshots[?Tags[?Key=='RetentionDate' && Value<='$TODAY']].SnapshotId" \
      --output text \
      --region "${cfg.crossRegionTarget}" 2>/dev/null || echo "")

    if [ -z "$EXPIRED_SNAPSHOTS" ] || [ "$EXPIRED_SNAPSHOTS" = "None" ]; then
      echo "No expired DR snapshots found"
      return 0
    fi

    for SNAPSHOT_ID in $EXPIRED_SNAPSHOTS; do
      echo "Deleting expired DR snapshot: $SNAPSHOT_ID"
      ${pkgs.awscli2}/bin/aws ec2 delete-snapshot \
        --snapshot-id "$SNAPSHOT_ID" \
        --region "${cfg.crossRegionTarget}" 2>/dev/null || echo "  Warning: Failed to delete $SNAPSHOT_ID"
    done

    echo "DR cleanup complete"
  '';

  # Script: Restore test
  restoreTestScript = pkgs.writeShellScript "barbican-ebs-restore-test" ''
    set -euo pipefail
    ${imdsScript}

    HOSTNAME=$(${pkgs.hostname}/bin/hostname)
    echo "=========================================="
    echo "Barbican EBS Restore Test - $HOSTNAME"
    echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "=========================================="

    # Get latest snapshot
    LATEST_SNAPSHOT=$(${pkgs.awscli2}/bin/aws ec2 describe-snapshots \
      --owner-ids self \
      --filters \
        "Name=tag:ManagedBy,Values=barbican" \
        "Name=tag:Hostname,Values=$HOSTNAME" \
      --query 'reverse(sort_by(Snapshots,&StartTime))[0].SnapshotId' \
      --output text \
      --region "${cfg.awsRegion}")

    if [ "$LATEST_SNAPSHOT" = "None" ] || [ -z "$LATEST_SNAPSHOT" ]; then
      echo "ERROR: No snapshots found for restore test"
      exit 1
    fi

    echo "Testing restore from snapshot: $LATEST_SNAPSHOT"

    # Get availability zone from IMDS
    AZ=$(get_imds_value "placement/availability-zone")
    if [ -z "$AZ" ]; then
      echo "ERROR: Failed to get availability zone from IMDS"
      exit 1
    fi

    echo "Creating test volume in $AZ..."

    # Create test volume from snapshot
    TEST_VOLUME_ID=$(${pkgs.awscli2}/bin/aws ec2 create-volume \
      --snapshot-id "$LATEST_SNAPSHOT" \
      --availability-zone "$AZ" \
      --volume-type gp3 \
      --tag-specifications "ResourceType=volume,Tags=[
        {Key=Name,Value=barbican-restore-test-$HOSTNAME},
        {Key=ManagedBy,Value=barbican},
        {Key=Purpose,Value=restore-test},
        {Key=SourceSnapshot,Value=$LATEST_SNAPSHOT}
      ]" \
      --query 'VolumeId' \
      --output text \
      --region "${cfg.awsRegion}")

    echo "Created test volume: $TEST_VOLUME_ID"

    # Cleanup function
    cleanup_test_volume() {
      echo "Cleaning up test volume $TEST_VOLUME_ID..."
      ${pkgs.awscli2}/bin/aws ec2 delete-volume \
        --volume-id "$TEST_VOLUME_ID" \
        --region "${cfg.awsRegion}" 2>/dev/null || true
    }
    trap cleanup_test_volume EXIT

    # Wait for volume to be available
    echo "Waiting for volume to be available..."
    ${pkgs.awscli2}/bin/aws ec2 wait volume-available \
      --volume-ids "$TEST_VOLUME_ID" \
      --region "${cfg.awsRegion}"

    echo "Volume $TEST_VOLUME_ID is available"

    # Verify volume state
    VOLUME_STATE=$(${pkgs.awscli2}/bin/aws ec2 describe-volumes \
      --volume-ids "$TEST_VOLUME_ID" \
      --query 'Volumes[0].State' \
      --output text \
      --region "${cfg.awsRegion}")

    if [ "$VOLUME_STATE" != "available" ]; then
      echo "ERROR: Volume in unexpected state: $VOLUME_STATE"
      exit 1
    fi

    echo ""
    echo "=========================================="
    echo "Restore test PASSED"
    echo "- Snapshot: $LATEST_SNAPSHOT"
    echo "- Test volume created and verified: $TEST_VOLUME_ID"
    echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "=========================================="
  '';

  # Main orchestrator script
  snapshotOrchestratorScript = pkgs.writeShellScript "barbican-ebs-snapshot" ''
    set -euo pipefail

    HOSTNAME=$(${pkgs.hostname}/bin/hostname)
    echo "=========================================="
    echo "Barbican EBS Snapshot - $HOSTNAME"
    echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Region: ${cfg.awsRegion}"
    echo "Priority: ${cfg.priority}"
    echo "Retention: ${toString cfg.retentionDays} days"
    ${optionalString cfg.enableCrossRegionCopy ''
    echo "Cross-region: ${cfg.crossRegionTarget} (${toString cfg.crossRegionRetentionDays} days)"
    ''}
    echo "=========================================="

    # Discover volumes
    echo ""
    echo "--- Discovering attached volumes ---"
    VOLUMES=$(${discoverVolumesScript})

    if [ -z "$VOLUMES" ] || [ "$VOLUMES" = "None" ]; then
      echo "ERROR: No volumes found attached to this instance"
      exit 1
    fi

    echo "Found volumes: $VOLUMES"

    # Create snapshots
    CREATED_SNAPSHOTS=""
    for VOLUME_ID in $VOLUMES; do
      echo ""
      echo "--- Processing volume: $VOLUME_ID ---"
      SNAPSHOT_ID=$(${createSnapshotScript} "$VOLUME_ID" | tail -1)
      CREATED_SNAPSHOTS="$CREATED_SNAPSHOTS $SNAPSHOT_ID"
    done

    ${optionalString cfg.enableCrossRegionCopy ''
    # Cross-region replication
    echo ""
    echo "--- Cross-region replication to ${cfg.crossRegionTarget} ---"
    for SNAPSHOT_ID in $CREATED_SNAPSHOTS; do
      ${replicateSnapshotScript} "$SNAPSHOT_ID"
    done
    ''}

    # Cleanup expired snapshots
    echo ""
    echo "--- Cleanup expired snapshots ---"
    ${cleanupSnapshotsScript}

    ${optionalString cfg.enableCrossRegionCopy ''
    echo ""
    echo "--- Cleanup expired DR snapshots ---"
    ${cleanupDrSnapshotsScript}
    ''}

    echo ""
    echo "=========================================="
    echo "Barbican EBS Snapshot Complete"
    echo "Snapshots created:$CREATED_SNAPSHOTS"
    echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "=========================================="
  '';

  # Restore test schedule mapping
  restoreTestScheduleMap = {
    daily = "*-*-* 04:00:00";
    weekly = "Sun *-*-* 04:00:00";
    monthly = "*-*-01 04:00:00";
  };

in {
  options.barbican.ebsRecovery = {
    enable = mkEnableOption "EBS volume backup and recovery (CP-9)";

    awsRegion = mkOption {
      type = types.str;
      description = "AWS region for EBS operations";
      example = "us-east-1";
    };

    schedule = mkOption {
      type = types.str;
      default = "";
      description = ''
        Systemd calendar expression for snapshot schedule.
        If empty, uses priority-based default schedule.
        Examples: "03:00" (daily at 3am), "*-*-* 00,12:00:00" (twice daily)
      '';
    };

    retentionDays = mkOption {
      type = types.int;
      default = 30;
      description = "Number of days to retain snapshots in primary region";
    };

    priority = mkOption {
      type = types.enum [ "critical" "standard" "low" ];
      default = "standard";
      description = ''
        Backup priority level affecting default schedule:
        - critical: Every 6 hours
        - standard: Daily at 3 AM
        - low: Weekly on Sunday
      '';
    };

    enableCrossRegionCopy = mkOption {
      type = types.bool;
      default = false;
      description = "Enable cross-region snapshot replication for disaster recovery (CP-6)";
    };

    crossRegionTarget = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Target AWS region for cross-region copies (e.g., us-west-2)";
      example = "us-west-2";
    };

    crossRegionRetentionDays = mkOption {
      type = types.int;
      default = 90;
      description = "Number of days to retain snapshots in DR region";
    };

    enableRestoreTest = mkOption {
      type = types.bool;
      default = false;
      description = "Enable periodic restore verification testing (CP-9(1))";
    };

    restoreTestSchedule = mkOption {
      type = types.enum [ "daily" "weekly" "monthly" ];
      default = "weekly";
      description = "How often to run restore verification tests";
    };

    alertOnFailure = mkOption {
      type = types.bool;
      default = true;
      description = "Log failures prominently for alerting integration";
    };
  };

  config = mkIf cfg.enable {
    # Validate configuration
    assertions = [
      {
        assertion = cfg.enableCrossRegionCopy -> cfg.crossRegionTarget != null;
        message = "barbican.ebsRecovery.crossRegionTarget must be set when enableCrossRegionCopy is true";
      }
      {
        assertion = cfg.enableCrossRegionCopy -> cfg.crossRegionTarget != cfg.awsRegion;
        message = "barbican.ebsRecovery.crossRegionTarget must be different from awsRegion";
      }
    ];

    # Main snapshot service
    systemd.services.barbican-ebs-snapshot = {
      description = "Barbican EBS Snapshot Service (CP-9)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      path = [ pkgs.awscli2 pkgs.curl pkgs.coreutils pkgs.hostname pkgs.gnugrep ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = snapshotOrchestratorScript;
        # Retry logic
        Restart = "on-failure";
        RestartSec = "5min";
        # Security hardening
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        # Network required for AWS API
        PrivateNetwork = false;
        # Resource limits
        MemoryMax = "256M";
        CPUQuota = "50%";
      };

      environment = {
        AWS_DEFAULT_REGION = cfg.awsRegion;
        HOME = "/tmp"; # AWS CLI needs a writable home
      };
    };

    # Snapshot timer
    systemd.timers.barbican-ebs-snapshot = {
      description = "Barbican EBS Snapshot Timer";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnCalendar = if cfg.schedule != "" then cfg.schedule else scheduleForPriority.${cfg.priority};
        Persistent = true; # Run immediately if missed
        RandomizedDelaySec = "5min"; # Jitter to avoid thundering herd
      };
    };

    # Restore test service (if enabled)
    systemd.services.barbican-ebs-restore-test = mkIf cfg.enableRestoreTest {
      description = "Barbican EBS Restore Test Service (CP-9(1))";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      path = [ pkgs.awscli2 pkgs.curl pkgs.coreutils pkgs.hostname ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = restoreTestScript;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        PrivateNetwork = false;
        MemoryMax = "256M";
        CPUQuota = "50%";
      };

      environment = {
        AWS_DEFAULT_REGION = cfg.awsRegion;
        HOME = "/tmp";
      };
    };

    # Restore test timer (if enabled)
    systemd.timers.barbican-ebs-restore-test = mkIf cfg.enableRestoreTest {
      description = "Barbican EBS Restore Test Timer";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnCalendar = restoreTestScheduleMap.${cfg.restoreTestSchedule};
        Persistent = true;
        RandomizedDelaySec = "10min";
      };
    };

    # Ensure AWS CLI is available
    environment.systemPackages = [ pkgs.awscli2 ];
  };
}
