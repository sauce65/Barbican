# Barbican Security Module: Diagnostic Doctor
#
# Provides a comprehensive health-check command that validates all
# Barbican security services are properly configured and running.
#
# Usage: barbican-doctor [--verbose] [--fix]
#
# NIST 800-53 Controls:
# - CM-4: Security Impact Analysis
# - CM-6: Configuration Settings
# - SI-6: Security Function Verification
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.doctor;

  # Color codes for terminal output
  colors = {
    red = "\\033[0;31m";
    green = "\\033[0;32m";
    yellow = "\\033[0;33m";
    blue = "\\033[0;34m";
    reset = "\\033[0m";
  };

  # Generate the doctor script
  doctorScript = pkgs.writeShellScript "barbican-doctor" ''
    #!/usr/bin/env bash
    set -euo pipefail

    # Parse arguments
    VERBOSE=false
    FIX=false
    for arg in "$@"; do
      case $arg in
        -v|--verbose) VERBOSE=true ;;
        --fix) FIX=true ;;
        -h|--help)
          echo "Usage: barbican-doctor [OPTIONS]"
          echo ""
          echo "Diagnose Barbican security infrastructure health."
          echo ""
          echo "Options:"
          echo "  -v, --verbose  Show detailed output"
          echo "  --fix          Attempt to fix common issues"
          echo "  -h, --help     Show this help message"
          exit 0
          ;;
      esac
    done

    # Counters
    PASS=0
    WARN=0
    FAIL=0

    # Output helpers
    pass() { echo -e "${colors.green}✓${colors.reset} $1"; ((PASS++)) || true; }
    warn() { echo -e "${colors.yellow}⚠${colors.reset} $1"; ((WARN++)) || true; }
    fail() { echo -e "${colors.red}✗${colors.reset} $1"; ((FAIL++)) || true; }
    info() { $VERBOSE && echo -e "${colors.blue}ℹ${colors.reset} $1" || true; }
    section() { echo -e "\n${colors.blue}━━━ $1 ━━━${colors.reset}"; }

    echo -e "${colors.blue}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║          Barbican Security Infrastructure Doctor          ║"
    echo "║              NIST 800-53 Compliance Check                 ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${colors.reset}"

    # ===== SYSTEMD SERVICES =====
    section "Systemd Services"

    check_service() {
      local service=$1
      local description=$2

      if systemctl is-active --quiet "$service" 2>/dev/null; then
        pass "$description ($service): running"
      elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
        warn "$description ($service): enabled but not running"
      else
        info "$description ($service): not configured"
      fi
    }

    # Check common Barbican services
    check_service "vault.service" "Vault PKI"
    check_service "vault-pki-setup.service" "Vault PKI Setup"
    check_service "barbican-observability.service" "Observability Stack"
    check_service "postgresql.service" "PostgreSQL"
    check_service "nginx.service" "Nginx"
    check_service "sshd.service" "SSH Daemon"
    check_service "systemd-timesyncd.service" "Time Sync"
    check_service "auditd.service" "Audit Daemon"

    # ===== NETWORK PORTS =====
    section "Network Ports"

    check_port() {
      local port=$1
      local service=$2
      local bind_addr=''${3:-"0.0.0.0"}

      if ${pkgs.netcat}/bin/nc -z localhost "$port" 2>/dev/null; then
        # Check if bound to expected address
        local actual_bind=$(${pkgs.iproute2}/bin/ss -tlnp 2>/dev/null | grep ":$port " | head -1 | awk '{print $4}' | cut -d: -f1)
        if [[ "$actual_bind" == "*" ]] || [[ "$actual_bind" == "0.0.0.0" ]] || [[ "$actual_bind" == "$bind_addr" ]]; then
          pass "$service (port $port): listening on $actual_bind"
        else
          warn "$service (port $port): listening on $actual_bind (expected $bind_addr)"
        fi
      else
        info "$service (port $port): not listening"
      fi
    }

    check_port 8200 "Vault API"
    check_port 9090 "Prometheus"
    check_port 3000 "Grafana"
    check_port 3100 "Loki"
    check_port 9093 "Alertmanager"
    check_port 5432 "PostgreSQL"
    check_port 80 "HTTP"
    check_port 443 "HTTPS"
    check_port 22 "SSH"

    # ===== VAULT PKI =====
    section "Vault PKI (SC-12, SC-17)"

    if command -v vault &>/dev/null && [[ -n "''${VAULT_ADDR:-}" ]]; then
      if vault status &>/dev/null; then
        pass "Vault is accessible"

        # Check PKI mounts
        if vault secrets list 2>/dev/null | grep -q "pki/"; then
          pass "PKI secrets engine mounted"
        else
          warn "PKI secrets engine not mounted"
        fi

        if vault secrets list 2>/dev/null | grep -q "pki_int/"; then
          pass "Intermediate PKI mounted"
        else
          warn "Intermediate PKI not mounted"
        fi

        # Check if sealed
        if vault status 2>/dev/null | grep -q "Sealed.*false"; then
          pass "Vault is unsealed"
        else
          fail "Vault is sealed"
        fi
      else
        warn "Vault not accessible (VAULT_ADDR=$VAULT_ADDR)"
      fi
    else
      info "Vault not configured (VAULT_ADDR not set)"
    fi

    # ===== CONTAINERS (PODMAN) =====
    section "Container Services"

    if command -v podman &>/dev/null; then
      # Check for running observability containers
      running_containers=$(${pkgs.podman}/bin/podman ps --format "{{.Names}}" 2>/dev/null || echo "")

      for container in prometheus grafana loki alertmanager; do
        if echo "$running_containers" | grep -qi "$container"; then
          pass "Container $container: running"
        else
          info "Container $container: not running"
        fi
      done
    else
      info "Podman not available"
    fi

    # ===== SECURITY CONFIGURATION =====
    section "Security Configuration (AC-*, SC-*)"

    # Check firewall
    if systemctl is-active --quiet firewalld 2>/dev/null || systemctl is-active --quiet nftables 2>/dev/null; then
      pass "Firewall active"
    elif [[ -f /etc/nftables.conf ]] || ${pkgs.iptables}/bin/iptables -L -n 2>/dev/null | grep -q "DROP"; then
      pass "Firewall rules configured"
    else
      warn "No firewall detected"
    fi

    # Check SSH configuration
    if [[ -f /etc/ssh/sshd_config ]]; then
      if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        pass "SSH: Root login disabled"
      else
        warn "SSH: Root login may be enabled"
      fi

      if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        pass "SSH: Password auth disabled"
      else
        warn "SSH: Password authentication may be enabled"
      fi
    else
      info "SSH not configured"
    fi

    # Check kernel hardening
    if sysctl kernel.kptr_restrict 2>/dev/null | grep -q "= 2"; then
      pass "Kernel: kptr_restrict=2"
    else
      warn "Kernel: kptr_restrict not hardened"
    fi

    if sysctl kernel.dmesg_restrict 2>/dev/null | grep -q "= 1"; then
      pass "Kernel: dmesg_restrict=1"
    else
      warn "Kernel: dmesg_restrict not set"
    fi

    # ===== AUDIT LOGGING (AU-*) =====
    section "Audit Logging (AU-2, AU-12)"

    if systemctl is-active --quiet auditd 2>/dev/null; then
      pass "Auditd running"

      if [[ -f /var/log/audit/audit.log ]]; then
        log_size=$(du -h /var/log/audit/audit.log 2>/dev/null | cut -f1)
        pass "Audit log exists ($log_size)"
      else
        warn "Audit log file not found"
      fi
    else
      warn "Auditd not running"
    fi

    if [[ -f /var/log/vault/audit.log ]]; then
      vault_log_size=$(du -h /var/log/vault/audit.log 2>/dev/null | cut -f1)
      pass "Vault audit log exists ($vault_log_size)"
    else
      info "Vault audit log not present"
    fi

    # ===== TLS/CERTIFICATES (SC-8, SC-12) =====
    section "TLS Configuration (SC-8)"

    check_cert() {
      local cert_path=$1
      local name=$2

      if [[ -f "$cert_path" ]]; then
        expiry=$(${pkgs.openssl}/bin/openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2)
        expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

        if [[ $days_left -gt 30 ]]; then
          pass "$name: valid ($days_left days remaining)"
        elif [[ $days_left -gt 0 ]]; then
          warn "$name: expiring soon ($days_left days remaining)"
        else
          fail "$name: expired or invalid"
        fi
      else
        info "$name: not found at $cert_path"
      fi
    }

    check_cert "/var/lib/vault/certs/ca.crt" "Vault CA"
    check_cert "/etc/ssl/certs/server.crt" "Server TLS"
    check_cert "/etc/nginx/ssl/cert.pem" "Nginx TLS"

    # ===== DATABASE (AU-9) =====
    section "Database Security"

    if command -v psql &>/dev/null && [[ -n "''${DATABASE_URL:-}" ]]; then
      if psql "$DATABASE_URL" -c "SELECT 1" &>/dev/null; then
        pass "PostgreSQL connection successful"
      else
        warn "PostgreSQL connection failed"
      fi
    else
      info "PostgreSQL client or DATABASE_URL not configured"
    fi

    # ===== TIME SYNC (AU-8) =====
    section "Time Synchronization (AU-8)"

    if timedatectl show 2>/dev/null | grep -q "NTPSynchronized=yes"; then
      pass "NTP synchronized"
    else
      warn "NTP not synchronized"
    fi

    # ===== CONFIG-AWARE CHECKS =====
    ${configChecks}

    # ===== SUMMARY =====
    echo ""
    echo -e "${colors.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}"
    echo ""
    echo -e "  Results: ${colors.green}$PASS passed${colors.reset}, ${colors.yellow}$WARN warnings${colors.reset}, ${colors.red}$FAIL failed${colors.reset}"
    echo ""

    if [[ $FAIL -gt 0 ]]; then
      echo -e "  ${colors.red}⚠ Critical issues detected. Review failures above.${colors.reset}"
      exit 1
    elif [[ $WARN -gt 0 ]]; then
      echo -e "  ${colors.yellow}ℹ Some warnings. Review recommendations above.${colors.reset}"
      exit 0
    else
      echo -e "  ${colors.green}✓ All checks passed. Infrastructure looks healthy.${colors.reset}"
      exit 0
    fi
  '';

  # Config-aware checks generated from NixOS module state
  configChecks =
    let
      # Safe attribute access
      atPath = path: default: lib.attrByPath path default config;

      vmFirewallEnabled = atPath [ "barbican" "vmFirewall" "enable" ] false;
      nftablesEnabled = atPath [ "networking" "nftables" "enable" ] false;

      keycloakEnabled = atPath [ "barbican" "keycloak" "enable" ] false;
      keycloakMgmtPort = toString (atPath [ "barbican" "keycloak" "ports" "management" ] 9000);
      keycloakHostname = atPath [ "barbican" "keycloak" "hostname" ] "localhost";
      keycloakSelfSigned = atPath [ "barbican" "keycloak" "tls" "selfSigned" ] false;

      ebsRecoveryEnabled = atPath [ "barbican" "ebsRecovery" "enable" ] false;
      ebsRecoveryRegion = atPath [ "barbican" "ebsRecovery" "awsRegion" ] "";
      ebsRecoveryPriority = atPath [ "barbican" "ebsRecovery" "priority" ] "standard";
    in
    # nftables conflict detection
    (optionalString (vmFirewallEnabled && nftablesEnabled) ''
      section "Configuration Conflicts"
      fail "barbican.vmFirewall and networking.nftables are both enabled (iptables vs nftables conflict)"
    '')
    # Keycloak health check
    + (optionalString keycloakEnabled ''
      section "Keycloak (IA-2)"

      # Check management port for health (try HTTPS first, fall back to HTTP)
      kc_health=""
      kc_health=$(${pkgs.curl}/bin/curl -sk "https://localhost:${keycloakMgmtPort}/health/ready" 2>/dev/null) || \
        kc_health=$(${pkgs.curl}/bin/curl -s "http://localhost:${keycloakMgmtPort}/health/ready" 2>/dev/null) || true

      if echo "$kc_health" | ${pkgs.jq}/bin/jq -e '.status == "UP"' &>/dev/null; then
        pass "Keycloak health (port ${keycloakMgmtPort}): UP"
      elif [ -n "$kc_health" ]; then
        warn "Keycloak health (port ${keycloakMgmtPort}): responded but not UP — $kc_health"
      else
        fail "Keycloak health (port ${keycloakMgmtPort}): no response"
      fi
    '')
    # Keycloak self-signed cert expiry check
    + (optionalString (keycloakEnabled && keycloakSelfSigned) ''
      check_cert "/run/keycloak/certs/cert.pem" "Keycloak self-signed TLS"
    '')
    # EBS Recovery health check (CP-9)
    + (optionalString ebsRecoveryEnabled ''
      section "EBS Recovery (CP-9)"

      # Check if snapshot timer is active
      if systemctl is-active --quiet barbican-ebs-snapshot.timer 2>/dev/null; then
        pass "EBS snapshot timer: active"
      else
        fail "EBS snapshot timer: not active"
      fi

      # Check for recent snapshots
      HOSTNAME=$(hostname)
      MAX_AGE_HOURS=${ if ebsRecoveryPriority == "critical" then "12" else if ebsRecoveryPriority == "standard" then "48" else "192" }

      LATEST=$(${pkgs.awscli2}/bin/aws ec2 describe-snapshots \
        --owner-ids self \
        --filters \
          "Name=tag:ManagedBy,Values=barbican" \
          "Name=tag:Hostname,Values=$HOSTNAME" \
        --query 'reverse(sort_by(Snapshots,&StartTime))[0].StartTime' \
        --output text \
        --region "${ebsRecoveryRegion}" 2>/dev/null || echo "None")

      if [ "$LATEST" = "None" ] || [ -z "$LATEST" ]; then
        warn "EBS snapshots: none found (may be first run)"
      else
        LATEST_EPOCH=$(date -d "$LATEST" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        AGE_HOURS=$(( (NOW_EPOCH - LATEST_EPOCH) / 3600 ))

        if [ "$AGE_HOURS" -gt "$MAX_AGE_HOURS" ]; then
          fail "EBS snapshots: stale ($AGE_HOURS hours old, threshold: $MAX_AGE_HOURS)"
        else
          pass "EBS snapshots: fresh ($AGE_HOURS hours old)"
        fi
      fi

      # Check last run status
      if systemctl show barbican-ebs-snapshot.service --property=ActiveState 2>/dev/null | grep -q "failed"; then
        fail "EBS snapshot service: last run failed"
      else
        info "EBS snapshot service: no recent failures"
      fi
    '');

in {
  options.barbican.doctor = {
    enable = mkEnableOption "Barbican doctor diagnostic command";

    extraChecks = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional shell commands to run as health checks";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [
      (pkgs.runCommand "barbican-doctor" { } ''
        mkdir -p $out/bin
        cp ${doctorScript} $out/bin/barbican-doctor
        chmod +x $out/bin/barbican-doctor
      '')
    ];
  };
}
