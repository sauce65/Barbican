//! Script Generation
//!
//! Generates helper scripts for the observability stack.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::{ComplianceProfile, GeneratedFile, ObservabilityComplianceConfig, StackResult};

/// Generate helper scripts
pub fn generate(
    output_dir: &Path,
    fedramp: &ObservabilityComplianceConfig,
    app_name: &str,
) -> StackResult<Vec<GeneratedFile>> {
    let mut files = Vec::new();
    let scripts_dir = output_dir.join("scripts");

    // Certificate generation script (only for non-development profiles)
    if fedramp.tls_enabled() {
        let gen_certs = generate_cert_script(fedramp, app_name);
        let certs_path = scripts_dir.join("gen-certs.sh");
        fs::write(&certs_path, gen_certs)?;
        make_executable(&certs_path)?;
        files.push(
            GeneratedFile::new(&certs_path, "TLS certificate generation script")
                .with_controls(vec!["SC-8", "SC-12"])
        );
    }

    // Backup script
    if fedramp.backup_encryption {
        let backup = generate_backup_script(fedramp, app_name);
        let backup_path = scripts_dir.join("backup-audit-logs.sh");
        fs::write(&backup_path, backup)?;
        make_executable(&backup_path)?;
        files.push(
            GeneratedFile::new(&backup_path, "Encrypted backup script")
                .with_controls(vec!["CP-9", "SC-28"])
        );

        // Restore script
        let restore = generate_restore_script(fedramp, app_name);
        let restore_path = scripts_dir.join("restore-audit-logs.sh");
        fs::write(&restore_path, restore)?;
        make_executable(&restore_path)?;
        files.push(
            GeneratedFile::new(&restore_path, "Backup restore script")
                .with_controls(vec!["CP-9", "CP-10"])
        );
    }

    // Health check script
    let health = generate_health_script(fedramp, app_name);
    let health_path = scripts_dir.join("health-check.sh");
    fs::write(&health_path, health)?;
    make_executable(&health_path)?;
    files.push(
        GeneratedFile::new(&health_path, "Stack health check script")
            .with_controls(vec!["CA-7"])
    );

    // Startup script
    let startup = generate_startup_script(fedramp, app_name);
    let startup_path = scripts_dir.join("start-stack.sh");
    fs::write(&startup_path, startup)?;
    make_executable(&startup_path)?;
    files.push(
        GeneratedFile::new(&startup_path, "Stack startup script")
            .with_controls(vec![])
    );

    Ok(files)
}

fn make_executable(path: &Path) -> StackResult<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn generate_cert_script(fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    let validity_days = match fedramp.profile() {
        ComplianceProfile::FedRampHigh => 90, // Shorter validity for High
        _ => 365,
    };

    format!(
        r#"#!/bin/bash
# TLS Certificate Generation - {app_name} Observability Stack
# FedRAMP {profile} Profile
# Controls: SC-8 (TLS), SC-12 (Key Management)
#
# Prerequisites:
#   - mkcert (https://github.com/FiloSottile/mkcert)
#   - OR openssl
#
# Usage: ./gen-certs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
CERTS_DIR="${{SCRIPT_DIR}}/../certs"

# Certificate validity in days
VALIDITY_DAYS={validity_days}

# Services that need certificates
SERVICES=(loki prometheus grafana alertmanager)

echo "Generating TLS certificates for {app_name} observability stack..."
echo "FedRAMP Profile: {profile}"
echo "Certificate validity: ${{VALIDITY_DAYS}} days"
echo ""

# Create certificate directories
mkdir -p "${{CERTS_DIR}}"
for service in "${{SERVICES[@]}}"; do
    mkdir -p "${{CERTS_DIR}}/${{service}}"
done
mkdir -p "${{CERTS_DIR}}/clients"

# Check for mkcert
if command -v mkcert &> /dev/null; then
    echo "Using mkcert for certificate generation..."

    # Install CA if not already done
    if [ ! -f "$(mkcert -CAROOT)/rootCA.pem" ]; then
        echo "Installing mkcert CA (may require sudo)..."
        mkcert -install
    fi

    # Copy CA certificate
    cp "$(mkcert -CAROOT)/rootCA.pem" "${{CERTS_DIR}}/ca.crt"

    # Generate service certificates
    for service in "${{SERVICES[@]}}"; do
        echo "Generating certificate for ${{service}}..."
        mkcert -cert-file "${{CERTS_DIR}}/${{service}}/server.crt" \
               -key-file "${{CERTS_DIR}}/${{service}}/server.key" \
               "${{service}}" "localhost" "127.0.0.1" "::1"

        # Also generate client certificate for mTLS
        mkcert -client \
               -cert-file "${{CERTS_DIR}}/${{service}}/client.crt" \
               -key-file "${{CERTS_DIR}}/${{service}}/client.key" \
               "${{service}}-client"
    done

else
    echo "mkcert not found, using openssl..."

    # Generate CA
    if [ ! -f "${{CERTS_DIR}}/ca.key" ]; then
        echo "Generating CA..."
        openssl genrsa -out "${{CERTS_DIR}}/ca.key" 4096
        openssl req -x509 -new -nodes -key "${{CERTS_DIR}}/ca.key" \
            -sha256 -days ${{VALIDITY_DAYS}} \
            -out "${{CERTS_DIR}}/ca.crt" \
            -subj "/CN={app_name}-CA/O={app_name}"
    fi

    # Generate service certificates
    for service in "${{SERVICES[@]}}"; do
        echo "Generating certificate for ${{service}}..."

        # Create config for SAN
        cat > "${{CERTS_DIR}}/${{service}}/openssl.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${{service}}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${{service}}
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

        # Generate key and CSR
        openssl genrsa -out "${{CERTS_DIR}}/${{service}}/server.key" 2048
        openssl req -new -key "${{CERTS_DIR}}/${{service}}/server.key" \
            -out "${{CERTS_DIR}}/${{service}}/server.csr" \
            -config "${{CERTS_DIR}}/${{service}}/openssl.cnf"

        # Sign with CA
        openssl x509 -req -in "${{CERTS_DIR}}/${{service}}/server.csr" \
            -CA "${{CERTS_DIR}}/ca.crt" \
            -CAkey "${{CERTS_DIR}}/ca.key" \
            -CAcreateserial \
            -out "${{CERTS_DIR}}/${{service}}/server.crt" \
            -days ${{VALIDITY_DAYS}} \
            -sha256 \
            -extensions v3_req \
            -extfile "${{CERTS_DIR}}/${{service}}/openssl.cnf"

        # Generate client certificate
        openssl genrsa -out "${{CERTS_DIR}}/${{service}}/client.key" 2048
        openssl req -new -key "${{CERTS_DIR}}/${{service}}/client.key" \
            -out "${{CERTS_DIR}}/${{service}}/client.csr" \
            -subj "/CN=${{service}}-client"
        openssl x509 -req -in "${{CERTS_DIR}}/${{service}}/client.csr" \
            -CA "${{CERTS_DIR}}/ca.crt" \
            -CAkey "${{CERTS_DIR}}/ca.key" \
            -CAcreateserial \
            -out "${{CERTS_DIR}}/${{service}}/client.crt" \
            -days ${{VALIDITY_DAYS}} \
            -sha256

        # Clean up CSR
        rm -f "${{CERTS_DIR}}/${{service}}/server.csr" "${{CERTS_DIR}}/${{service}}/client.csr"
    done
fi

# Set appropriate permissions
echo "Setting certificate permissions..."
chmod 644 "${{CERTS_DIR}}/ca.crt"
for service in "${{SERVICES[@]}}"; do
    chmod 644 "${{CERTS_DIR}}/${{service}}/server.crt"
    chmod 600 "${{CERTS_DIR}}/${{service}}/server.key"
    chmod 644 "${{CERTS_DIR}}/${{service}}/client.crt"
    chmod 600 "${{CERTS_DIR}}/${{service}}/client.key"
done

echo ""
echo "Certificate generation complete!"
echo "Certificates are in: ${{CERTS_DIR}}"
echo ""
echo "Certificate expiration: $(date -d "+${{VALIDITY_DAYS}} days" '+%Y-%m-%d')"
echo ""
echo "Next steps:"
echo "  1. Review generated certificates"
echo "  2. Add CA to your system trust store if needed"
echo "  3. Start the observability stack: docker-compose up -d"
"#,
        app_name = app_name,
        profile = fedramp.profile().name(),
        validity_days = validity_days,
    )
}

fn generate_backup_script(fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    format!(
        r#"#!/bin/bash
# Encrypted Backup Script - {app_name} Observability Stack
# FedRAMP {profile} Profile
# Controls: CP-9 (Backup), SC-28 (Encryption at Rest)
#
# Prerequisites:
#   - BACKUP_ENCRYPTION_KEY environment variable
#   - docker and docker-compose
#
# Usage: ./backup-audit-logs.sh [backup_dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
BACKUP_DIR="${{1:-${{SCRIPT_DIR}}/../backups}}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${{BACKUP_DIR}}/{app_name}_observability_${{TIMESTAMP}}.tar.gz"
ENCRYPTED_FILE="${{BACKUP_FILE}}.enc"

# Retention settings
RETENTION_DAYS={retention_days}

# Verify encryption key is set
if [ -z "${{BACKUP_ENCRYPTION_KEY:-}}" ]; then
    echo "ERROR: BACKUP_ENCRYPTION_KEY environment variable not set"
    echo "Generate one with: openssl rand -base64 32"
    exit 1
fi

echo "Starting encrypted backup..."
echo "FedRAMP Profile: {profile}"
echo "Backup location: ${{BACKUP_DIR}}"
echo ""

# Create backup directory
mkdir -p "${{BACKUP_DIR}}"

# Create temporary directory for backup
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${{TEMP_DIR}}" EXIT

echo "Backing up Loki data..."
docker cp {app_name}-loki:/loki/data "${{TEMP_DIR}}/loki-data" 2>/dev/null || echo "  (Loki data not found or empty)"

echo "Backing up Prometheus data..."
docker cp {app_name}-prometheus:/prometheus "${{TEMP_DIR}}/prometheus-data" 2>/dev/null || echo "  (Prometheus data not found or empty)"

echo "Backing up Grafana data..."
docker cp {app_name}-grafana:/var/lib/grafana "${{TEMP_DIR}}/grafana-data" 2>/dev/null || echo "  (Grafana data not found or empty)"

echo "Backing up configuration files..."
cp -r "${{SCRIPT_DIR}}/../loki" "${{TEMP_DIR}}/config-loki"
cp -r "${{SCRIPT_DIR}}/../prometheus" "${{TEMP_DIR}}/config-prometheus"
cp -r "${{SCRIPT_DIR}}/../grafana" "${{TEMP_DIR}}/config-grafana"
cp -r "${{SCRIPT_DIR}}/../alertmanager" "${{TEMP_DIR}}/config-alertmanager"

# Create metadata file
cat > "${{TEMP_DIR}}/backup-metadata.json" << EOF
{{
    "app_name": "{app_name}",
    "fedramp_profile": "{profile}",
    "timestamp": "${{TIMESTAMP}}",
    "created_by": "$(whoami)",
    "hostname": "$(hostname)",
    "control": "CP-9"
}}
EOF

echo "Creating compressed archive..."
tar -czf "${{BACKUP_FILE}}" -C "${{TEMP_DIR}}" .

echo "Encrypting backup with AES-256-CBC..."
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "${{BACKUP_FILE}}" \
    -out "${{ENCRYPTED_FILE}}" \
    -pass env:BACKUP_ENCRYPTION_KEY

# Remove unencrypted backup
rm -f "${{BACKUP_FILE}}"

# Calculate checksum
sha256sum "${{ENCRYPTED_FILE}}" > "${{ENCRYPTED_FILE}}.sha256"

echo ""
echo "Backup complete!"
echo "  File: ${{ENCRYPTED_FILE}}"
echo "  Size: $(du -h "${{ENCRYPTED_FILE}}" | cut -f1)"
echo "  SHA256: $(cat "${{ENCRYPTED_FILE}}.sha256" | cut -d' ' -f1)"
echo ""

# Clean up old backups
echo "Cleaning up backups older than ${{RETENTION_DAYS}} days..."
find "${{BACKUP_DIR}}" -name "{app_name}_observability_*.tar.gz.enc" -mtime +${{RETENTION_DAYS}} -delete
find "${{BACKUP_DIR}}" -name "{app_name}_observability_*.tar.gz.enc.sha256" -mtime +${{RETENTION_DAYS}} -delete

echo "Remaining backups:"
ls -lh "${{BACKUP_DIR}}"/{app_name}_observability_*.tar.gz.enc 2>/dev/null || echo "  (no backups found)"
"#,
        app_name = app_name,
        profile = fedramp.profile().name(),
        retention_days = fedramp.backup_retention_days,
    )
}

fn generate_restore_script(fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    format!(
        r#"#!/bin/bash
# Backup Restore Script - {app_name} Observability Stack
# FedRAMP {profile} Profile
# Controls: CP-9 (Backup), CP-10 (Recovery)
#
# Prerequisites:
#   - BACKUP_ENCRYPTION_KEY environment variable (same as used for backup)
#   - docker and docker-compose
#
# Usage: ./restore-audit-logs.sh <backup_file.tar.gz.enc>

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file.tar.gz.enc>"
    exit 1
fi

BACKUP_FILE="$1"
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

# Verify backup file exists
if [ ! -f "${{BACKUP_FILE}}" ]; then
    echo "ERROR: Backup file not found: ${{BACKUP_FILE}}"
    exit 1
fi

# Verify encryption key is set
if [ -z "${{BACKUP_ENCRYPTION_KEY:-}}" ]; then
    echo "ERROR: BACKUP_ENCRYPTION_KEY environment variable not set"
    exit 1
fi

# Verify checksum if available
if [ -f "${{BACKUP_FILE}}.sha256" ]; then
    echo "Verifying backup integrity..."
    sha256sum -c "${{BACKUP_FILE}}.sha256" || {{
        echo "ERROR: Checksum verification failed!"
        exit 1
    }}
fi

echo "Starting restore from: ${{BACKUP_FILE}}"
echo "FedRAMP Profile: {profile}"
echo ""
echo "WARNING: This will overwrite existing data!"
read -p "Continue? (yes/no): " CONFIRM
if [ "${{CONFIRM}}" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

# Create temporary directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${{TEMP_DIR}}" EXIT

echo "Decrypting backup..."
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
    -in "${{BACKUP_FILE}}" \
    -out "${{TEMP_DIR}}/backup.tar.gz" \
    -pass env:BACKUP_ENCRYPTION_KEY

echo "Extracting backup..."
tar -xzf "${{TEMP_DIR}}/backup.tar.gz" -C "${{TEMP_DIR}}"

# Display metadata
if [ -f "${{TEMP_DIR}}/backup-metadata.json" ]; then
    echo ""
    echo "Backup metadata:"
    cat "${{TEMP_DIR}}/backup-metadata.json"
    echo ""
fi

echo "Stopping services..."
cd "${{SCRIPT_DIR}}/.."
docker-compose down

echo "Restoring Loki data..."
if [ -d "${{TEMP_DIR}}/loki-data" ]; then
    docker volume rm {app_name}_loki_data 2>/dev/null || true
    docker volume create {app_name}_loki_data
    docker run --rm -v {app_name}_loki_data:/data -v "${{TEMP_DIR}}/loki-data:/backup:ro" \
        alpine sh -c "cp -a /backup/. /data/"
fi

echo "Restoring Prometheus data..."
if [ -d "${{TEMP_DIR}}/prometheus-data" ]; then
    docker volume rm {app_name}_prometheus_data 2>/dev/null || true
    docker volume create {app_name}_prometheus_data
    docker run --rm -v {app_name}_prometheus_data:/data -v "${{TEMP_DIR}}/prometheus-data:/backup:ro" \
        alpine sh -c "cp -a /backup/. /data/"
fi

echo "Restoring Grafana data..."
if [ -d "${{TEMP_DIR}}/grafana-data" ]; then
    docker volume rm {app_name}_grafana_data 2>/dev/null || true
    docker volume create {app_name}_grafana_data
    docker run --rm -v {app_name}_grafana_data:/data -v "${{TEMP_DIR}}/grafana-data:/backup:ro" \
        alpine sh -c "cp -a /backup/. /data/"
fi

echo "Starting services..."
docker-compose up -d

echo ""
echo "Restore complete!"
echo "Verify services are running: docker-compose ps"
"#,
        app_name = app_name,
        profile = fedramp.profile().name(),
    )
}

fn generate_health_script(_fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    format!(
        r#"#!/bin/bash
# Health Check Script - {app_name} Observability Stack
# Control: CA-7 (Continuous Monitoring)
#
# Usage: ./health-check.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0

check_service() {{
    local name=$1
    local url=$2
    local expected=${{3:-200}}

    printf "Checking %-15s ... " "$name"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 "$url" 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "$expected" ]; then
        echo -e "${{GREEN}}OK${{NC}} (HTTP $HTTP_CODE)"
    else
        echo -e "${{RED}}FAIL${{NC}} (HTTP $HTTP_CODE, expected $expected)"
        ERRORS=$((ERRORS + 1))
    fi
}}

echo "============================================"
echo "{app_name} Observability Stack Health Check"
echo "============================================"
echo ""
echo "Timestamp: $(date -Iseconds)"
echo ""

# Check services
check_service "Loki" "http://localhost:3100/ready"
check_service "Prometheus" "http://localhost:9090/-/ready"
check_service "Grafana" "http://localhost:3000/api/health"
check_service "Alertmanager" "http://localhost:9093/-/ready"

echo ""

# Check Docker containers
echo "Container Status:"
docker ps --filter "name={app_name}" --format "table {{{{.Names}}}}\t{{{{.Status}}}}\t{{{{.Ports}}}}" 2>/dev/null || echo "  (unable to check containers)"

echo ""

# Check disk usage
echo "Disk Usage:"
docker system df 2>/dev/null | head -5 || echo "  (unable to check disk usage)"

echo ""
echo "============================================"

if [ $ERRORS -gt 0 ]; then
    echo -e "${{RED}}Health check FAILED with $ERRORS error(s)${{NC}}"
    exit 1
else
    echo -e "${{GREEN}}All services healthy${{NC}}"
    exit 0
fi
"#,
        app_name = app_name,
    )
}

fn generate_startup_script(fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    let is_dev = fedramp.is_development();

    let prerequisites = if is_dev {
        // Development mode: no prerequisites, just start
        r#"echo "Development mode - no TLS or secrets required"
echo ""
"#.to_string()
    } else {
        // Production mode: check for .env and certificates
        r#"# Check prerequisites
if [ ! -f ".env" ]; then
    echo "WARNING: .env file not found!"
    echo "  Copy .env.example to .env and configure it first."
    echo ""
    read -p "Create .env from template? (y/n): " CREATE_ENV
    if [ "${CREATE_ENV}" = "y" ]; then
        cp .env.example .env
        echo "Created .env - please edit it with secure values before continuing."
        exit 1
    fi
fi

if [ ! -d "certs" ] || [ ! -f "certs/ca.crt" ]; then
    echo "WARNING: TLS certificates not found!"
    echo "  Use Vault PKI to generate certificates:"
    echo "    nix run .#vault-dev  # Start Vault (Terminal 1)"
    echo "    export VAULT_ADDR=http://127.0.0.1:8200"
    echo "    export VAULT_TOKEN=barbican-dev"
    echo "    nix run .#vault-cert-server prometheus ./certs/prometheus"
    echo "    nix run .#vault-cert-server loki ./certs/loki"
    echo "    nix run .#vault-cert-server grafana ./certs/grafana"
    echo "    nix run .#vault-cert-server alertmanager ./certs/alertmanager"
    echo "    nix run .#vault-ca-chain ./certs"
    echo ""
    exit 1
fi

# Ensure config files have correct permissions
echo "Setting config file permissions..."
find . -name "*.yml" -exec chmod 644 {} \;
find . -name "*.ini" -exec chmod 644 {} \;
"#.to_string()
    };

    format!(
        r#"#!/bin/bash
# Stack Startup Script - {app_name} Observability Stack
# Profile: {profile}
#
# Usage: ./start-stack.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
STACK_DIR="${{SCRIPT_DIR}}/.."

cd "${{STACK_DIR}}"

echo "Starting {app_name} observability stack ({profile})..."
echo ""

{prerequisites}
# Start the stack
echo "Starting Docker Compose..."
docker-compose up -d

echo ""
echo "Waiting for services to become healthy..."
sleep 10

# Run health check
./scripts/health-check.sh || true

echo ""
echo "Stack URLs:"
echo "  Grafana:      http://localhost:3000"
echo "  Prometheus:   http://localhost:9090"
echo "  Loki:         http://localhost:3100"
echo "  Alertmanager: http://localhost:9093"
echo ""
echo "To stop the stack: docker-compose down"
"#,
        app_name = app_name,
        profile = fedramp.profile().name(),
        prerequisites = prerequisites,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_script_generation() {
        let fedramp = ObservabilityComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let script = generate_cert_script(&fedramp, "test-app");
        assert!(script.contains("mkcert"));
        assert!(script.contains("openssl"));
    }
}
