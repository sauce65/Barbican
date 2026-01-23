# Configuration Reference

Complete reference for `barbican.toml` configuration options.

## Overview

`barbican.toml` is the single source of truth for your security configuration. The Barbican CLI generates both Rust and NixOS configuration from this file.

```bash
# Generate Rust configuration
barbican generate rust

# Generate NixOS configuration
barbican generate nix
```

---

## File Structure

```toml
[app]
# Application metadata and profile selection

[database]
# PostgreSQL configuration

[session]
# Session timeout settings

[auth]
# Authentication settings

[password]
# Password policy settings

[firewall]
# Network firewall rules

[rate_limit]
# Rate limiting configuration

[observability]
# Logging and metrics

[encryption]
# Encryption settings

[network]
# Network listener configuration
```

---

## [app] Section

Application metadata and compliance profile.

```toml
[app]
name = "my-secure-app"          # Required: Application name
version = "1.0.0"               # Application version
profile = "fedramp-moderate"    # Compliance profile
description = "My application"  # Optional description
```

### profile

Compliance profile that sets default values for all security settings.

| Value | Description |
|-------|-------------|
| `development` | Relaxed settings for local development |
| `fedramp-low` | FedRAMP Low baseline (limited impact) |
| `fedramp-moderate` | FedRAMP Moderate baseline (most common) |
| `fedramp-high` | FedRAMP High baseline (maximum security) |

Profile defaults can be overridden by explicit settings in other sections.

---

## [database] Section

PostgreSQL database configuration.

```toml
[database]
type = "postgres"                    # Database type (only postgres supported)
url = "${DATABASE_URL}"              # Connection URL (supports env vars)
pool_size = 20                       # Maximum connections
min_connections = 5                  # Minimum connections
acquire_timeout = 30                 # Connection acquire timeout (seconds)
idle_timeout = 600                   # Idle connection timeout (seconds)
require_ssl = true                   # Require SSL/TLS
require_client_cert = false          # Require client certificates (mTLS)
enable_audit_log = true              # Enable pgaudit logging
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | `"postgres"` | Database type |
| `url` | string | **required** | Connection URL |
| `pool_size` | integer | `20` | Max connection pool size |
| `min_connections` | integer | `5` | Min pool connections |
| `acquire_timeout` | integer | `30` | Seconds to wait for connection |
| `idle_timeout` | integer | `600` | Seconds before idle connection closed |
| `require_ssl` | boolean | `true` | Require SSL for connections |
| `require_client_cert` | boolean | Profile-dependent | Require client certificates |
| `enable_audit_log` | boolean | `true` | Enable pgaudit extension |

### Environment Variables

Use `${VAR_NAME}` syntax to reference environment variables:

```toml
url = "${DATABASE_URL}"
```

---

## [session] Section

Session management settings (AC-11, AC-12).

```toml
[session]
idle_timeout_minutes = 15       # Idle timeout (AC-11)
session_timeout_minutes = 15    # Max session lifetime (AC-12)
```

### Options

| Option | Type | Default by Profile | Description |
|--------|------|-------------------|-------------|
| `idle_timeout_minutes` | integer | Low: 15, Mod: 15, High: 10 | Minutes of inactivity before session lock |
| `session_timeout_minutes` | integer | Low: 30, Mod: 15, High: 10 | Maximum session duration in minutes |

### Profile Defaults

| Profile | Idle Timeout | Max Session |
|---------|--------------|-------------|
| development | 1440 (24h) | 1440 (24h) |
| fedramp-low | 15 | 30 |
| fedramp-moderate | 15 | 15 |
| fedramp-high | 10 | 10 |

---

## [auth] Section

Authentication configuration (IA-2, AC-7).

```toml
[auth]
require_mfa = true              # Require multi-factor authentication
jwt_issuer = "https://auth.example.com"  # JWT issuer for validation
jwt_audience = "my-app"         # Expected JWT audience
max_login_attempts = 3          # Failed attempts before lockout
lockout_duration_minutes = 30   # Lockout duration
```

### Options

| Option | Type | Default by Profile | Description |
|--------|------|-------------------|-------------|
| `require_mfa` | boolean | Low: false, Mod: true, High: true | Require MFA for all users |
| `jwt_issuer` | string | None | Expected JWT issuer |
| `jwt_audience` | string | None | Expected JWT audience |
| `max_login_attempts` | integer | 3 | Attempts before lockout (AC-7) |
| `lockout_duration_minutes` | integer | Low/Mod: 30, High: 180 | Lockout duration |

---

## [password] Section

Password policy settings (IA-5).

```toml
[password]
min_length = 15                 # Minimum password length
max_length = 128                # Maximum password length
require_uppercase = true        # Require uppercase letter
require_lowercase = true        # Require lowercase letter
require_digit = true            # Require numeric digit
require_special = true          # Require special character
check_common = true             # Check against common passwords
check_breach = false            # Check against breach database (hibp)
```

### Options

| Option | Type | Default by Profile | Description |
|--------|------|-------------------|-------------|
| `min_length` | integer | Low: 8, Mod/High: 15 | Minimum characters |
| `max_length` | integer | 128 | Maximum characters |
| `require_uppercase` | boolean | false | Require A-Z |
| `require_lowercase` | boolean | false | Require a-z |
| `require_digit` | boolean | false | Require 0-9 |
| `require_special` | boolean | false | Require special chars |
| `check_common` | boolean | true | Check common password list |
| `check_breach` | boolean | false | Check HIBP (requires feature) |

### NIST 800-63B Note

NIST 800-63B recommends length over complexity. The defaults follow NIST guidance:
- Minimum 8 characters (or 15 for STIG compliance)
- No arbitrary complexity rules
- Check against known breached passwords

---

## [firewall] Section

Network firewall configuration (SC-7).

```toml
[firewall]
default_policy = "drop"         # Default policy for unmatched traffic
enable_egress_filtering = true  # Filter outbound connections
log_dropped = true              # Log dropped packets

[[firewall.allowed_inbound]]
port = 443
protocol = "tcp"
source = "0.0.0.0/0"
description = "HTTPS"

[[firewall.allowed_inbound]]
port = 22
protocol = "tcp"
source = "10.0.0.0/8"
description = "SSH from internal"

[[firewall.allowed_outbound]]
port = 443
protocol = "tcp"
destination = "0.0.0.0/0"
description = "HTTPS outbound"

[[firewall.allowed_outbound]]
port = 53
protocol = "udp"
destination = "10.0.0.1/32"
description = "DNS"
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `default_policy` | string | `"drop"` | `"drop"` or `"accept"` |
| `enable_egress_filtering` | boolean | Profile-dependent | Filter outbound traffic |
| `log_dropped` | boolean | `true` | Log dropped packets |

### allowed_inbound

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `port` | integer | Yes | Port number |
| `protocol` | string | Yes | `"tcp"` or `"udp"` |
| `source` | string | No | Source CIDR (default: any) |
| `description` | string | No | Rule description |

### allowed_outbound

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `port` | integer | Yes | Port number |
| `protocol` | string | Yes | `"tcp"` or `"udp"` |
| `destination` | string | No | Destination CIDR (default: any) |
| `description` | string | No | Rule description |

---

## [rate_limit] Section

Rate limiting configuration (SC-5).

```toml
[rate_limit]
enabled = true
requests_per_second = 100       # Requests per second limit
burst = 10                      # Burst capacity

# Per-endpoint overrides
[rate_limit.overrides]
"/auth/login" = { requests_per_second = 5, burst = 3 }
"/api/upload" = { requests_per_second = 10, burst = 5 }
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable rate limiting |
| `requests_per_second` | integer | 100 | Base rate limit |
| `burst` | integer | 10 | Burst capacity |

### Response Headers

When rate limited, responses include:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1234567890
```

---

## [observability] Section

Logging and metrics configuration (AU-2, AU-3, AU-11).

```toml
[observability]
log_level = "info"              # Log level
log_format = "json"             # Log format: json or pretty
tracing = true                  # Enable distributed tracing
retention_days = 90             # Log retention period

[observability.loki]
enabled = false                 # Push logs to Loki
endpoint = "http://loki:3100"
labels = { app = "my-app", env = "production" }

[observability.prometheus]
enabled = true                  # Enable Prometheus metrics
endpoint = "/metrics"           # Metrics endpoint path

[observability.otlp]
enabled = false                 # OpenTelemetry Protocol
endpoint = "http://otel-collector:4317"
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_level` | string | `"info"` | `trace`, `debug`, `info`, `warn`, `error` |
| `log_format` | string | `"json"` | `json` or `pretty` |
| `tracing` | boolean | `true` | Enable distributed tracing |
| `retention_days` | integer | Profile-dependent | Log retention (AU-11) |

### Retention by Profile

| Profile | Retention |
|---------|-----------|
| development | 7 days |
| fedramp-low | 30 days |
| fedramp-moderate | 90 days |
| fedramp-high | 365 days |

---

## [encryption] Section

Encryption settings (SC-28, SC-13).

```toml
[encryption]
algorithm = "aes-256-gcm"       # Encryption algorithm
key_rotation_days = 90          # Key rotation interval
require_fips = false            # Require FIPS 140-3 crypto
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `algorithm` | string | `"aes-256-gcm"` | Encryption algorithm |
| `key_rotation_days` | integer | Profile-dependent | Days between key rotation |
| `require_fips` | boolean | Profile-dependent | Require FIPS crypto |

### Key Rotation by Profile

| Profile | Rotation Interval |
|---------|------------------|
| fedramp-low | 90 days |
| fedramp-moderate | 90 days |
| fedramp-high | 30 days |

---

## [network] Section

Network listener configuration.

```toml
[network]
listen = "0.0.0.0:3000"         # Listen address
tls_mode = "required"           # TLS mode

[network.tls]
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
client_ca_file = "/path/to/ca.pem"  # For mTLS
```

### tls_mode

| Value | Description |
|-------|-------------|
| `disabled` | No TLS (development only) |
| `preferred` | TLS if available |
| `required` | Require TLS |
| `strict` | Require TLS + client certificate (mTLS) |

### TLS by Profile

| Profile | Default TLS Mode |
|---------|-----------------|
| development | disabled |
| fedramp-low | preferred |
| fedramp-moderate | required |
| fedramp-high | strict |

---

## [deployment] Section

Deployment settings.

```toml
[deployment]
platform = "nixos"              # Deployment platform
output_dir = "."                # Output directory for generated files
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platform` | string | `"nixos"` | Deployment platform |
| `output_dir` | string | `"."` | Generated file location |

---

## Complete Example

```toml
# FedRAMP Moderate Application Configuration

[app]
name = "secure-api"
version = "1.0.0"
profile = "fedramp-moderate"
description = "FedRAMP Moderate compliant API"

[deployment]
platform = "nixos"
output_dir = "."

[database]
type = "postgres"
url = "${DATABASE_URL}"
pool_size = 20
min_connections = 5
require_ssl = true
enable_audit_log = true

[session]
idle_timeout_minutes = 15
session_timeout_minutes = 15

[auth]
require_mfa = true
jwt_issuer = "https://auth.example.com"
max_login_attempts = 3
lockout_duration_minutes = 30

[password]
min_length = 15
check_common = true

[firewall]
default_policy = "drop"
enable_egress_filtering = true
log_dropped = true

[[firewall.allowed_inbound]]
port = 443
protocol = "tcp"
source = "0.0.0.0/0"
description = "HTTPS"

[[firewall.allowed_outbound]]
port = 443
protocol = "tcp"
description = "HTTPS outbound"

[[firewall.allowed_outbound]]
port = 5432
protocol = "tcp"
destination = "10.0.0.0/8"
description = "PostgreSQL"

[rate_limit]
enabled = true
requests_per_second = 100
burst = 10

[rate_limit.overrides]
"/auth/login" = { requests_per_second = 5, burst = 3 }

[observability]
log_level = "info"
log_format = "json"
tracing = true
retention_days = 90

[observability.prometheus]
enabled = true
endpoint = "/metrics"

[encryption]
algorithm = "aes-256-gcm"
key_rotation_days = 90

[network]
listen = "0.0.0.0:3000"
tls_mode = "required"

[network.tls]
cert_file = "/etc/ssl/certs/server.crt"
key_file = "/etc/ssl/private/server.key"
```

---

## Environment Variable Substitution

Use `${VAR_NAME}` syntax anywhere in the configuration:

```toml
[database]
url = "${DATABASE_URL}"

[network.tls]
cert_file = "${TLS_CERT_PATH}"
key_file = "${TLS_KEY_PATH}"
```

Variables are resolved at:
1. Runtime for Rust configuration
2. Build time for NixOS configuration (via agenix secrets)

---

## Validation

Validate your configuration without generating files:

```bash
barbican validate
```

Common validation errors:
- Missing required fields
- Invalid profile name
- Port numbers out of range
- Invalid CIDR notation
- Conflicting settings
