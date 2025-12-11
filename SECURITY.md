# Security Documentation

This document describes the security controls, compliance mappings, threat model coverage, and audit procedures for barbican.

Barbican implements **52 NIST 800-53 Rev 5 controls** across 12 security modules. For the complete control registry, see `.claudedocs/SECURITY_CONTROL_REGISTRY.md`.

## Security Controls Matrix

### Infrastructure Controls

| Control | Name | Implementation | NIST 800-53 | SOC 2 | FedRAMP | Status |
|---------|------|----------------|-------------|-------|---------|--------|
| SC-2 | Security Headers | HTTP security headers via tower-http | SC-28 | CC6.1 | - | Implemented |
| SC-3 | Rate Limiting | Token bucket per IP via tower-governor | SC-5 | - | SC-5 | Implemented |
| SC-4 | Request Size Limits | Body size limits via tower-http | SC-5 | - | SC-5 | Implemented |
| SC-5 | Request Timeouts | Configurable timeout via tower-http | SC-10 | - | - | Implemented |
| SC-6 | CORS Policy | Origin allowlist via tower-http | AC-4 | CC6.6 | - | Implemented |
| SC-7 | Structured Logging | JSON audit logs via tracing | AU-2, AU-3, AU-12 | CC7.2 | - | Implemented |
| SC-8 | Database Security | SSL/TLS, pooling, health checks via SQLx | SC-8, SC-28, IA-5 | CC6.1, CC6.6, CC6.7 | SC-8, SC-28 | Implemented |
| SC-9 | Observability | Pluggable logging/metrics providers | AU-2, AU-12 | CC7.2 | - | Implemented |

### Authentication & Session Controls

| Control | Name | Implementation | NIST 800-53 | SOC 2 | FedRAMP | Status |
|---------|------|----------------|-------------|-------|---------|--------|
| AUTH-1 | OAuth/OIDC Claims | JWT claims extraction (Keycloak, Entra, Auth0) | IA-2, AC-2 | CC6.1 | IA-2 | Implemented |
| AUTH-2 | MFA Policy | MFA verification via `amr`/`acr` claims | IA-2(1), IA-2(2) | CC6.1 | IA-2(1) | Implemented |
| AUTH-3 | Password Policy | NIST 800-63B compliant validation | IA-5(1) | CC6.1 | IA-5(1) | Implemented |
| AUTH-4 | Login Tracking | Failed attempt tracking with lockout | AC-7 | CC6.1, CC6.8 | AC-7 | Implemented |
| AUTH-5 | Session Management | Idle/absolute timeout, secure termination | AC-11, AC-12 | CC6.1 | AC-11, AC-12 | Implemented |

### Data Protection Controls

| Control | Name | Implementation | NIST 800-53 | SOC 2 | FedRAMP | Status |
|---------|------|----------------|-------------|-------|---------|--------|
| DATA-1 | Input Validation | Email, URL, length, pattern validation | SI-10 | CC6.1 | SI-10 | Implemented |
| DATA-2 | HTML Sanitization | XSS prevention via HTML escaping | SI-10 | CC6.1 | SI-10 | Implemented |
| DATA-3 | Error Handling | Safe error responses, no info leakage | SI-11 | CC6.1 | SI-11 | Implemented |
| DATA-4 | Constant-Time Comparison | Timing attack prevention | SC-13 | CC6.1 | SC-13 | Implemented |

### Operational Security Controls

| Control | Name | Implementation | NIST 800-53 | SOC 2 | FedRAMP | Status |
|---------|------|----------------|-------------|-------|---------|--------|
| OPS-1 | Security Alerting | Incident alerting with rate limiting | IR-4, IR-5 | CC7.3, CC7.4 | IR-4, IR-5 | Implemented |
| OPS-2 | Health Checks | Async health framework with aggregation | CA-7 | CC7.1 | CA-7 | Implemented |
| OPS-3 | Key Management | KMS traits, rotation tracking | SC-12 | CC6.1 | SC-12 | Implemented |
| OPS-4 | Supply Chain | SBOM generation, license compliance | SR-3, SR-4 | CC6.1 | SR-3, SR-4 | Implemented |
| OPS-5 | Security Testing | XSS/SQLi payloads, header validation | SA-11, CA-8 | CC7.1 | SA-11 | Implemented |

### Control Details

#### SC-2: Security Headers

**File**: `src/layers.rs:75-108`

**NIST 800-53 Mapping**:
- SC-28: Protection of information at rest (via HSTS)
- SOC 2 CC6.1: Security controls to protect system resources

**Implementation**:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` - Enforces HTTPS for 1 year
- `X-Content-Type-Options: nosniff` - Prevents MIME type sniffing
- `X-Frame-Options: DENY` - Prevents clickjacking
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` - Restrictive CSP for APIs
- `Cache-Control: no-store, no-cache, must-revalidate, private` - Prevents caching of sensitive data
- `X-XSS-Protection: 0` - Disables legacy XSS filter (CSP preferred)

**Configuration**:
- Enable/disable: `SECURITY_HEADERS_ENABLED=true/false`
- Default: Enabled

**Threat Mitigation**:
- Man-in-the-middle attacks (HSTS)
- Clickjacking (X-Frame-Options)
- Content sniffing attacks (X-Content-Type-Options)
- XSS attacks (CSP)
- Sensitive data leakage via cache (Cache-Control)

**Test Coverage**: Verify headers present/absent based on configuration

#### SC-3: Rate Limiting

**File**: `src/layers.rs:65-73`

**NIST 800-53 Mapping**:
- SC-5: Denial of Service Protection
- FedRAMP SC-5

**Implementation**:
- Token bucket algorithm per IP address
- Configurable requests per second and burst size
- Returns HTTP 429 (Too Many Requests) when exceeded
- Uses tower-governor for in-memory state

**Configuration**:
- `RATE_LIMIT_PER_SECOND=5` - Sustained rate (default: 5)
- `RATE_LIMIT_BURST=10` - Burst capacity (default: 10)
- `RATE_LIMIT_ENABLED=true/false` - Enable/disable (default: enabled)

**Threat Mitigation**:
- Brute force attacks (login, password guessing)
- Denial of Service (DoS) attacks
- Resource exhaustion
- Credential stuffing

**Limitations**:
- Per-instance only (not distributed across replicas)
- IP-based (can be bypassed with distributed IPs)
- No persistent state (resets on restart)

**Production Recommendations**:
- Deploy distributed rate limiting (Redis, etc.) for multi-instance deployments
- Combine with CDN/WAF rate limiting
- Monitor rate limit metrics to detect attacks
- Consider user-based rate limiting for authenticated endpoints

**Test Coverage**: Verify 429 response after exceeding limits

#### SC-4: Request Size Limits

**File**: `src/layers.rs:62-63`

**NIST 800-53 Mapping**:
- SC-5: Denial of Service Protection
- FedRAMP SC-5

**Implementation**:
- Maximum request body size enforced by tower-http
- Rejects requests exceeding limit with HTTP 413 (Payload Too Large)
- Applied before request reaches handler

**Configuration**:
- `MAX_REQUEST_SIZE=1MB` - Maximum body size (default: 1MB)
- Supports human-readable format: "10MB", "1GB", "512KB"

**Threat Mitigation**:
- Denial of Service via large payloads
- Memory exhaustion
- Disk exhaustion (if bodies are buffered)

**Production Recommendations**:
- Set based on actual API requirements (e.g., file upload size)
- Monitor request size metrics
- Consider separate limits for different endpoints
- Validate content length before accepting body

**Test Coverage**: Verify 413 response for oversized requests

#### SC-5: Request Timeouts

**File**: `src/layers.rs:56-60`

**NIST 800-53 Mapping**:
- SC-10: Network Disconnect

**Implementation**:
- Configurable timeout for entire request processing
- Returns HTTP 408 (Request Timeout) when exceeded
- Applies to entire middleware stack and handler

**Configuration**:
- `REQUEST_TIMEOUT=30s` - Timeout duration (default: 30 seconds)
- Supports human-readable format: "30s", "5m", "1h"

**Threat Mitigation**:
- Slowloris attacks (slow HTTP requests)
- Resource exhaustion from hung connections
- Infinite loops in handlers
- Slow external API calls

**Production Recommendations**:
- Set based on slowest legitimate request (p99 latency + buffer)
- Monitor timeout metrics to detect attacks
- Consider separate timeouts for different endpoint types
- Use structured logging to debug timeout causes

**Test Coverage**: Verify 408 response for slow handlers

#### SC-6: CORS Policy

**File**: `src/layers.rs:110-112, 124-145`

**NIST 800-53 Mapping**:
- AC-4: Information Flow Enforcement
- SOC 2 CC6.6: Logical access controls

**Implementation**:
- Configurable origin allowlist via tower-http
- Three modes:
  - Restrictive: Same-origin only (empty list)
  - Allowlist: Explicit origins (list of URLs)
  - Permissive: Any origin (`*`) - development only
- Allowed methods: GET, POST, PUT, DELETE, OPTIONS
- Allowed headers: Content-Type, Authorization, Accept
- Max age: 3600 seconds (1 hour)
- Credentials allowed for allowlist mode only

**Configuration**:
- `CORS_ALLOWED_ORIGINS=""` - Empty (restrictive, same-origin only)
- `CORS_ALLOWED_ORIGINS="https://app.example.com"` - Single origin
- `CORS_ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com"` - Multiple origins
- `CORS_ALLOWED_ORIGINS="*"` - Any origin (development only)

**Threat Mitigation**:
- Cross-Site Request Forgery (CSRF) via CORS
- Unauthorized cross-origin data access
- Cross-origin timing attacks
- Information leakage to untrusted origins

**Limitations**:
- CORS is a browser security feature (not enforced server-side)
- Does not protect against non-browser clients
- Preflight requests add latency
- Credentials mode requires careful origin configuration

**Production Recommendations**:
- NEVER use `*` in production
- Maintain explicit allowlist of trusted origins
- Audit origin list regularly
- Use HTTPS for all allowed origins
- Monitor CORS errors in logs
- Consider CSRF tokens for state-changing operations

**Test Coverage**: Verify CORS headers for different modes, preflight handling

#### SC-7: Structured Logging

**File**: `src/layers.rs:114-117`, `src/observability/`

**NIST 800-53 Mapping**:
- AU-2: Audit Events
- AU-3: Content of Audit Records
- AU-12: Audit Generation
- SOC 2 CC7.2: System Monitoring

**Implementation**:
- Structured logging via tracing crate
- Configurable output format (JSON, pretty, compact)
- TraceLayer for HTTP request/response logging
- SecurityEvent enum for audit-relevant events
- Automatic fields: timestamp, level, target, message
- Custom fields: user_id, ip_address, resource, action, etc.

**Configuration**:
- `TRACING_ENABLED=true/false` - Enable request tracing
- `LOG_FORMAT=json/pretty/compact` - Output format
- `RUST_LOG=info` - Log filter directive

**Audit Events** (via `SecurityEvent` enum):
- Authentication: Success, Failure, Logout, SessionCreated, SessionDestroyed
- Authorization: AccessGranted, AccessDenied
- User Management: UserRegistered, UserModified, UserDeleted, PasswordChanged, PasswordResetRequested
- Security: RateLimitExceeded, BruteForceDetected, AccountLocked, AccountUnlocked, SuspiciousActivity
- System: SystemStartup, SystemShutdown, ConfigurationChanged, DatabaseConnected, DatabaseDisconnected

**Audit Record Content** (NIST AU-3):
- Event type (security_event field)
- Date and time (timestamp field)
- Source (ip_address, user_agent fields)
- Outcome (success/failure implied by event type)
- Subject identity (user_id, email fields)
- Object identity (resource, endpoint fields)

**Threat Mitigation**:
- Forensic analysis of security incidents
- Compliance auditing
- Anomaly detection
- Accountability

**Production Recommendations**:
- Use JSON format for production (machine-readable)
- Send logs to centralized logging system (Loki, OTLP)
- Retain logs per compliance requirements (90 days minimum)
- Monitor for high-severity events (Critical, High)
- Implement log integrity protection (write-once storage, signing)
- DO NOT log sensitive data (passwords, tokens, PII)

**Test Coverage**: Verify security events logged with correct fields and severity

#### SC-8: Database Security

**File**: `src/database.rs`

**NIST 800-53 Mapping**:
- SC-8: Transmission Confidentiality and Integrity (SSL/TLS)
- SC-28: Protection of Information at Rest (via PostgreSQL encryption)
- IA-5: Authenticator Management (credential protection)
- SOC 2 CC6.1, CC6.6, CC6.7
- FedRAMP SC-8, SC-28

**Implementation**:
- Connection pooling via SQLx with security defaults:
  - Max connections: 10 (prevents resource exhaustion)
  - Min idle connections: 1 (ensures quick response)
  - Acquire timeout: 30 seconds (detects pool exhaustion)
  - Max connection lifetime: 30 minutes (prevents stale connections)
  - Idle timeout: 10 minutes (releases unused connections)
  - Test before acquire: Always (verifies connection health)
- SSL/TLS modes:
  - `Disable`: No encryption (development only)
  - `Prefer`: Use SSL if available (default for development)
  - `Require`: Enforce SSL (default for production)
  - `VerifyCa`: Verify server certificate
  - `VerifyFull`: Verify certificate and hostname
- Health checks:
  - Connection liveness (SELECT 1)
  - SSL status (pg_stat_ssl)
  - Query latency
  - Pool size metrics

**Configuration**:
- `DATABASE_URL=postgres://...` - Connection URL
- `DB_MAX_CONNECTIONS=10` - Pool size
- `DB_ACQUIRE_TIMEOUT=30s` - Connection timeout
- `DB_SSL_MODE=require` - SSL mode
- `DB_SSL_ROOT_CERT=/path/to/ca.crt` - CA certificate for VerifyCa/VerifyFull

**Threat Mitigation**:
- Man-in-the-middle attacks (SSL/TLS)
- Connection hijacking (SSL/TLS)
- Resource exhaustion (connection limits)
- Connection pool exhaustion (timeouts)
- Stale connection issues (max lifetime)
- Credential theft (secure connection strings)

**Limitations**:
- SSL/TLS protects in-transit only (not at-rest)
- Connection pooling is per-instance (not distributed)
- Health checks add overhead
- Certificate verification requires CA cert

**Production Recommendations**:
- ALWAYS use `VerifyFull` in production
- Store CA certificate securely (mounted secret, not in image)
- Use short connection lifetimes (30 minutes or less)
- Monitor pool metrics (size, idle, acquire latency)
- Enable statement logging for audit (via `DB_STATEMENT_LOGGING=true`)
- Rotate database credentials regularly
- Use least-privilege database accounts
- Enable PostgreSQL SSL (postgresql.conf: ssl=on)
- Configure PostgreSQL to require SSL (pg_hba.conf: hostssl)

**Test Coverage**: Verify SSL enforcement, health checks, connection pooling

#### SC-9: Observability

**File**: `src/observability/`

**NIST 800-53 Mapping**:
- AU-2: Audit Events
- AU-12: Audit Generation
- SOC 2 CC7.2: System Monitoring

**Implementation**:
- Provider-agnostic architecture (application uses `tracing` macros)
- Log providers:
  - Stdout: Console output (default)
  - Loki: Grafana Loki (requires `observability-loki` feature)
  - OTLP: OpenTelemetry Protocol (requires `observability-otlp` feature)
- Metrics providers:
  - Prometheus: Metrics endpoint (requires `metrics-prometheus` feature)
- Configurable log format (JSON, pretty, compact)
- Configurable log filter (per-module levels)

**Configuration**:
- `LOG_PROVIDER=stdout/loki/otlp` - Logging backend
- `LOG_FORMAT=json/pretty/compact` - Output format
- `RUST_LOG=info` - Filter directive
- `LOKI_ENDPOINT=http://loki:3100` - Loki URL
- `OTLP_ENDPOINT=http://jaeger:4317` - OTLP collector URL
- `OTEL_SERVICE_NAME=myapp` - Service name for traces
- `METRICS_PROVIDER=prometheus` - Enable Prometheus
- `PROMETHEUS_LISTEN=0.0.0.0:9090` - Metrics endpoint

**Threat Mitigation**:
- Security event detection
- Anomaly detection
- Performance degradation detection
- Capacity planning

**Production Recommendations**:
- Use centralized logging (Loki, OTLP)
- Use JSON format for machine-readable logs
- Configure log retention per compliance requirements
- Monitor metrics for anomalies
- Set up alerts for critical events (BruteForceDetected, etc.)
- Protect metrics endpoint (authentication, firewall)

**Test Coverage**: Verify provider initialization, log format selection

## NIST 800-53 Rev 5 Mapping

### Access Control (AC)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| AC-2 | Account Management | `auth` module - Claims extraction, role management | Implemented |
| AC-4 | Information Flow Enforcement | CORS policy (SC-6) | Implemented |
| AC-7 | Unsuccessful Logon Attempts | `login` module - LockoutPolicy, LoginTracker | Implemented |
| AC-11 | Session Lock | `session` module - Idle timeout policies | Implemented |
| AC-12 | Session Termination | `session` module - SessionState termination | Implemented |

### Audit and Accountability (AU)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| AU-2 | Audit Events | SecurityEvent enum with defined event categories | Implemented |
| AU-3 | Content of Audit Records | Structured logging with timestamp, user, action, outcome | Implemented |
| AU-6 | Audit Review, Analysis | `alerting` module - Alert aggregation and analysis | Implemented |
| AU-7 | Audit Reduction | `alerting` module - Rate limiting, deduplication | Implemented |
| AU-12 | Audit Generation | Tracing integration, security_event! macro | Implemented |

### Security Assessment (CA)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| CA-7 | Continuous Monitoring | `health` module - HealthChecker framework | Implemented |
| CA-8 | Penetration Testing | `testing` module - Security test payloads | Implemented |

### Identification and Authentication (IA)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| IA-2 | Identification and Authentication | `auth` module - OAuth/OIDC claims extraction | Implemented |
| IA-2(1) | MFA - Network Access | `auth` module - MfaPolicy enforcement | Implemented |
| IA-2(2) | MFA - Non-privileged Accounts | `auth` module - MfaPolicy with flexible configuration | Implemented |
| IA-5 | Authenticator Management | Constant-time comparison, secure connection strings | Implemented |
| IA-5(1) | Password-Based Authentication | `password` module - NIST 800-63B compliance | Implemented |

### Incident Response (IR)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| IR-4 | Incident Handling | `alerting` module - AlertManager, handlers | Implemented |
| IR-5 | Incident Monitoring | `alerting` module - Real-time alert processing | Implemented |
| IR-6 | Incident Reporting | `alerting` module - AlertHandler callbacks | Implemented |

### System and Communications Protection (SC)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| SC-5 | Denial of Service Protection | Rate limiting (SC-3), request size limits (SC-4) | Implemented |
| SC-8 | Transmission Confidentiality and Integrity | Database SSL/TLS | Implemented |
| SC-10 | Network Disconnect | Request timeouts (SC-5) | Implemented |
| SC-12 | Cryptographic Key Management | `keys` module - KeyStore trait, RotationTracker | Implemented |
| SC-13 | Cryptographic Protection | `crypto` module - Constant-time comparison | Implemented |
| SC-28 | Protection of Information at Rest | Security headers (SC-2), database encryption via PostgreSQL | Partial |

### System and Information Integrity (SI)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| SI-10 | Information Input Validation | `validation` module - Email, URL, length, pattern | Implemented |
| SI-11 | Error Handling | `error` module - Safe responses, no info leakage | Implemented |

### System and Services Acquisition (SA)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| SA-11 | Developer Security Testing | `testing` module - XSS, SQLi, injection payloads | Implemented |

### Supply Chain Risk Management (SR)

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| SR-3 | Supply Chain Controls | `supply_chain` module - SBOM generation | Implemented |
| SR-4 | Provenance | `supply_chain` module - Dependency tracking, license compliance | Implemented |

## SOC 2 Type II Mapping

### CC6: Logical and Physical Access Controls

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC6.1 | Security controls protect system resources | Security headers, database SSL, auth, validation | Implemented |
| CC6.6 | Logical access controls restrict access | CORS policy, database SSL, session management | Implemented |
| CC6.7 | Transmission of data is protected | Database SSL/TLS | Implemented |
| CC6.8 | Unauthorized access prevention | Login tracking with lockout (AC-7) | Implemented |

### CC7: System Operations

| Criterion | Description | Implementation | Status |
|-----------|-------------|----------------|--------|
| CC7.1 | Detection of security events | Health checks, security testing utilities | Implemented |
| CC7.2 | System monitoring detects anomalies | Structured logging, observability | Implemented |
| CC7.3 | Security event evaluation | AlertManager with severity classification | Implemented |
| CC7.4 | Security incident response | Alert handlers, incident callbacks | Implemented |

## FedRAMP Mapping

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| AC-7 | Unsuccessful Logon Attempts | Login tracking with lockout | Implemented |
| AC-11 | Session Lock | Session idle timeout | Implemented |
| AC-12 | Session Termination | Session termination policies | Implemented |
| CA-7 | Continuous Monitoring | Health check framework | Implemented |
| IA-2 | Identification and Authentication | OAuth/OIDC claims extraction | Implemented |
| IA-2(1) | MFA - Network Access | MFA policy enforcement | Implemented |
| IA-5(1) | Password-Based Authentication | NIST 800-63B compliance | Implemented |
| IR-4 | Incident Handling | Alert management | Implemented |
| IR-5 | Incident Monitoring | Real-time alerting | Implemented |
| SC-5 | Denial of Service Protection | Rate limiting, request size limits | Implemented |
| SC-8 | Transmission Confidentiality and Integrity | Database SSL/TLS | Implemented |
| SC-12 | Cryptographic Key Management | Key store traits, rotation tracking | Implemented |
| SI-10 | Information Input Validation | Input validation module | Implemented |
| SI-11 | Error Handling | Secure error responses | Implemented |
| SR-3 | Supply Chain Controls | SBOM generation | Implemented |
| SR-4 | Provenance | Dependency tracking | Implemented |
| SC-28 | Protection of Information at Rest | Database encryption via PostgreSQL | Partial |

## Threat Model Coverage

### Threats Mitigated

| Threat | Mitigation | Control |
|--------|------------|---------|
| Man-in-the-middle attacks | HSTS, database SSL/TLS | SC-2, SC-8 |
| Clickjacking | X-Frame-Options header | SC-2 |
| Content sniffing attacks | X-Content-Type-Options header | SC-2 |
| XSS attacks | Content Security Policy, input validation, HTML sanitization | SC-2, SI-10 |
| SQL injection | Input validation, testing payloads for detection | SI-10, SA-11 |
| Command injection | Input validation, testing payloads for detection | SI-10, SA-11 |
| Brute force attacks | Rate limiting, login tracking with lockout | SC-3, AC-7 |
| Denial of Service | Rate limiting, request size limits, timeouts | SC-3, SC-4, SC-5 |
| Resource exhaustion | Rate limiting, connection pooling limits | SC-3, SC-8 |
| Slowloris attacks | Request timeouts | SC-5 |
| Cross-Site Request Forgery | CORS policy | SC-6 |
| Unauthorized data access | CORS policy, session management | SC-6, AC-11, AC-12 |
| Timing attacks | Constant-time comparison | SC-13 |
| Connection hijacking | Database SSL/TLS | SC-8 |
| Credential theft | Secure connection strings, SSL/TLS | SC-8 |
| Stale connections | Connection lifetime limits | SC-8 |
| Weak passwords | NIST 800-63B password policy, context validation | IA-5(1) |
| Password reuse | Breached password detection (configurable) | IA-5(1) |
| Session hijacking | Session termination, idle timeout | AC-11, AC-12 |
| Account enumeration | Secure error handling, timing-safe comparison | SI-11, SC-13 |
| MFA bypass | MFA policy enforcement via JWT claims | IA-2(1), IA-2(2) |
| Information disclosure | Secure error responses, no stack traces in prod | SI-11 |
| Supply chain attacks | SBOM generation, vulnerability scanning | SR-3, SR-4 |
| License violations | License compliance checking | SR-4 |
| Key exposure | Key rotation tracking, KMS integration | SC-12 |
| Security misconfigurations | Security header validation, health checks | CA-7, SA-11 |

### Threats NOT Mitigated

| Threat | Reason | Recommendation |
|--------|--------|----------------|
| Application-specific SQL injection | Depends on query construction | Use parameterized queries (SQLx supports this) |
| Authorization bypass | Application-level concern | Implement authorization checks using `auth` module claims |
| Business logic flaws | Application-level concern | Application-specific validation |
| Distributed DoS | Infrastructure-level concern | Deploy WAF, CDN with DDoS protection |
| Zero-day exploits | Unpredictable | Keep dependencies updated, use `supply_chain` module for monitoring |
| Insider threats | Organizational concern | Access controls, audit logging, separation of duties |
| Physical attacks | Infrastructure concern | Physical security controls |
| Side-channel attacks | Implementation-specific | Use `crypto` module constant-time operations |
| Memory corruption | Rust prevents most issues | Use safe Rust, avoid unsafe blocks |

## Known Limitations

### SC-3: Rate Limiting

**Limitation**: In-memory state, per-instance only

**Impact**: Rate limits reset on restart, ineffective for multi-instance deployments

**Workaround**: Deploy distributed rate limiting (Redis, etc.) for production

### SC-6: CORS Policy

**Limitation**: Browser-enforced only, not server-side

**Impact**: Non-browser clients can bypass CORS

**Workaround**: Implement server-side CSRF tokens for state-changing operations

### SC-8: Database Security

**Limitation**: SSL/TLS protects in-transit only, not at-rest

**Impact**: Data on disk is not encrypted by this crate

**Workaround**: Enable PostgreSQL tablespace encryption or full-disk encryption

### SC-28: Protection at Rest

**Limitation**: No application-level encryption at rest

**Impact**: Relies on PostgreSQL or infrastructure encryption

**Workaround**: Use PostgreSQL transparent data encryption or infrastructure encryption

### Observability

**Limitation**: No built-in log integrity protection

**Impact**: Logs can be tampered with if attacker gains access

**Workaround**: Send logs to write-once storage, implement log signing

## Audit Test Procedures

### Pre-Audit Checklist

- [ ] Update dependencies to latest versions
- [ ] Run full test suite: `cargo test --all-features`
- [ ] Run security audit: `cargo audit`
- [ ] Review recent security advisories
- [ ] Verify all security controls enabled in production config
- [ ] Check log retention meets compliance requirements

### SC-2: Security Headers Audit

**Procedure**:

1. Start application with production config
2. Send HTTP request to any endpoint:
   ```bash
   curl -i https://api.example.com/health
   ```
3. Verify response headers:
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
   - `Cache-Control: no-store, no-cache, must-revalidate, private`
   - `X-XSS-Protection: 0`
4. Test with `SECURITY_HEADERS_ENABLED=false` - headers should be absent

**Expected Result**: All security headers present when enabled, absent when disabled

**Compliance**: NIST SC-28, SOC 2 CC6.1

### SC-3: Rate Limiting Audit

**Procedure**:

1. Configure low rate limit: `RATE_LIMIT_PER_SECOND=2 RATE_LIMIT_BURST=3`
2. Send 10 rapid requests to same endpoint from same IP:
   ```bash
   for i in {1..10}; do curl -i https://api.example.com/test; done
   ```
3. Verify first 3-4 requests succeed (200 OK)
4. Verify subsequent requests fail with 429 Too Many Requests
5. Wait 5 seconds, send another request - should succeed (rate limit reset)
6. Test with `RATE_LIMIT_ENABLED=false` - all requests should succeed

**Expected Result**: Requests exceeding rate limit receive 429 response

**Compliance**: NIST SC-5, FedRAMP SC-5

### SC-4: Request Size Limits Audit

**Procedure**:

1. Configure limit: `MAX_REQUEST_SIZE=1KB`
2. Send request with 500-byte body - should succeed:
   ```bash
   curl -X POST -H "Content-Type: application/json" \
     -d "$(python3 -c 'print("x"*500)')" \
     https://api.example.com/test
   ```
3. Send request with 2KB body - should fail:
   ```bash
   curl -X POST -H "Content-Type: application/json" \
     -d "$(python3 -c 'print("x"*2048)')" \
     https://api.example.com/test
   ```
4. Verify 413 Payload Too Large response

**Expected Result**: Oversized requests rejected with 413

**Compliance**: NIST SC-5, FedRAMP SC-5

### SC-5: Request Timeouts Audit

**Procedure**:

1. Configure short timeout: `REQUEST_TIMEOUT=2s`
2. Create handler that sleeps for 5 seconds
3. Send request - should timeout after 2 seconds:
   ```bash
   time curl https://api.example.com/slow-endpoint
   ```
4. Verify 408 Request Timeout response
5. Verify response time approximately 2 seconds (not 5)

**Expected Result**: Long-running requests timeout with 408

**Compliance**: NIST SC-10

### SC-6: CORS Policy Audit

**Procedure**:

1. Test restrictive mode (empty origins):
   ```bash
   curl -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: POST" \
     -X OPTIONS https://api.example.com/test
   ```
   - Should NOT include `Access-Control-Allow-Origin` header

2. Test allowlist mode:
   ```bash
   export CORS_ALLOWED_ORIGINS="https://app.example.com"
   # Restart app
   curl -H "Origin: https://app.example.com" \
     -H "Access-Control-Request-Method: POST" \
     -X OPTIONS https://api.example.com/test
   ```
   - Should include `Access-Control-Allow-Origin: https://app.example.com`

3. Test unauthorized origin:
   ```bash
   curl -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: POST" \
     -X OPTIONS https://api.example.com/test
   ```
   - Should NOT include `Access-Control-Allow-Origin` header

**Expected Result**: Only allowed origins receive CORS headers

**Compliance**: NIST AC-4, SOC 2 CC6.6

### SC-7: Structured Logging Audit

**Procedure**:

1. Configure JSON logging: `LOG_FORMAT=json`
2. Trigger security events:
   ```bash
   # Simulate authentication failure
   curl -X POST https://api.example.com/login -d '{"email":"test","password":"wrong"}'
   ```
3. Check logs for JSON structure:
   ```bash
   cat logs/app.log | jq .
   ```
4. Verify required fields present:
   - `timestamp`
   - `level` (info/warn/error)
   - `security_event` (event name)
   - `category` (authentication/authorization/security/etc.)
   - `severity` (low/medium/high/critical)
   - `message`
5. Verify no sensitive data in logs (passwords, tokens, full PII)

**Expected Result**: All security events logged with structured fields, no secrets

**Compliance**: NIST AU-2, AU-3, AU-12, SOC 2 CC7.2

### SC-8: Database Security Audit

**Procedure**:

1. Configure SSL mode: `DB_SSL_MODE=require`
2. Start application, check logs for SSL status:
   ```
   Database health check passed (SSL enabled)
   ```
3. Connect to database, verify SSL:
   ```sql
   SELECT ssl, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();
   ```
   - Should return `ssl=true` and cipher name

4. Test SSL enforcement - configure `DB_SSL_MODE=require` but disable SSL on PostgreSQL:
   ```
   # postgresql.conf: ssl=off
   ```
   - Application should fail to connect

5. Verify connection pool limits:
   ```bash
   # Send DB_MAX_CONNECTIONS + 5 concurrent requests
   # Should not exceed max connections
   ```

6. Verify health checks:
   ```bash
   curl https://api.example.com/health/db
   ```
   - Should report SSL status, latency, pool size

**Expected Result**: SSL enforced, connection limits respected, health checks pass

**Compliance**: NIST SC-8, SC-28, IA-5, SOC 2 CC6.1/CC6.6/CC6.7, FedRAMP SC-8/SC-28

### SC-9: Observability Audit

**Procedure**:

1. Test log provider switching:
   - Stdout: `LOG_PROVIDER=stdout` - logs to console
   - Loki: `LOG_PROVIDER=loki LOKI_ENDPOINT=http://loki:3100` - sends to Loki
   - OTLP: `LOG_PROVIDER=otlp OTLP_ENDPOINT=http://jaeger:4317` - sends traces

2. Verify log format selection:
   - JSON: `LOG_FORMAT=json` - machine-readable
   - Pretty: `LOG_FORMAT=pretty` - human-readable with colors
   - Compact: `LOG_FORMAT=compact` - single-line

3. Verify log filtering:
   - `RUST_LOG=debug` - all debug and above
   - `RUST_LOG=myapp=debug,tower_http=info` - per-module levels

4. Verify metrics (if Prometheus enabled):
   ```bash
   curl http://localhost:9090/metrics
   ```
   - Should return Prometheus format metrics

**Expected Result**: Logs sent to configured provider, format applied, filtering works

**Compliance**: NIST AU-2, AU-12, SOC 2 CC7.2

### AUTH-3: Password Policy Audit

**Procedure**:

1. Test minimum length enforcement:
   ```rust
   let policy = PasswordPolicy::default();
   assert!(policy.validate("short").is_err()); // < 8 chars
   assert!(policy.validate("longenoughpassword").is_ok()); // >= 8 chars
   ```

2. Test context-based validation (username/email in password):
   ```rust
   let result = policy.validate_with_context("john123pass", Some("john"), None);
   assert!(result.is_err()); // Contains username
   ```

3. Test common password rejection:
   ```rust
   assert!(policy.validate("password123").is_err()); // Common password
   assert!(policy.validate("qwerty12345").is_err()); // Common password
   ```

4. Run unit tests: `cargo test --package barbican password`

**Expected Result**: Weak passwords rejected, NIST 800-63B compliance

**Compliance**: NIST IA-5(1), SOC 2 CC6.1

### AUTH-4: Login Tracking Audit

**Procedure**:

1. Test lockout after failed attempts:
   ```rust
   let policy = LockoutPolicy::nist_compliant(); // 3 attempts, 15 min lockout
   let mut tracker = LoginTracker::new(policy);

   tracker.record_attempt("user@test.com", false); // Attempt 1
   tracker.record_attempt("user@test.com", false); // Attempt 2
   let result = tracker.record_attempt("user@test.com", false); // Attempt 3

   assert!(matches!(result, AttemptResult::AccountLocked(_)));
   ```

2. Test lockout duration:
   ```rust
   let info = tracker.get_lockout_info("user@test.com");
   assert!(info.is_some());
   assert!(info.unwrap().lockout_until > Utc::now());
   ```

3. Test successful login clears attempts:
   ```rust
   // After lockout expires...
   tracker.record_attempt("user@test.com", true);
   let info = tracker.get_lockout_info("user@test.com");
   assert!(info.is_none()); // Cleared after success
   ```

4. Run unit tests: `cargo test --package barbican login`

**Expected Result**: Account lockout works correctly, timing is accurate

**Compliance**: NIST AC-7, FedRAMP AC-7

### AUTH-5: Session Management Audit

**Procedure**:

1. Test idle timeout:
   ```rust
   let policy = SessionPolicy::builder()
       .idle_timeout(Duration::from_secs(900))
       .build();

   let mut session = SessionState::new("sess-1", "user-1");
   // Simulate 20 minutes of inactivity
   session.last_activity = Utc::now() - Duration::from_secs(1200);

   assert!(policy.is_idle_timeout_exceeded(&session));
   ```

2. Test absolute timeout:
   ```rust
   let policy = SessionPolicy::builder()
       .absolute_timeout(Duration::from_secs(28800))
       .build();

   let mut session = SessionState::new("sess-1", "user-1");
   // Simulate 10 hours since creation
   session.created_at = Utc::now() - Duration::from_secs(36000);

   assert!(policy.is_absolute_timeout_exceeded(&session));
   ```

3. Test session termination logging:
   ```rust
   session.terminate(SessionTerminationReason::IdleTimeout);
   assert!(session.terminated_at.is_some());
   assert_eq!(session.termination_reason, Some(SessionTerminationReason::IdleTimeout));
   ```

4. Run unit tests: `cargo test --package barbican session`

**Expected Result**: Timeouts enforced, termination logged

**Compliance**: NIST AC-11, AC-12, FedRAMP AC-11, AC-12

### DATA-1: Input Validation Audit

**Procedure**:

1. Test email validation:
   ```rust
   assert!(validate_email("user@example.com").is_ok());
   assert!(validate_email("invalid").is_err());
   assert!(validate_email("user@.com").is_err());
   ```

2. Test URL validation:
   ```rust
   assert!(validate_url("https://example.com").is_ok());
   assert!(validate_url("javascript:alert(1)").is_err());
   ```

3. Test HTML sanitization:
   ```rust
   let input = "<script>alert('xss')</script>Hello";
   let safe = sanitize_html(input);
   assert!(!safe.contains("<script>"));
   assert!(safe.contains("Hello"));
   ```

4. Test length validation:
   ```rust
   assert!(validate_length("test", 1, 10, "field").is_ok());
   assert!(validate_length("", 1, 10, "field").is_err()); // Too short
   assert!(validate_length("a".repeat(20), 1, 10, "field").is_err()); // Too long
   ```

5. Run unit tests: `cargo test --package barbican validation`

**Expected Result**: Invalid input rejected, XSS prevented

**Compliance**: NIST SI-10, FedRAMP SI-10

### OPS-1: Security Alerting Audit

**Procedure**:

1. Test alert creation and severity:
   ```rust
   let alert = Alert::new(
       AlertSeverity::Critical,
       "Brute force attack detected",
       AlertCategory::Security,
   );
   assert_eq!(alert.severity, AlertSeverity::Critical);
   ```

2. Test rate limiting (alerts not duplicated):
   ```rust
   let config = AlertConfig::builder()
       .rate_limit_window(Duration::from_secs(60))
       .build();
   let manager = AlertManager::new(config);

   // Send same alert twice quickly
   manager.alert(alert.clone());
   manager.alert(alert.clone());
   // Second should be rate-limited
   ```

3. Test alert handler callback:
   ```rust
   let (tx, rx) = channel();
   manager.add_handler(Box::new(move |a| tx.send(a.clone()).unwrap()));
   manager.alert(alert);
   assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
   ```

4. Run unit tests: `cargo test --package barbican alerting`

**Expected Result**: Alerts delivered, rate limiting prevents floods

**Compliance**: NIST IR-4, IR-5, SOC 2 CC7.3, CC7.4

### OPS-2: Health Check Audit

**Procedure**:

1. Test health check registration:
   ```rust
   let mut checker = HealthChecker::new();
   checker.add_check("database", HealthCheck::new(|| async {
       HealthStatus::healthy()
   }));
   ```

2. Test aggregated health report:
   ```rust
   let report = checker.check_all().await;
   assert_eq!(report.status, Status::Healthy);
   assert!(report.checks.contains_key("database"));
   ```

3. Test degraded status propagation:
   ```rust
   checker.add_check("cache", HealthCheck::new(|| async {
       HealthStatus::degraded("High latency")
   }));
   let report = checker.check_all().await;
   assert_eq!(report.status, Status::Degraded);
   ```

4. Run unit tests: `cargo test --package barbican health`

**Expected Result**: Health status accurately reported

**Compliance**: NIST CA-7, SOC 2 CC7.1

### OPS-4: Supply Chain Audit

**Procedure**:

1. Test Cargo.lock parsing:
   ```rust
   let deps = parse_cargo_lock("Cargo.lock")?;
   assert!(!deps.is_empty());
   ```

2. Test SBOM generation:
   ```rust
   let metadata = SbomMetadata::new("myapp", "1.0.0");
   let sbom = generate_cyclonedx_sbom(&deps, metadata);
   assert!(sbom.contains("CycloneDX"));
   assert!(sbom.contains("myapp"));
   ```

3. Test license compliance:
   ```rust
   let policy = LicensePolicy::default();
   assert!(policy.is_allowed("MIT"));
   assert!(policy.is_allowed("Apache-2.0"));
   // Test restrictive license handling per policy
   ```

4. Run `cargo audit` integration:
   ```bash
   cargo audit
   ```

5. Run unit tests: `cargo test --package barbican supply_chain`

**Expected Result**: Dependencies tracked, SBOM generated, licenses checked

**Compliance**: NIST SR-3, SR-4, FedRAMP SR-3, SR-4

### OPS-5: Security Testing Utilities Audit

**Procedure**:

1. Test XSS payload availability:
   ```rust
   let payloads = xss_payloads();
   assert!(payloads.iter().any(|p| p.contains("<script>")));
   assert!(payloads.len() >= 10);
   ```

2. Test SQLi payload availability:
   ```rust
   let payloads = sql_injection_payloads();
   assert!(payloads.iter().any(|p| p.contains("OR")));
   assert!(payloads.len() >= 10);
   ```

3. Test security header validation:
   ```rust
   let headers = SecurityHeaders::new()
       .hsts("max-age=31536000")
       .csp("default-src 'none'");
   let issues = headers.validate();
   assert!(issues.is_empty());
   ```

4. Test header issue detection:
   ```rust
   let headers = SecurityHeaders::new(); // Missing headers
   let issues = headers.validate();
   assert!(!issues.is_empty());
   assert!(issues.iter().any(|i| i.header == "Strict-Transport-Security"));
   ```

5. Run unit tests: `cargo test --package barbican testing`

**Expected Result**: Payloads available, header validation accurate

**Compliance**: NIST SA-11, CA-8

## Incident Response

If security vulnerability discovered:

1. **DO NOT** publicly disclose until patch available
2. Contact maintainers via security email (if configured)
3. Provide:
   - Vulnerability description
   - Affected versions
   - Proof of concept (if safe to share)
   - Suggested remediation
4. Maintainers will:
   - Acknowledge within 48 hours
   - Assess severity and impact
   - Develop and test patch
   - Release security advisory and patched version
   - Credit reporter (if desired)

## Security Audit History

| Date | Auditor | Scope | Findings | Status |
|------|---------|-------|----------|--------|
| - | - | - | - | - |

## Security Contact

For security vulnerabilities, contact: [security email or GitHub security advisories]

## References

- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/resources/landing/trust-services-criteria)
- [FedRAMP Security Controls](https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
