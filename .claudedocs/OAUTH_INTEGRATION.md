# OAuth/OIDC Integration Guide

This guide covers integrating barbican with external OAuth/OIDC identity providers for NIST 800-53 compliant authentication and authorization.

## Design Philosophy

**Barbican does NOT implement authentication.** Your OAuth provider handles:
- User identity management (IA-2)
- Multi-factor authentication (IA-2(1), IA-2(2))
- Session management at the IdP level
- Federation and SSO
- Password policies (if using local accounts)

**Barbican provides:**
- Claims extraction helpers for audit logging
- **MFA enforcement** based on JWT claims (IA-2(1), IA-2(2))
- Security event logging for access decisions (AU-2, AU-3)
- Input validation for tokens and claims (SI-10)

## Recommended OAuth Providers

| Provider | Best For | NIST 800-53 | FedRAMP |
|----------|----------|-------------|---------|
| **Keycloak** | Self-hosted, full control | Configurable | With hardening |
| **Entra ID** | Microsoft ecosystem, enterprise | Built-in | Authorized |
| **Auth0** | Developer experience, rapid setup | Configurable | SOC 2 |
| **Okta** | Enterprise SSO, workforce | Built-in | Authorized |

## Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Browser   │────▶│   OAuth     │────▶│  Your Axum  │
│   / Client  │◀────│   Provider  │◀────│     App     │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                    │
                           │ JWT with claims    │
                           │ (incl. amr, acr)   │
                           └───────────────────▶│
                                                │
                                    ┌───────────▼───────────┐
                                    │  barbican::auth       │
                                    │  - Extract claims     │
                                    │  - Enforce MFA        │
                                    │  - Log access events  │
                                    └───────────────────────┘
```

## MFA Enforcement (IA-2(1), IA-2(2))

Barbican enforces MFA requirements by checking JWT claims from your OAuth provider.
Your provider performs the actual MFA; barbican verifies it was completed.

### Key Claims for MFA

| Claim | Description | Example Values |
|-------|-------------|----------------|
| `amr` | Authentication Methods Reference | `["pwd", "otp"]`, `["pwd", "hwk"]` |
| `acr` | Authentication Context Class Reference | `"urn:mace:incommon:iap:silver"`, `"2"` |

### AMR Values (RFC 8176)

| Value | Description | Factor Type |
|-------|-------------|-------------|
| `pwd` | Password | Knowledge |
| `otp` | One-time password (TOTP/HOTP) | Possession |
| `hwk` | Hardware key (WebAuthn, FIDO2, YubiKey) | Possession |
| `swk` | Software key | Possession |
| `sms` | SMS verification | Possession |
| `pin` | PIN | Knowledge |
| `fpt` | Fingerprint | Inherence |
| `face` | Facial recognition | Inherence |
| `mfa` | Multiple factors used | Combined |

### Using MfaPolicy

```rust
use barbican::auth::{Claims, MfaPolicy};
use axum::{Extension, http::StatusCode};

// Require any form of MFA
async fn sensitive_handler(
    Extension(claims): Extension<Claims>,
) -> Result<&'static str, StatusCode> {
    let policy = MfaPolicy::require_mfa();

    if policy.check_and_log(&claims, "sensitive_data") {
        Ok("Access granted")
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// Require hardware key for admin actions (IA-2(6))
async fn admin_handler(
    Extension(claims): Extension<Claims>,
) -> Result<&'static str, StatusCode> {
    let policy = MfaPolicy::require_hardware_key();

    if policy.check_and_log(&claims, "admin_action") {
        Ok("Admin access granted")
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// Require specific methods (hardware key or biometric)
async fn high_security_handler(
    Extension(claims): Extension<Claims>,
) -> Result<&'static str, StatusCode> {
    let policy = MfaPolicy::require_any(&["hwk", "fpt", "face"]);

    if policy.is_satisfied(&claims) {
        Ok("High security access granted")
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
```

### Quick MFA Checks on Claims

```rust
// Check if MFA was completed
if claims.mfa_satisfied() {
    // User used password + second factor, or explicit MFA
}

// Check for specific authentication methods
if claims.used_hardware_auth() {
    // User authenticated with hardware key (IA-2(6))
}

if claims.used_biometric_auth() {
    // User authenticated with fingerprint or face
}

if claims.used_auth_method("otp") {
    // User used TOTP/HOTP
}
```

## Integration Patterns

### Pattern 1: API Gateway Validation (Recommended)

Let your API gateway (Kong, Envoy, AWS ALB) validate JWTs. Your app receives pre-validated claims.

```rust
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    Extension, Router,
};
use barbican::auth::{Claims, log_access_decision};

// Middleware: Extract claims from gateway headers
async fn extract_claims(
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Gateway sets these headers after JWT validation
    let subject = request
        .headers()
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous");

    let roles: Vec<String> = request
        .headers()
        .get("X-User-Roles")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or_default();

    let claims = Claims::new(subject)
        .with_roles(roles);

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

// Handler: Use claims for authorization
async fn admin_handler(Extension(claims): Extension<Claims>) -> Result<&'static str, StatusCode> {
    if claims.has_role("admin") {
        log_access_decision(&claims, "admin_panel", true);
        Ok("Welcome, admin!")
    } else {
        log_access_decision(&claims, "admin_panel", false);
        Err(StatusCode::FORBIDDEN)
    }
}

// Router setup
let app = Router::new()
    .route("/admin", axum::routing::get(admin_handler))
    .layer(middleware::from_fn(extract_claims));
```

### Pattern 2: Direct JWT Validation

Validate JWTs directly in your app using `jsonwebtoken` crate.

```toml
# Cargo.toml
[dependencies]
jsonwebtoken = "9"
reqwest = { version = "0.11", features = ["json"] }
```

```rust
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::{self, Next},
    response::Response,
    Extension, Router,
};
use barbican::auth::{Claims, extract_keycloak_roles, extract_keycloak_groups};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use std::sync::Arc;

// JWKS cache (fetch from /.well-known/jwks.json)
struct JwksCache {
    keys: std::collections::HashMap<String, DecodingKey>,
}

// Middleware: Validate JWT and extract claims
async fn validate_jwt(
    jwks: Extension<Arc<JwksCache>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract token from Authorization header
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Decode header to get key ID
    let header = jsonwebtoken::decode_header(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let kid = header.kid.ok_or(StatusCode::UNAUTHORIZED)?;
    let key = jwks.keys.get(&kid).ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate token
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://your-keycloak.example.com/realms/your-realm"]);
    validation.set_audience(&["your-client-id"]);

    let token_data = decode::<serde_json::Value>(token, key, &validation)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Extract claims using barbican helpers
    let raw_claims = token_data.claims;
    let claims = Claims {
        subject: raw_claims.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        email: raw_claims.get("email")
            .and_then(|v| v.as_str())
            .map(String::from),
        roles: extract_keycloak_roles(&raw_claims),
        groups: extract_keycloak_groups(&raw_claims),
        issuer: raw_claims.get("iss")
            .and_then(|v| v.as_str())
            .map(String::from),
        expires_at: raw_claims.get("exp")
            .and_then(|v| v.as_i64()),
        ..Default::default()
    };

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
```

## Provider-Specific Configuration

### Keycloak

#### Token Claims Structure

```json
{
  "sub": "f1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "email": "user@example.com",
  "name": "John Doe",
  "realm_access": {
    "roles": ["user", "admin"]
  },
  "resource_access": {
    "my-app": {
      "roles": ["app-admin"]
    }
  },
  "groups": ["/engineering", "/platform/sre"]
}
```

#### Keycloak Configuration for Compliance

1. **Enable MFA** (IA-2(1)):
   - Authentication > Flows > Browser > Add "OTP Form" (for TOTP)
   - Or: Authentication > Flows > Browser > Add "WebAuthn Authenticator" (for hardware keys)
   - Set "Requirement" to "Required" for privileged users

2. **Configure ACR for MFA Levels** (for `acr` claim):
   - Authentication > Flows > Create new flow for MFA
   - Realm Settings > Client Policies > Create policy requiring MFA flow
   - Keycloak uses `acr` claim to indicate authentication level:
     - `0` = No authentication
     - `1` = Single factor (password only)
     - `2` = Multi-factor authentication

3. **Configure Password Policy** (IA-5(1)):
   - Realm Settings > Security Defenses > Password Policy
   - Add: `length(12) and notUsername and notEmail`

4. **Enable Audit Logging** (AU-2):
   - Events > Config > Enable "Save Events"
   - Select: LOGIN, LOGIN_ERROR, LOGOUT, etc.

5. **Session Timeouts** (AC-11, AC-12):
   - Realm Settings > Sessions
   - Set SSO Session Idle/Max appropriately

6. **Add Groups to Tokens**:
   - Client Scopes > Create "groups" scope
   - Add mapper: Type = "Group Membership", Token Claim Name = "groups"

**Note:** Keycloak uses `acr` (not `amr`) to indicate MFA. Check `acr` value or use step-up authentication.

#### Extract Claims in Rust

```rust
use barbican::auth::{Claims, extract_keycloak_roles, extract_keycloak_groups, extract_acr};

fn claims_from_keycloak(token_claims: &serde_json::Value) -> Claims {
    Claims {
        subject: token_claims.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        email: token_claims.get("email")
            .and_then(|v| v.as_str())
            .map(String::from),
        name: token_claims.get("name")
            .and_then(|v| v.as_str())
            .map(String::from),
        roles: extract_keycloak_roles(token_claims),
        groups: extract_keycloak_groups(token_claims),
        issuer: token_claims.get("iss")
            .and_then(|v| v.as_str())
            .map(String::from),
        expires_at: token_claims.get("exp")
            .and_then(|v| v.as_i64()),
        issued_at: token_claims.get("iat")
            .and_then(|v| v.as_i64()),
        acr: extract_acr(token_claims), // MFA level indicator
        ..Default::default()
    }
}

// Enforce MFA using ACR level
use barbican::auth::MfaPolicy;

let policy = MfaPolicy::require_acr("2"); // Require MFA (level 2)
if policy.is_satisfied(&claims) {
    // User completed MFA
}
```

### Entra ID (Azure AD)

#### Token Claims Structure

```json
{
  "oid": "12345678-1234-1234-1234-123456789012",
  "sub": "abcdefgh-1234-5678-90ab-cdef12345678",
  "email": "user@contoso.com",
  "name": "John Doe",
  "roles": ["Admin", "Reader"],
  "groups": ["guid-1", "guid-2"],
  "tid": "tenant-guid",
  "amr": ["pwd", "mfa"]
}
```

**Entra ID uses `amr` claim** for MFA indication. Common values:
- `pwd` - Password authentication
- `mfa` - Multi-factor authentication completed
- `rsa` - RSA SecurID or similar
- `otp` - One-time password
- `fido` - FIDO2/WebAuthn

#### Entra ID Configuration for Compliance

1. **Configure App Registration**:
   - Azure Portal > App Registrations > New
   - Add API permissions as needed
   - Configure token version (v2 recommended)

2. **Enable App Roles**:
   - App Registration > App Roles > Create
   - Assign roles to users/groups in Enterprise Applications

3. **Add Groups to Token**:
   - App Registration > Token Configuration > Add groups claim
   - Select "Security groups" or "Groups assigned to the application"

4. **Configure MFA via Conditional Access** (IA-2(1)):
   - Entra ID > Security > Conditional Access > Policies > New
   - Assignments: Select your app
   - Grant: Require multi-factor authentication
   - This ensures the `amr` claim includes `mfa`

5. **Require Specific Auth Methods** (IA-2(6)):
   - Entra ID > Security > Authentication methods
   - Configure FIDO2, Microsoft Authenticator, etc.
   - Conditional Access can require phishing-resistant methods

6. **Session Controls** (AC-11, AC-12):
   - Conditional Access > Session controls
   - Configure sign-in frequency

#### Extract Claims in Rust

```rust
use barbican::auth::{Claims, extract_entra_roles, extract_entra_groups, extract_amr};

fn claims_from_entra(token_claims: &serde_json::Value) -> Claims {
    // Entra uses 'oid' as the stable user identifier
    let subject = token_claims.get("oid")
        .or_else(|| token_claims.get("sub"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    Claims {
        subject,
        email: token_claims.get("email")
            .or_else(|| token_claims.get("preferred_username"))
            .and_then(|v| v.as_str())
            .map(String::from),
        name: token_claims.get("name")
            .and_then(|v| v.as_str())
            .map(String::from),
        roles: extract_entra_roles(token_claims),
        groups: extract_entra_groups(token_claims),
        amr: extract_amr(token_claims), // MFA methods used
        issuer: token_claims.get("iss")
            .and_then(|v| v.as_str())
            .map(String::from),
        expires_at: token_claims.get("exp")
            .and_then(|v| v.as_i64()),
        ..Default::default()
    }
}

// Enforce MFA using amr claim
use barbican::auth::MfaPolicy;

let policy = MfaPolicy::require_mfa();
if policy.is_satisfied(&claims) {
    // User completed MFA (amr contains "mfa" or pwd + second factor)
}

// Require phishing-resistant authentication (IA-2(6))
let phishing_resistant = MfaPolicy::require_any(&["fido", "hwk"]);
if phishing_resistant.is_satisfied(&claims) {
    // User used FIDO2/WebAuthn
}
```

### Auth0

#### Token Claims Structure

```json
{
  "sub": "auth0|1234567890",
  "email": "user@example.com",
  "name": "John Doe",
  "https://myapp.com/roles": ["admin", "user"],
  "permissions": ["read:users", "write:users"]
}
```

#### Auth0 Configuration

1. **Add Roles via Actions**:
   ```javascript
   // Auth0 Action: Add roles to token
   exports.onExecutePostLogin = async (event, api) => {
     const roles = event.authorization?.roles || [];
     api.idToken.setCustomClaim('https://myapp.com/roles', roles);
     api.accessToken.setCustomClaim('https://myapp.com/roles', roles);
   };
   ```

2. **Enable RBAC**:
   - APIs > Your API > Settings > Enable RBAC
   - Enable "Add Permissions in the Access Token"

#### Extract Claims in Rust

```rust
fn claims_from_auth0(token_claims: &serde_json::Value, namespace: &str) -> Claims {
    let roles_claim = format!("{}/roles", namespace);

    let roles: HashSet<String> = token_claims
        .get(&roles_claim)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
        .unwrap_or_default();

    let permissions: HashSet<String> = token_claims
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
        .unwrap_or_default();

    Claims {
        subject: token_claims.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        email: token_claims.get("email")
            .and_then(|v| v.as_str())
            .map(String::from),
        roles,
        scopes: permissions,
        ..Default::default()
    }
}
```

## Audit Logging Integration

All access decisions should be logged for compliance:

```rust
use barbican::auth::{Claims, log_access_decision, log_access_denied};

async fn protected_resource(
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check authorization
    if !claims.has_role("admin") && !claims.has_scope("read:sensitive") {
        log_access_denied(&claims, "sensitive_data", "missing admin role or read:sensitive scope");
        return Err(StatusCode::FORBIDDEN);
    }

    log_access_decision(&claims, "sensitive_data", true);
    Ok(Json(sensitive_data))
}
```

This produces audit logs like:

```json
{
  "timestamp": "2024-12-11T10:30:00Z",
  "security_event": "access_granted",
  "category": "authorization",
  "severity": "low",
  "user_id": "user-123",
  "resource": "sensitive_data",
  "roles": "admin,user",
  "issuer": "https://keycloak.example.com/realms/prod"
}
```

## NIST 800-53 Control Mapping

| Control | Requirement | OAuth Provider Responsibility | App Responsibility |
|---------|-------------|------------------------------|-------------------|
| **IA-2** | User identification | Authenticate users, issue tokens | Validate tokens |
| **IA-2(1)** | MFA for privileged | Configure MFA policies | Enforce MFA claim |
| **IA-5(1)** | Password policy | Enforce password requirements | N/A (delegated) |
| **AC-2** | Account management | User provisioning, deprovisioning | Honor token validity |
| **AC-3** | Access enforcement | Issue role/group claims | Enforce claims |
| **AC-7** | Login attempts | Lockout policies | N/A (delegated) |
| **AC-11** | Session lock | Idle timeout | Honor token expiry |
| **AC-12** | Session termination | Max session lifetime | Honor token expiry |
| **AU-2** | Audit events | Log auth events | Log authz decisions |
| **AU-3** | Audit content | Include user, time, outcome | Include resource, decision |

## Security Checklist

### Token Validation

- [ ] Validate token signature using provider's JWKS
- [ ] Verify `iss` (issuer) matches expected value
- [ ] Verify `aud` (audience) includes your client ID
- [ ] Check `exp` (expiration) is in the future
- [ ] Check `nbf` (not before) is in the past (if present)
- [ ] Validate `alg` is expected (RS256, ES256) - never accept `none`

### Claims Handling

- [ ] Extract roles/groups using provider-specific helpers
- [ ] Log all access decisions with user context
- [ ] Handle missing claims gracefully (deny by default)
- [ ] Validate claim values before use (SI-10)

### Provider Configuration

- [ ] Enable MFA for privileged accounts
- [ ] Configure appropriate session timeouts
- [ ] Enable audit logging in the provider
- [ ] Configure token lifetimes appropriately
- [ ] Use refresh tokens for long-lived sessions

### Infrastructure

- [ ] Use HTTPS for all OAuth endpoints
- [ ] Cache JWKS with appropriate TTL
- [ ] Handle JWKS rotation gracefully
- [ ] Monitor for authentication failures
