//! OAuth/JWT Claims Bridge (AC-3, IA-2)
//!
//! Minimal bridge for extracting and logging authorization claims from OAuth/OIDC
//! providers like Keycloak, Entra ID, Auth0, etc.
//!
//! # Design Philosophy
//!
//! Barbican does NOT attempt to be an authorization framework. Your OAuth provider
//! (Keycloak, Entra, Auth0) handles:
//! - User authentication
//! - Role/group management
//! - Token issuance
//! - MFA enrollment and verification
//! - SSO, federation
//!
//! This module provides a **minimal bridge** to:
//! 1. Extract claims from validated JWTs for use in your app
//! 2. **Enforce MFA requirements** based on token claims (IA-2(1), IA-2(2))
//! 3. Log authorization decisions for NIST 800-53 AU-2/AU-3 compliance
//! 4. Provide helper types for common claim patterns
//!
//! # MFA Enforcement (IA-2(1), IA-2(2))
//!
//! Your OAuth provider performs MFA. Barbican enforces that MFA was completed
//! by checking the `amr` (Authentication Methods References) claim in the JWT.
//!
//! ```ignore
//! use barbican::auth::{Claims, MfaPolicy};
//!
//! // Check if user completed MFA
//! if claims.mfa_satisfied() {
//!     // User passed MFA challenge
//! }
//!
//! // Require specific authentication methods
//! let policy = MfaPolicy::require_any(&["otp", "hwk", "swk"]);
//! if policy.is_satisfied(&claims) {
//!     // User used TOTP, hardware key, or software key
//! }
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use barbican::auth::{Claims, log_access_decision};
//! use axum::{Extension, extract::Request};
//!
//! // Your JWT validation middleware populates Claims
//! async fn protected_handler(Extension(claims): Extension<Claims>) -> &'static str {
//!     // Check claims from your OAuth provider
//!     if claims.has_role("admin") {
//!         log_access_decision(&claims, "admin_panel", true);
//!         "Welcome, admin!"
//!     } else {
//!         log_access_decision(&claims, "admin_panel", false);
//!         "Access denied"
//!     }
//! }
//! ```
//!
//! # Integration with OAuth Providers
//!
//! See the documentation in `.claudedocs/OAUTH_INTEGRATION.md` for detailed
//! integration patterns with Keycloak, Entra ID, and other providers.

use std::collections::HashSet;

use crate::observability::SecurityEvent;

// ============================================================================
// Claims Types
// ============================================================================

/// Standard claims extracted from a validated JWT (AC-3, IA-2)
///
/// This struct represents the common claims found in OAuth/OIDC tokens.
/// Populate this from your JWT validation middleware.
///
/// # Common Claim Mappings
///
/// | Provider | Subject | Roles Claim | Groups Claim | MFA Claim |
/// |----------|---------|-------------|--------------|-----------|
/// | Keycloak | `sub` | `realm_access.roles` | `groups` | `acr` |
/// | Entra ID | `oid` or `sub` | `roles` | `groups` | `amr` |
/// | Auth0 | `sub` | `permissions` or custom | custom namespace | `amr` |
/// | Okta | `sub` | `groups` | `groups` | `amr` |
#[derive(Debug, Clone, Default)]
pub struct Claims {
    /// Subject identifier (user ID from the IdP)
    pub subject: String,

    /// User's email (if provided in token)
    pub email: Option<String>,

    /// User's display name (if provided)
    pub name: Option<String>,

    /// Roles from the token (provider-specific claim)
    pub roles: HashSet<String>,

    /// Groups from the token (provider-specific claim)
    pub groups: HashSet<String>,

    /// Scopes granted to the token
    pub scopes: HashSet<String>,

    /// Token issuer (iss claim)
    pub issuer: Option<String>,

    /// Token audience (aud claim)
    pub audience: Option<String>,

    /// Token expiration (exp claim) as Unix timestamp
    pub expires_at: Option<i64>,

    /// Token issued at (iat claim) as Unix timestamp
    pub issued_at: Option<i64>,

    /// Authentication Methods References (amr claim) - IA-2(1), IA-2(2)
    ///
    /// This claim indicates which authentication methods were used.
    /// Common values (RFC 8176):
    /// - `pwd` - Password
    /// - `otp` - One-time password (TOTP/HOTP)
    /// - `hwk` - Hardware key (WebAuthn, FIDO2)
    /// - `swk` - Software key
    /// - `sms` - SMS verification
    /// - `mfa` - Multiple factors used
    /// - `pin` - PIN
    /// - `fpt` - Fingerprint biometric
    /// - `face` - Facial recognition
    pub amr: HashSet<String>,

    /// Authentication Context Class Reference (acr claim)
    ///
    /// Indicates the authentication context class (level of assurance).
    /// Keycloak uses this to indicate authentication level.
    pub acr: Option<String>,

    /// Additional custom claims (provider-specific)
    pub custom: std::collections::HashMap<String, serde_json::Value>,
}

impl Claims {
    /// Create empty claims (for anonymous/unauthenticated requests)
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".to_string(),
            ..Default::default()
        }
    }

    /// Create claims with just a subject
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            ..Default::default()
        }
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Check if the user has any of the specified roles
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.roles.contains(*r))
    }

    /// Check if the user has all of the specified roles
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        roles.iter().all(|r| self.roles.contains(*r))
    }

    /// Check if the user is in a specific group
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.contains(group)
    }

    /// Check if the user has a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            exp < now
        } else {
            false // No expiration = not expired (though this is unusual)
        }
    }

    /// Get a custom claim value
    pub fn get_custom(&self, key: &str) -> Option<&serde_json::Value> {
        self.custom.get(key)
    }

    /// Get a custom claim as a string
    pub fn get_custom_str(&self, key: &str) -> Option<&str> {
        self.custom.get(key).and_then(|v| v.as_str())
    }

    /// Builder: add a role
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.insert(role.into());
        self
    }

    /// Builder: add roles
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.roles.extend(roles.into_iter().map(|r| r.into()));
        self
    }

    /// Builder: add a group
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.groups.insert(group.into());
        self
    }

    /// Builder: add a scope
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.insert(scope.into());
        self
    }

    /// Builder: set email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Builder: set issuer
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Builder: add authentication method reference
    pub fn with_amr(mut self, method: impl Into<String>) -> Self {
        self.amr.insert(method.into());
        self
    }

    /// Builder: set authentication context class reference
    pub fn with_acr(mut self, acr: impl Into<String>) -> Self {
        self.acr = Some(acr.into());
        self
    }

    // ========================================================================
    // MFA Methods (IA-2(1), IA-2(2))
    // ========================================================================

    /// Check if MFA was completed (IA-2(1), IA-2(2))
    ///
    /// Returns true if the token indicates multi-factor authentication was used.
    /// This checks for common MFA indicators:
    /// - `mfa` in amr claim
    /// - Multiple authentication methods in amr
    /// - Second factor methods (otp, hwk, swk, sms, fpt, face)
    pub fn mfa_satisfied(&self) -> bool {
        // Explicit MFA claim
        if self.amr.contains("mfa") {
            return true;
        }

        // Check for second factor methods
        let second_factors = ["otp", "hwk", "swk", "sms", "fpt", "face", "pin"];
        let has_second_factor = self.amr.iter().any(|m| second_factors.contains(&m.as_str()));

        // Check for password + second factor
        let has_password = self.amr.contains("pwd");

        has_password && has_second_factor
    }

    /// Check if a specific authentication method was used
    pub fn used_auth_method(&self, method: &str) -> bool {
        self.amr.contains(method)
    }

    /// Check if any of the specified authentication methods were used
    pub fn used_any_auth_method(&self, methods: &[&str]) -> bool {
        methods.iter().any(|m| self.amr.contains(*m))
    }

    /// Check if hardware-based authentication was used (IA-2(6))
    ///
    /// Hardware keys provide stronger security than software-based methods.
    pub fn used_hardware_auth(&self) -> bool {
        self.amr.contains("hwk")
    }

    /// Check if biometric authentication was used
    pub fn used_biometric_auth(&self) -> bool {
        self.amr.contains("fpt") || self.amr.contains("face")
    }

    /// Get the authentication context class (level of assurance)
    pub fn auth_level(&self) -> Option<&str> {
        self.acr.as_deref()
    }
}

// ============================================================================
// Keycloak-specific helpers
// ============================================================================

/// Helper to extract roles from Keycloak's nested claim structure
///
/// Keycloak stores roles in `realm_access.roles` and `resource_access.<client>.roles`
pub fn extract_keycloak_roles(token_claims: &serde_json::Value) -> HashSet<String> {
    let mut roles = HashSet::new();

    // Extract realm roles from realm_access.roles
    if let Some(realm_access) = token_claims.get("realm_access") {
        if let Some(realm_roles) = realm_access.get("roles").and_then(|r| r.as_array()) {
            for role in realm_roles {
                if let Some(r) = role.as_str() {
                    roles.insert(r.to_string());
                }
            }
        }
    }

    // Extract client roles from resource_access.<client>.roles
    if let Some(resource_access) = token_claims.get("resource_access").and_then(|r| r.as_object()) {
        for (_client, access) in resource_access {
            if let Some(client_roles) = access.get("roles").and_then(|r| r.as_array()) {
                for role in client_roles {
                    if let Some(r) = role.as_str() {
                        roles.insert(r.to_string());
                    }
                }
            }
        }
    }

    roles
}

/// Helper to extract groups from Keycloak tokens
///
/// Keycloak stores groups in the `groups` claim (if mapper is configured)
pub fn extract_keycloak_groups(token_claims: &serde_json::Value) -> HashSet<String> {
    let mut groups = HashSet::new();

    if let Some(groups_claim) = token_claims.get("groups").and_then(|g| g.as_array()) {
        for group in groups_claim {
            if let Some(g) = group.as_str() {
                // Keycloak groups often have leading slash, normalize
                groups.insert(g.trim_start_matches('/').to_string());
            }
        }
    }

    groups
}

// ============================================================================
// Entra ID (Azure AD) helpers
// ============================================================================

/// Helper to extract roles from Entra ID tokens
///
/// Entra ID stores app roles in the `roles` claim
pub fn extract_entra_roles(token_claims: &serde_json::Value) -> HashSet<String> {
    let mut roles = HashSet::new();

    if let Some(roles_claim) = token_claims.get("roles").and_then(|r| r.as_array()) {
        for role in roles_claim {
            if let Some(r) = role.as_str() {
                roles.insert(r.to_string());
            }
        }
    }

    roles
}

/// Helper to extract groups from Entra ID tokens
///
/// Entra ID stores group IDs in the `groups` claim (GUIDs by default)
/// Note: Configure "Emit groups as role claims" for group names instead of IDs
pub fn extract_entra_groups(token_claims: &serde_json::Value) -> HashSet<String> {
    let mut groups = HashSet::new();

    if let Some(groups_claim) = token_claims.get("groups").and_then(|g| g.as_array()) {
        for group in groups_claim {
            if let Some(g) = group.as_str() {
                groups.insert(g.to_string());
            }
        }
    }

    groups
}

// ============================================================================
// MFA Claim Extraction Helpers
// ============================================================================

/// Extract authentication methods reference (amr) from token claims
///
/// The `amr` claim is an array of strings indicating which authentication
/// methods were used. This is standard in OIDC tokens.
pub fn extract_amr(token_claims: &serde_json::Value) -> HashSet<String> {
    let mut amr = HashSet::new();

    if let Some(amr_claim) = token_claims.get("amr").and_then(|a| a.as_array()) {
        for method in amr_claim {
            if let Some(m) = method.as_str() {
                amr.insert(m.to_string());
            }
        }
    }

    amr
}

/// Extract authentication context class reference (acr) from token claims
///
/// The `acr` claim indicates the authentication context class (level of assurance).
pub fn extract_acr(token_claims: &serde_json::Value) -> Option<String> {
    token_claims
        .get("acr")
        .and_then(|a| a.as_str())
        .map(String::from)
}

// ============================================================================
// MFA Policy (IA-2(1), IA-2(2))
// ============================================================================

/// MFA enforcement policy (IA-2(1), IA-2(2))
///
/// Use this to define MFA requirements for your application.
/// The policy checks the `amr` claim in the JWT to verify MFA completion.
///
/// # Example
///
/// ```ignore
/// use barbican::auth::MfaPolicy;
///
/// // Require any second factor
/// let policy = MfaPolicy::require_mfa();
///
/// // Require specific methods (hardware key or biometric)
/// let strict = MfaPolicy::require_any(&["hwk", "fpt", "face"]);
///
/// // Require hardware key specifically (IA-2(6))
/// let hardware_only = MfaPolicy::require_hardware_key();
///
/// // Check policy against claims
/// if policy.is_satisfied(&claims) {
///     // MFA requirement met
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MfaPolicy {
    /// Required authentication methods (any of these satisfies the policy)
    pub required_methods: HashSet<String>,

    /// If true, just check that MFA was performed (any second factor)
    pub require_any_mfa: bool,

    /// If true, require hardware-based authentication
    pub require_hardware: bool,

    /// Minimum ACR level (if specified)
    pub min_acr_level: Option<String>,
}

impl Default for MfaPolicy {
    fn default() -> Self {
        Self {
            required_methods: HashSet::new(),
            require_any_mfa: true, // By default, require some form of MFA
            require_hardware: false,
            min_acr_level: None,
        }
    }
}

impl MfaPolicy {
    /// Create a policy that requires any form of MFA
    pub fn require_mfa() -> Self {
        Self::default()
    }

    /// Create a policy that requires specific authentication methods
    ///
    /// The user must have used at least one of the specified methods.
    pub fn require_any(methods: &[&str]) -> Self {
        Self {
            required_methods: methods.iter().map(|s| s.to_string()).collect(),
            require_any_mfa: false,
            require_hardware: false,
            min_acr_level: None,
        }
    }

    /// Create a policy that requires hardware key authentication (IA-2(6))
    pub fn require_hardware_key() -> Self {
        Self {
            required_methods: HashSet::new(),
            require_any_mfa: false,
            require_hardware: true,
            min_acr_level: None,
        }
    }

    /// Create a policy that requires a minimum ACR level
    pub fn require_acr(level: impl Into<String>) -> Self {
        Self {
            required_methods: HashSet::new(),
            require_any_mfa: false,
            require_hardware: false,
            min_acr_level: Some(level.into()),
        }
    }

    /// Create a permissive policy (no MFA required)
    pub fn none() -> Self {
        Self {
            required_methods: HashSet::new(),
            require_any_mfa: false,
            require_hardware: false,
            min_acr_level: None,
        }
    }

    /// Check if the policy is satisfied by the given claims
    pub fn is_satisfied(&self, claims: &Claims) -> bool {
        // Check hardware requirement
        if self.require_hardware && !claims.used_hardware_auth() {
            return false;
        }

        // Check specific method requirements
        if !self.required_methods.is_empty() {
            let has_required = self
                .required_methods
                .iter()
                .any(|m| claims.amr.contains(m));
            if !has_required {
                return false;
            }
        }

        // Check general MFA requirement
        if self.require_any_mfa && !claims.mfa_satisfied() {
            return false;
        }

        // Check ACR level (simple string comparison for now)
        if let Some(ref min_acr) = self.min_acr_level {
            match &claims.acr {
                Some(acr) => {
                    // For Keycloak-style numeric ACR levels
                    if let (Ok(min), Ok(actual)) = (min_acr.parse::<i32>(), acr.parse::<i32>()) {
                        if actual < min {
                            return false;
                        }
                    } else {
                        // String comparison - must match exactly
                        if acr != min_acr {
                            return false;
                        }
                    }
                }
                None => return false,
            }
        }

        true
    }

    /// Check policy and log the result
    pub fn check_and_log(&self, claims: &Claims, resource: &str) -> bool {
        let satisfied = self.is_satisfied(claims);

        if satisfied {
            log_mfa_success(claims, resource);
        } else {
            log_mfa_required(claims, resource, self.describe_requirement());
        }

        satisfied
    }

    /// Describe what this policy requires (for error messages)
    pub fn describe_requirement(&self) -> String {
        if self.require_hardware {
            return "Hardware key authentication required".to_string();
        }

        if !self.required_methods.is_empty() {
            return format!(
                "One of these authentication methods required: {}",
                self.required_methods
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        if let Some(ref acr) = self.min_acr_level {
            return format!("Authentication level {} or higher required", acr);
        }

        if self.require_any_mfa {
            return "Multi-factor authentication required".to_string();
        }

        "No MFA required".to_string()
    }
}

// ============================================================================
// MFA Audit Logging
// ============================================================================

/// Log successful MFA verification (AU-2, AU-3)
pub fn log_mfa_success(claims: &Claims, resource: &str) {
    let amr_str = claims.amr.iter().cloned().collect::<Vec<_>>().join(",");

    crate::security_event!(
        SecurityEvent::AccessGranted,
        user_id = %claims.subject,
        resource = %resource,
        amr = %amr_str,
        acr = %claims.acr.as_deref().unwrap_or("none"),
        mfa_satisfied = true,
        "MFA requirement satisfied"
    );
}

/// Log MFA requirement not met (AU-2, AU-3)
pub fn log_mfa_required(claims: &Claims, resource: &str, requirement: String) {
    let amr_str = claims.amr.iter().cloned().collect::<Vec<_>>().join(",");

    crate::security_event!(
        SecurityEvent::AccessDenied,
        user_id = %claims.subject,
        resource = %resource,
        amr = %amr_str,
        acr = %claims.acr.as_deref().unwrap_or("none"),
        requirement = %requirement,
        "MFA requirement not satisfied"
    );
}

// ============================================================================
// Audit Logging (AU-2, AU-3)
// ============================================================================

/// Log an access control decision for audit compliance (AU-2, AU-3)
///
/// Use this function after making authorization decisions to maintain
/// an audit trail as required by NIST 800-53.
///
/// # Arguments
///
/// * `claims` - The user's claims from the JWT
/// * `resource` - Description of the resource being accessed
/// * `allowed` - Whether access was granted
///
/// # Example
///
/// ```ignore
/// use barbican::auth::{Claims, log_access_decision};
///
/// fn check_admin_access(claims: &Claims) -> bool {
///     let allowed = claims.has_role("admin");
///     log_access_decision(claims, "admin_panel", allowed);
///     allowed
/// }
/// ```
pub fn log_access_decision(claims: &Claims, resource: &str, allowed: bool) {
    let event = if allowed {
        SecurityEvent::AccessGranted
    } else {
        SecurityEvent::AccessDenied
    };

    let roles_str = claims.roles.iter().cloned().collect::<Vec<_>>().join(",");

    crate::security_event!(
        event,
        user_id = %claims.subject,
        resource = %resource,
        roles = %roles_str,
        issuer = %claims.issuer.as_deref().unwrap_or("unknown"),
        "Access decision made"
    );
}

/// Log an access denial with reason (AU-2, AU-3)
///
/// More detailed logging for denied access attempts.
pub fn log_access_denied(claims: &Claims, resource: &str, reason: &str) {
    let roles_str = claims.roles.iter().cloned().collect::<Vec<_>>().join(",");

    crate::security_event!(
        SecurityEvent::AccessDenied,
        user_id = %claims.subject,
        resource = %resource,
        roles = %roles_str,
        reason = %reason,
        issuer = %claims.issuer.as_deref().unwrap_or("unknown"),
        "Access denied"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_roles() {
        let claims = Claims::new("user1")
            .with_role("admin")
            .with_role("user");

        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
        assert!(!claims.has_role("superadmin"));

        assert!(claims.has_any_role(&["admin", "superadmin"]));
        assert!(!claims.has_any_role(&["superadmin", "guest"]));

        assert!(claims.has_all_roles(&["admin", "user"]));
        assert!(!claims.has_all_roles(&["admin", "superadmin"]));
    }

    #[test]
    fn test_claims_groups() {
        let claims = Claims::new("user1")
            .with_group("engineering")
            .with_group("platform");

        assert!(claims.in_group("engineering"));
        assert!(!claims.in_group("marketing"));
    }

    #[test]
    fn test_claims_scopes() {
        let claims = Claims::new("user1")
            .with_scope("read:users")
            .with_scope("write:users");

        assert!(claims.has_scope("read:users"));
        assert!(!claims.has_scope("delete:users"));
    }

    #[test]
    fn test_token_expiration() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let valid_claims = Claims {
            subject: "user1".to_string(),
            expires_at: Some(now + 3600), // 1 hour from now
            ..Default::default()
        };
        assert!(!valid_claims.is_expired());

        let expired_claims = Claims {
            subject: "user1".to_string(),
            expires_at: Some(now - 3600), // 1 hour ago
            ..Default::default()
        };
        assert!(expired_claims.is_expired());
    }

    #[test]
    fn test_keycloak_role_extraction() {
        let token = serde_json::json!({
            "realm_access": {
                "roles": ["user", "admin"]
            },
            "resource_access": {
                "my-client": {
                    "roles": ["client-admin"]
                }
            }
        });

        let roles = extract_keycloak_roles(&token);
        assert!(roles.contains("user"));
        assert!(roles.contains("admin"));
        assert!(roles.contains("client-admin"));
    }

    #[test]
    fn test_keycloak_group_extraction() {
        let token = serde_json::json!({
            "groups": ["/engineering", "/platform/sre"]
        });

        let groups = extract_keycloak_groups(&token);
        assert!(groups.contains("engineering"));
        assert!(groups.contains("platform/sre"));
    }

    #[test]
    fn test_entra_role_extraction() {
        let token = serde_json::json!({
            "roles": ["Admin", "Reader"]
        });

        let roles = extract_entra_roles(&token);
        assert!(roles.contains("Admin"));
        assert!(roles.contains("Reader"));
    }

    #[test]
    fn test_anonymous_claims() {
        let claims = Claims::anonymous();
        assert_eq!(claims.subject, "anonymous");
        assert!(claims.roles.is_empty());
    }

    // MFA Tests

    #[test]
    fn test_mfa_satisfied_explicit() {
        // Explicit MFA claim
        let claims = Claims::new("user1").with_amr("mfa");
        assert!(claims.mfa_satisfied());
    }

    #[test]
    fn test_mfa_satisfied_pwd_plus_otp() {
        // Password + TOTP
        let claims = Claims::new("user1")
            .with_amr("pwd")
            .with_amr("otp");
        assert!(claims.mfa_satisfied());
    }

    #[test]
    fn test_mfa_satisfied_pwd_plus_hwk() {
        // Password + Hardware key
        let claims = Claims::new("user1")
            .with_amr("pwd")
            .with_amr("hwk");
        assert!(claims.mfa_satisfied());
        assert!(claims.used_hardware_auth());
    }

    #[test]
    fn test_mfa_not_satisfied_pwd_only() {
        // Password only - not MFA
        let claims = Claims::new("user1").with_amr("pwd");
        assert!(!claims.mfa_satisfied());
    }

    #[test]
    fn test_mfa_not_satisfied_empty() {
        // No auth methods
        let claims = Claims::new("user1");
        assert!(!claims.mfa_satisfied());
    }

    #[test]
    fn test_mfa_policy_require_mfa() {
        let policy = MfaPolicy::require_mfa();

        let mfa_claims = Claims::new("user1")
            .with_amr("pwd")
            .with_amr("otp");
        assert!(policy.is_satisfied(&mfa_claims));

        let no_mfa = Claims::new("user1").with_amr("pwd");
        assert!(!policy.is_satisfied(&no_mfa));
    }

    #[test]
    fn test_mfa_policy_require_any() {
        let policy = MfaPolicy::require_any(&["hwk", "fpt"]);

        let hwk_claims = Claims::new("user1").with_amr("hwk");
        assert!(policy.is_satisfied(&hwk_claims));

        let fpt_claims = Claims::new("user1").with_amr("fpt");
        assert!(policy.is_satisfied(&fpt_claims));

        let otp_claims = Claims::new("user1").with_amr("otp");
        assert!(!policy.is_satisfied(&otp_claims));
    }

    #[test]
    fn test_mfa_policy_require_hardware() {
        let policy = MfaPolicy::require_hardware_key();

        let hwk_claims = Claims::new("user1").with_amr("hwk");
        assert!(policy.is_satisfied(&hwk_claims));

        let otp_claims = Claims::new("user1").with_amr("otp");
        assert!(!policy.is_satisfied(&otp_claims));
    }

    #[test]
    fn test_mfa_policy_none() {
        let policy = MfaPolicy::none();

        let no_mfa = Claims::new("user1");
        assert!(policy.is_satisfied(&no_mfa));

        let mfa = Claims::new("user1").with_amr("mfa");
        assert!(policy.is_satisfied(&mfa));
    }

    #[test]
    fn test_mfa_policy_acr_level() {
        let policy = MfaPolicy::require_acr("2");

        let acr2 = Claims::new("user1").with_acr("2");
        assert!(policy.is_satisfied(&acr2));

        let acr3 = Claims::new("user1").with_acr("3");
        assert!(policy.is_satisfied(&acr3));

        let acr1 = Claims::new("user1").with_acr("1");
        assert!(!policy.is_satisfied(&acr1));

        let no_acr = Claims::new("user1");
        assert!(!policy.is_satisfied(&no_acr));
    }

    #[test]
    fn test_extract_amr() {
        let token = serde_json::json!({
            "amr": ["pwd", "otp"]
        });

        let amr = extract_amr(&token);
        assert!(amr.contains("pwd"));
        assert!(amr.contains("otp"));
        assert!(!amr.contains("hwk"));
    }

    #[test]
    fn test_extract_acr() {
        let token = serde_json::json!({
            "acr": "urn:mace:incommon:iap:silver"
        });

        let acr = extract_acr(&token);
        assert_eq!(acr, Some("urn:mace:incommon:iap:silver".to_string()));
    }

    #[test]
    fn test_biometric_auth() {
        let fpt_claims = Claims::new("user1").with_amr("fpt");
        assert!(fpt_claims.used_biometric_auth());

        let face_claims = Claims::new("user1").with_amr("face");
        assert!(face_claims.used_biometric_auth());

        let pwd_claims = Claims::new("user1").with_amr("pwd");
        assert!(!pwd_claims.used_biometric_auth());
    }
}
