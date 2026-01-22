# Barbican Keycloak FAPI 2.0 Library
#
# Generates FAPI 2.0 compliant client policies and profiles for Keycloak.
# Supports MTLS sender-constrained tokens per FedRAMP requirements.
#
# FAPI 2.0 Security Profile Requirements:
#   - PAR (Pushed Authorization Requests) required
#   - PKCE with S256 required
#   - MTLS or DPoP for sender-constrained tokens
#   - Signed request objects (JAR)
#   - Short token lifetimes (5 min access, 30 min refresh)
#   - Strict redirect URI validation
#
# References:
#   - https://openid.net/specs/fapi-2_0-security-profile.html
#   - https://www.keycloak.org/docs/latest/server_admin/#_fapi-support
{ lib }:

with lib;

rec {
  # ===========================================================================
  # FAPI 2.0 Client Policies
  # ===========================================================================

  # Base FAPI 2.0 executor configurations
  fapiExecutors = {
    # Require PKCE with S256
    pkce = {
      executor = "pkce-enforcer";
      configuration = {
        auto-configure = "true";
        s256-required = "true";
      };
    };

    # Require PAR (Pushed Authorization Requests)
    par = {
      executor = "par-required";
      configuration = {
        auto-configure = "true";
      };
    };

    # Require signed request objects
    signedRequestObject = {
      executor = "secure-request-object-executor";
      configuration = {
        auto-configure = "true";
        available-request-object-signing-algorithms = [ "PS256" "ES256" ];
        verify-nonce = "true";
      };
    };

    # MTLS client authentication
    mtlsClientAuth = {
      executor = "client-x509-certificate-validator";
      configuration = {
        auto-configure = "true";
        allow-regex-pattern-comparison = "false";
      };
    };

    # MTLS sender-constrained tokens
    mtlsSenderConstraint = {
      executor = "holder-of-key-enforcer";
      configuration = {
        auto-configure = "true";
      };
    };

    # Confidential client requirement
    confidentialClient = {
      executor = "confidential-client";
      configuration = { };
    };

    # Secure response type (code only, no implicit)
    secureResponseType = {
      executor = "secure-response-type-executor";
      configuration = {
        auto-configure = "true";
        allow-code = "true";
        allow-token = "false";
        allow-id-token = "false";
      };
    };

    # Short token lifetimes
    tokenLifetimes = {
      executor = "token-lifespan";
      configuration = {
        access-token-lifespan = "300";       # 5 minutes
        refresh-token-lifespan = "1800";     # 30 minutes
        client-session-idle-timeout = "1800";
        client-session-max-lifespan = "3600";
      };
    };

    # Secure signing algorithms
    secureSigningAlgorithms = {
      executor = "secure-signing-algorithm";
      configuration = {
        default-algorithm = "PS256";
      };
    };

    # Full scope disabled (explicit scope grants only)
    fullScopeDisabled = {
      executor = "full-scope-disabled";
      configuration = { };
    };
  };

  # ===========================================================================
  # FAPI 2.0 Client Profiles
  # ===========================================================================

  # FAPI 2.0 Security Profile with MTLS
  fapi2MtlsProfile = {
    name = "fapi-2-mtls-security-profile";
    description = "FAPI 2.0 Security Profile with MTLS sender-constrained tokens";
    executors = [
      fapiExecutors.pkce
      fapiExecutors.par
      fapiExecutors.signedRequestObject
      fapiExecutors.mtlsClientAuth
      fapiExecutors.mtlsSenderConstraint
      fapiExecutors.confidentialClient
      fapiExecutors.secureResponseType
      fapiExecutors.tokenLifetimes
      fapiExecutors.secureSigningAlgorithms
      fapiExecutors.fullScopeDisabled
    ];
  };

  # Development profile (relaxed for testing)
  fapi2DevelopmentProfile = {
    name = "fapi-2-development";
    description = "Relaxed FAPI 2.0 for development (PKCE + short tokens only)";
    executors = [
      fapiExecutors.pkce
      fapiExecutors.tokenLifetimes
      fapiExecutors.secureSigningAlgorithms
    ];
  };

  # ===========================================================================
  # Profile Selection by FedRAMP Level
  # ===========================================================================

  profileForFedRAMP = level: {
    "development" = fapi2DevelopmentProfile;
    "fedramp-low" = fapi2DevelopmentProfile;  # Low can use relaxed
    "fedramp-moderate" = fapi2MtlsProfile;
    "fedramp-high" = fapi2MtlsProfile;
  }.${level} or fapi2MtlsProfile;

  # ===========================================================================
  # Client Policy Generation
  # ===========================================================================

  # Generate a client policy that applies a profile to matching clients
  mkClientPolicy = {
    name,
    description ? "",
    profile,
    conditions ? [],
  }: {
    inherit name description;
    enabled = true;
    profiles = [ profile.name ];
    conditions = if conditions == [] then [{
      condition = "any-client";
      configuration = { };
    }] else conditions;
  };

  # Policy that applies to clients with specific role
  mkRoleBasedPolicy = {
    name,
    profile,
    clientRoles ? [],
    realmRoles ? [],
  }: mkClientPolicy {
    inherit name profile;
    description = "Apply ${profile.name} to clients with specified roles";
    conditions = [{
      condition = "client-roles";
      configuration = {
        roles = map (r: { name = r; }) (clientRoles ++ realmRoles);
      };
    }];
  };

  # ===========================================================================
  # Keycloak Realm Policy JSON Generation
  # ===========================================================================

  # Generate the full client policies JSON for a realm
  mkRealmPolicies = {
    profile,
    additionalProfiles ? [],
    policies ? [],
  }: {
    profiles = [ profile ] ++ additionalProfiles;
    policies = if policies == [] then [{
      name = "fapi-2-default";
      description = "Default FAPI 2.0 policy for all clients";
      enabled = true;
      profiles = [ profile.name ];
      conditions = [{
        condition = "any-client";
        configuration = { };
      }];
    }] else policies;
  };

  # ===========================================================================
  # MTLS Configuration
  # ===========================================================================

  # X.509 authenticator configuration for MTLS
  mtlsAuthenticatorConfig = {
    # Map client cert DN to Keycloak user
    x509UserMapping = {
      mapping-source-selection = "Subject's Common Name";
      user-mapping-method = "Username or Email";
      custom-attribute-name = "";
      crl-checking-enabled = "false";
      ocsp-checking-enabled = "false";
      timestamp-validation-enabled = "true";
    };

    # For client certificate authentication
    x509ClientAuth = {
      x509-cert-auth = "true";
      certificate-policy-checking-enabled = "true";
      crl-checking-enabled = "true";
      ocsp-checking-enabled = "true";
      key-usage-checking-enabled = "true";
      extended-key-usage-checking-enabled = "true";
    };
  };

  # TLS configuration for Keycloak with MTLS
  mtlsTlsConfig = {
    # Require client certificates
    clientAuth = "request";  # "none", "request", "required"

    # Trust store for client CA certificates
    trustStoreFile = "/etc/keycloak/truststore.jks";
    trustStorePassword = "changeit";  # Should come from Vault

    # Allowed certificate DNs (optional, for additional filtering)
    allowedDnPattern = null;
  };

  # ===========================================================================
  # Token Configuration
  # ===========================================================================

  # FAPI 2.0 compliant token settings
  fapi2TokenSettings = {
    accessTokenLifespan = 300;           # 5 minutes
    accessTokenLifespanForImplicitFlow = 300;
    refreshTokenLifespan = 1800;         # 30 minutes
    refreshTokenMaxReuse = 0;            # No reuse
    revokeRefreshToken = true;

    # ID token settings
    idTokenSignatureAlgorithm = "PS256";
    idTokenEncryptionRequired = false;

    # Access token settings
    accessTokenSignatureAlgorithm = "PS256";

    # Proof key settings
    useRefreshTokens = true;
    useRefreshTokenForClientCredentialsGrant = false;
  };

  # ===========================================================================
  # Audit/Logging Configuration (FedRAMP AU-2, AU-3)
  # ===========================================================================

  fapi2AuditEvents = [
    # Authentication events
    "LOGIN"
    "LOGIN_ERROR"
    "LOGOUT"
    "LOGOUT_ERROR"
    "CODE_TO_TOKEN"
    "CODE_TO_TOKEN_ERROR"
    "REFRESH_TOKEN"
    "REFRESH_TOKEN_ERROR"

    # Token events
    "INTROSPECT_TOKEN"
    "INTROSPECT_TOKEN_ERROR"
    "TOKEN_EXCHANGE"
    "TOKEN_EXCHANGE_ERROR"
    "REVOKE_GRANT"
    "REVOKE_GRANT_ERROR"

    # Client events
    "CLIENT_LOGIN"
    "CLIENT_LOGIN_ERROR"
    "CLIENT_REGISTER"
    "CLIENT_UPDATE"
    "CLIENT_DELETE"

    # User events
    "REGISTER"
    "REGISTER_ERROR"
    "UPDATE_PROFILE"
    "UPDATE_PASSWORD"
    "RESET_PASSWORD"
    "RESET_PASSWORD_ERROR"

    # Admin events
    "ADMIN_EVENT"

    # PAR events (FAPI 2.0 specific)
    "PUSHED_AUTHORIZATION_REQUEST"
    "PUSHED_AUTHORIZATION_REQUEST_ERROR"
  ];
}
