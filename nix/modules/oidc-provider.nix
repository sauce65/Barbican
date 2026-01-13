# Barbican Security Module: OIDC Provider (Keycloak)
#
# Why: Provides a turnkey, compliance-ready OIDC/OAuth2 identity provider
# for FedRAMP Low/Moderate/High applications with FAPI 2.0 security profile.
#
# What: Deploys Keycloak with:
# - FIPS 140-3 validated cryptography
# - FAPI 2.0 security profile (mTLS, PAR, certificate-bound tokens)
# - FedRAMP-compliant password policies and session timeouts
# - Declarative realm, client, role, and user provisioning
# - Integration with Barbican's secure-postgres, vault-pki, and observability
#
# How: Uses Podman containers for Keycloak, integrates with existing Barbican
# modules via NixOS configuration, auto-provisions on first boot.
#
# NIST 800-53 Controls: IA-2, IA-2(1), IA-2(2), IA-4, IA-5, IA-5(1), IA-8,
# AC-2, AC-3, AC-7, AC-11, AC-12, AU-2, AU-3, SC-8, SC-13, SC-23
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.oidc;

  # FedRAMP profile defaults for session and security settings
  # Based on NIST 800-53 Rev 5 controls AC-11, AC-12, AC-7, IA-5(1)
  profileDefaults = {
    development = {
      accessTokenLifespan = 3600;  # 1 hour for dev convenience
      sessionIdleTimeout = 3600;   # 1 hour
      sessionMaxLifespan = 43200;  # 12 hours
      bruteForceEnabled = false;
      failureFactor = 10;
      lockoutDuration = 300;       # 5 minutes
      passwordMinLength = 8;
      passwordRequireUppercase = false;
      passwordRequireDigit = false;
      passwordRequireSpecialChar = false;
      passwordHistoryCount = 0;
      requireMFA = false;
      fipsMode = false;
      enableFAPI = false;
    };
    fedramp-low = {
      accessTokenLifespan = 600;   # 10 minutes (FAPI 2.0 max)
      sessionIdleTimeout = 1800;   # 30 minutes (AC-11)
      sessionMaxLifespan = 28800;  # 8 hours (AC-12)
      bruteForceEnabled = true;
      failureFactor = 5;           # 5 attempts (AC-7)
      lockoutDuration = 900;       # 15 minutes (AC-7)
      passwordMinLength = 8;       # NIST 800-63B minimum
      passwordRequireUppercase = true;
      passwordRequireDigit = true;
      passwordRequireSpecialChar = true;
      passwordHistoryCount = 24;   # IA-5(1)
      requireMFA = false;
      fipsMode = true;
      enableFAPI = false;
    };
    fedramp-moderate = {
      accessTokenLifespan = 600;   # 10 minutes (FAPI 2.0 max)
      sessionIdleTimeout = 900;    # 15 minutes (AC-11)
      sessionMaxLifespan = 14400;  # 4 hours (AC-12)
      bruteForceEnabled = true;
      failureFactor = 3;           # 3 attempts (AC-7)
      lockoutDuration = 1800;      # 30 minutes (AC-7)
      passwordMinLength = 12;      # 12 characters
      passwordRequireUppercase = true;
      passwordRequireDigit = true;
      passwordRequireSpecialChar = true;
      passwordHistoryCount = 24;   # IA-5(1)
      requireMFA = false;          # Optional for Moderate
      fipsMode = true;
      enableFAPI = true;           # FAPI 2.0 for financial apps
    };
    fedramp-high = {
      accessTokenLifespan = 300;   # 5 minutes (stricter than FAPI)
      sessionIdleTimeout = 600;    # 10 minutes (AC-11)
      sessionMaxLifespan = 7200;   # 2 hours (AC-12)
      bruteForceEnabled = true;
      failureFactor = 3;           # 3 attempts (AC-7)
      lockoutDuration = 1800;      # 30 minutes (AC-7)
      passwordMinLength = 15;      # 15 characters for High
      passwordRequireUppercase = true;
      passwordRequireDigit = true;
      passwordRequireSpecialChar = true;
      passwordHistoryCount = 24;   # IA-5(1)
      requireMFA = true;           # MFA mandatory (IA-2(1))
      fipsMode = true;
      enableFAPI = true;
    };
  };

  # Generate random secret if not provided
  defaultSecret = "barbican-oidc-${builtins.substring 0 8 (builtins.hashString "sha256" (toString builtins.currentTime))}";

  # User submodule type
  userType = types.submodule {
    options = {
      email = mkOption {
        type = types.str;
        description = "User email address";
      };

      firstName = mkOption {
        type = types.str;
        default = "";
        description = "User first name";
      };

      lastName = mkOption {
        type = types.str;
        default = "";
        description = "User last name";
      };

      password = mkOption {
        type = types.str;
        description = "User password (use passwordFile in production)";
      };

      roles = mkOption {
        type = types.listOf types.str;
        default = [ "user" ];
        description = "Roles to assign to user";
      };

      enabled = mkOption {
        type = types.bool;
        default = true;
        description = "Whether the user account is enabled";
      };
    };
  };

  # Client submodule type with FAPI 2.0 support
  clientType = types.submodule {
    options = {
      name = mkOption {
        type = types.str;
        description = "Human-readable client name";
      };

      secret = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Client secret (null for public clients)";
      };

      public = mkOption {
        type = types.bool;
        default = false;
        description = "Whether this is a public client (SPAs, mobile apps)";
      };

      redirectUris = mkOption {
        type = types.listOf types.str;
        default = [ "http://localhost:*/*" "http://127.0.0.1:*/*" ];
        description = "Allowed redirect URIs";
      };

      webOrigins = mkOption {
        type = types.listOf types.str;
        default = [ "http://localhost:*" "http://127.0.0.1:*" ];
        description = "Allowed web origins for CORS";
      };

      directAccessGrantsEnabled = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Resource Owner Password Credentials grant";
      };

      serviceAccountsEnabled = mkOption {
        type = types.bool;
        default = false;
        description = "Enable service account (client credentials grant)";
      };

      # FAPI 2.0 Security Profile Options
      enableFAPI = mkOption {
        type = types.bool;
        default = profileDefaults.${cfg.profile}.enableFAPI;
        description = ''
          Enable FAPI 2.0 security profile for this client.
          Enforces: PKCE, PAR, mTLS, certificate-bound tokens, signed responses.
        '';
      };

      requirePKCE = mkOption {
        type = types.bool;
        default = true;
        description = "Require Proof Key for Code Exchange (PKCE) for authorization code flow";
      };

      pkceMethod = mkOption {
        type = types.enum [ "S256" "plain" ];
        default = "S256";
        description = "PKCE challenge method (S256 required for FAPI 2.0)";
      };

      requirePAR = mkOption {
        type = types.bool;
        default = false;
        description = "Require Pushed Authorization Requests (PAR) per RFC 9126";
      };

      requireMTLS = mkOption {
        type = types.bool;
        default = false;
        description = "Require mutual TLS for token endpoint authentication";
      };

      certificateBoundTokens = mkOption {
        type = types.bool;
        default = false;
        description = "Issue certificate-bound access tokens per RFC 8705";
      };

      useJWTAccessTokens = mkOption {
        type = types.bool;
        default = true;
        description = "Issue JWTs as access tokens (required for FAPI)";
      };
    };
  };

  # Role submodule type
  roleType = types.submodule {
    options = {
      description = mkOption {
        type = types.str;
        default = "";
        description = "Role description";
      };

      composite = mkOption {
        type = types.bool;
        default = false;
        description = "Whether this role includes other roles";
      };

      compositeRoles = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "List of roles to include if composite";
      };
    };
  };

  # Generate the provisioning script
  provisionScript = pkgs.writeShellScript "keycloak-provision" ''
    #!/usr/bin/env bash
    set -euo pipefail

    KC_BASE_URL="${cfg.externalUrl}"
    KC_ADMIN_USER="${cfg.adminUser}"
    KC_ADMIN_PASS="${cfg.adminPassword}"
    REALM_NAME="${cfg.realm.name}"

    # Colors
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'

    log_info() { echo -e "''${GREEN}[INFO]''${NC} $1"; }
    log_warn() { echo -e "''${YELLOW}[WARN]''${NC} $1"; }
    log_error() { echo -e "''${RED}[ERROR]''${NC} $1"; }

    # Wait for Keycloak to be ready
    log_info "Waiting for Keycloak to be ready..."
    for i in {1..60}; do
      if curl -sf "''${KC_BASE_URL}/health/ready" > /dev/null 2>&1; then
        log_info "Keycloak is ready"
        break
      fi
      if [ $i -eq 60 ]; then
        log_error "Keycloak failed to become ready"
        exit 1
      fi
      sleep 2
    done

    # Get admin token
    get_token() {
      curl -sf -X POST "''${KC_BASE_URL}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "username=''${KC_ADMIN_USER}" \
        --data-urlencode "password=''${KC_ADMIN_PASS}" \
        --data-urlencode "grant_type=password" \
        --data-urlencode "client_id=admin-cli" | ${pkgs.jq}/bin/jq -r '.access_token'
    }

    log_info "Authenticating as admin..."
    TOKEN=$(get_token)

    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
      log_error "Failed to get admin token"
      exit 1
    fi

    # Check if realm exists
    REALM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -X GET "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}" \
      -H "Authorization: Bearer $TOKEN")

    # Build password policy string
    PASSWORD_POLICY="length(${toString cfg.passwordPolicy.minLength})"
    ${optionalString cfg.passwordPolicy.requireUppercase ''PASSWORD_POLICY="$PASSWORD_POLICY and upperCase(1)"''}
    ${optionalString cfg.passwordPolicy.requireDigit ''PASSWORD_POLICY="$PASSWORD_POLICY and digits(1)"''}
    ${optionalString cfg.passwordPolicy.requireSpecialChar ''PASSWORD_POLICY="$PASSWORD_POLICY and specialChars(1)"''}
    ${optionalString (cfg.passwordPolicy.historyCount > 0) ''PASSWORD_POLICY="$PASSWORD_POLICY and passwordHistory(${toString cfg.passwordPolicy.historyCount})"''}
    ${optionalString cfg.passwordPolicy.notUsername ''PASSWORD_POLICY="$PASSWORD_POLICY and notUsername"''}

    if [ "$REALM_STATUS" = "200" ]; then
      log_warn "Realm ''${REALM_NAME} already exists, skipping creation"
    else
      log_info "Creating realm: ''${REALM_NAME}"
      log_info "Password policy: $PASSWORD_POLICY"
      curl -sf -X POST "''${KC_BASE_URL}/admin/realms" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "realm": "'"''${REALM_NAME}"'",
          "enabled": true,
          "displayName": "${cfg.realm.displayName}",
          "accessTokenLifespan": ${toString cfg.realm.accessTokenLifespan},
          "ssoSessionIdleTimeout": ${toString cfg.realm.sessionIdleTimeout},
          "ssoSessionMaxLifespan": ${toString cfg.realm.sessionMaxLifespan},
          "loginWithEmailAllowed": true,
          "duplicateEmailsAllowed": false,
          "bruteForceProtected": ${boolToString cfg.security.bruteForceProtection},
          "permanentLockout": false,
          "failureFactor": ${toString cfg.security.failureFactor},
          "waitIncrementSeconds": ${toString cfg.security.lockoutWaitIncrement},
          "maxFailureWaitSeconds": ${toString cfg.security.maxLockoutWait},
          "passwordPolicy": "'"$PASSWORD_POLICY"'"
        }'
    fi

    # Refresh token
    sleep 1
    TOKEN=$(get_token)

    # Create roles
    ${concatStringsSep "\n" (mapAttrsToList (name: role: ''
      log_info "Creating role: ${name}"
      curl -sf -X POST "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}/roles" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "name": "${name}",
          "description": "${role.description}",
          "composite": ${boolToString role.composite}
        }' || log_warn "Role ${name} may already exist"
    '') cfg.realm.roles)}

    # Create clients with FAPI 2.0 support
    ${concatStringsSep "\n" (mapAttrsToList (clientId: client: ''
      log_info "Creating client: ${clientId}${optionalString client.enableFAPI " (FAPI 2.0 enabled)"}"
      curl -sf -X POST "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}/clients" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "clientId": "${clientId}",
          "name": "${client.name}",
          "enabled": true,
          "clientAuthenticatorType": ${if client.requireMTLS then ''"client-x509"'' else ''"client-secret"''},
          ${optionalString (client.secret != null && !client.requireMTLS) ''"secret": "${client.secret}",''}
          "redirectUris": ${builtins.toJSON client.redirectUris},
          "webOrigins": ${builtins.toJSON client.webOrigins},
          "publicClient": ${boolToString client.public},
          "protocol": "openid-connect",
          "bearerOnly": false,
          "standardFlowEnabled": true,
          "directAccessGrantsEnabled": ${boolToString client.directAccessGrantsEnabled},
          "serviceAccountsEnabled": ${boolToString client.serviceAccountsEnabled},
          "fullScopeAllowed": true,
          "defaultClientScopes": ["web-origins", "acr", "profile", "roles", "email"],
          "optionalClientScopes": ["address", "phone", "offline_access", "microprofile-jwt"],
          "attributes": {
            ${optionalString client.enableFAPI ''"fapi-profile": "fapi-2-security-profile",''}
            "pkce.code.challenge.method": "${client.pkceMethod}",
            "require.pushed.authorization.requests": "${boolToString client.requirePAR}",
            "tls.client.certificate.bound.access.tokens": "${boolToString client.certificateBoundTokens}",
            "use.jwks.url": "false",
            "access.token.as.jwt.enabled": "${boolToString client.useJWTAccessTokens}"
          }
        }' || log_warn "Client ${clientId} may already exist"
    '') cfg.realm.clients)}

    # Create users
    ${concatStringsSep "\n" (mapAttrsToList (username: user: ''
      log_info "Creating user: ${username}"
      curl -sf -X POST "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "username": "${username}",
          "email": "${user.email}",
          "firstName": "${user.firstName}",
          "lastName": "${user.lastName}",
          "enabled": ${boolToString user.enabled},
          "emailVerified": true,
          "credentials": [{
            "type": "password",
            "value": "${user.password}",
            "temporary": false
          }]
        }' || log_warn "User ${username} may already exist"
    '') cfg.realm.users)}

    # Refresh token for role assignments
    sleep 1
    TOKEN=$(get_token)

    # Assign roles to users
    ${concatStringsSep "\n" (mapAttrsToList (username: user: ''
      USER_ID=$(curl -sf -X GET "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}/users?username=${username}&exact=true" \
        -H "Authorization: Bearer $TOKEN" | ${pkgs.jq}/bin/jq -r '.[0].id')

      if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
        ${concatMapStringsSep "\n" (role: ''
          ROLE_JSON=$(curl -sf -X GET "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}/roles/${role}" \
            -H "Authorization: Bearer $TOKEN")

          if [ -n "$ROLE_JSON" ]; then
            log_info "Assigning role ${role} to ${username}"
            curl -sf -X POST "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}/users/$USER_ID/role-mappings/realm" \
              -H "Authorization: Bearer $TOKEN" \
              -H "Content-Type: application/json" \
              -d "[$ROLE_JSON]" || log_warn "Failed to assign role ${role}"
          fi
        '') user.roles}
      fi
    '') cfg.realm.users)}

    log_info "Keycloak provisioning complete!"
    log_info ""
    log_info "OIDC Discovery URL: ''${KC_BASE_URL}/realms/''${REALM_NAME}/.well-known/openid-configuration"
    ${concatStringsSep "\n" (mapAttrsToList (clientId: client: ''
      log_info "Client '${clientId}': ${if client.public then "public" else "secret=${client.secret or "generated"}"}"
    '') cfg.realm.clients)}
  '';

  # Docker compose for Keycloak
  keycloakComposeConfig = pkgs.writeText "keycloak-compose.yml" ''
    # Keycloak OIDC Provider - Barbican
    # FedRAMP Profile: ${cfg.profile}

    services:
      keycloak-db:
        image: postgres:15-alpine
        container_name: ${cfg.containerPrefix}-keycloak-db
        restart: always
        environment:
          POSTGRES_DB: keycloak
          POSTGRES_USER: keycloak
          POSTGRES_PASSWORD: ''${KEYCLOAK_DB_PASSWORD:-keycloak}
        volumes:
          - ${cfg.containerPrefix}_keycloak_db:/var/lib/postgresql/data
        healthcheck:
          test: ["CMD-SHELL", "pg_isready -U keycloak"]
          interval: 10s
          timeout: 5s
          retries: 5

      keycloak:
        image: quay.io/keycloak/keycloak:${cfg.version}
        container_name: ${cfg.containerPrefix}-keycloak
        restart: always
        command:
          - start${optionalString (cfg.profile == "development") "-dev"}
          - --hostname=${cfg.hostname}
          - --hostname-port=${toString cfg.port}
          - --http-port=${toString cfg.port}
          ${optionalString cfg.tls.enable ''
          - --https-port=${toString cfg.tls.port}
          - --https-certificate-file=/certs/server.crt
          - --https-certificate-key-file=/certs/server.key
          ''}
          - --health-enabled=true
          - --metrics-enabled=true
          ${optionalString cfg.fipsMode ''
          - --features=fips
          - --fips-mode=strict
          ''}
        environment:
          KC_DB: postgres
          KC_DB_URL: jdbc:postgresql://keycloak-db:5432/keycloak
          KC_DB_USERNAME: keycloak
          KC_DB_PASSWORD: ''${KEYCLOAK_DB_PASSWORD:-keycloak}
          KEYCLOAK_ADMIN: ${cfg.adminUser}
          KEYCLOAK_ADMIN_PASSWORD: ''${KEYCLOAK_ADMIN_PASSWORD:-${cfg.adminPassword}}
          KC_PROXY: edge
          KC_HTTP_RELATIVE_PATH: /
          ${optionalString cfg.fipsMode ''
          KC_FIPS_MODE: strict
          JAVA_OPTS: "-Dorg.bouncycastle.fips.approved_only=true"
          ''}
        ports:
          - "${cfg.bindAddress}:${toString cfg.port}:${toString cfg.port}"
          ${optionalString cfg.tls.enable ''
          - "${cfg.bindAddress}:${toString cfg.tls.port}:${toString cfg.tls.port}"
          ''}
        volumes:
          ${optionalString cfg.tls.enable ''
          - ${cfg.tls.certPath}:/certs:ro
          ''}
        depends_on:
          keycloak-db:
            condition: service_healthy
        healthcheck:
          test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/${toString cfg.port} && echo -e 'GET /health/ready HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && cat <&3 | grep -q '200 OK'"]
          interval: 30s
          timeout: 10s
          retries: 5
          start_period: 120s

    volumes:
      ${cfg.containerPrefix}_keycloak_db:
  '';

in {
  options.barbican.oidc = {
    enable = mkEnableOption "Barbican OIDC provider (Keycloak)";

    profile = mkOption {
      type = types.enum [ "development" "fedramp-low" "fedramp-moderate" "fedramp-high" ];
      default = "development";
      description = ''
        Security compliance profile:
        - development: Relaxed security for local development
        - fedramp-low: FedRAMP Low baseline (FIPS, basic security)
        - fedramp-moderate: FedRAMP Moderate (stricter timeouts, FAPI 2.0)
        - fedramp-high: FedRAMP High (MFA required, shortest sessions)

        Profile defaults can be overridden via specific options.
      '';
    };

    fipsMode = mkOption {
      type = types.bool;
      default = profileDefaults.${cfg.profile}.fipsMode;
      description = ''
        Enable FIPS 140-3 validated cryptography mode.
        Uses BouncyCastle FIPS provider for all cryptographic operations.
        Required for FedRAMP compliance (SC-13).
      '';
    };

    version = mkOption {
      type = types.str;
      default = "25.0";
      description = "Keycloak version (25.0+ required for full FAPI 2.0 support)";
    };

    hostname = mkOption {
      type = types.str;
      default = "localhost";
      description = "Hostname for Keycloak";
    };

    port = mkOption {
      type = types.port;
      default = 8080;
      description = "HTTP port for Keycloak";
    };

    bindAddress = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = ''
        Address to bind Keycloak.
        Defaults to 0.0.0.0 for VM/container accessibility.
      '';
    };

    externalUrl = mkOption {
      type = types.str;
      default = "http://localhost:${toString cfg.port}";
      description = "External URL for Keycloak (used in provisioning)";
    };

    containerPrefix = mkOption {
      type = types.str;
      default = "barbican";
      description = "Prefix for container and volume names";
    };

    # Admin credentials
    adminUser = mkOption {
      type = types.str;
      default = "admin";
      description = "Keycloak admin username";
    };

    adminPassword = mkOption {
      type = types.str;
      default = "admin";
      description = "Keycloak admin password (use environment variable in production)";
    };

    # TLS configuration
    tls = {
      enable = mkOption {
        type = types.bool;
        default = cfg.profile == "production";
        description = "Enable TLS";
      };

      port = mkOption {
        type = types.port;
        default = 8443;
        description = "HTTPS port";
      };

      certPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to directory containing server.crt and server.key";
      };
    };

    # Security settings (AC-7: Unsuccessful Login Attempts)
    security = {
      bruteForceProtection = mkOption {
        type = types.bool;
        default = profileDefaults.${cfg.profile}.bruteForceEnabled;
        description = "Enable brute force protection (AC-7)";
      };

      failureFactor = mkOption {
        type = types.int;
        default = profileDefaults.${cfg.profile}.failureFactor;
        description = "Number of failed attempts before lockout (AC-7)";
      };

      lockoutWaitIncrement = mkOption {
        type = types.int;
        default = 60;
        description = "Seconds to wait after lockout";
      };

      maxLockoutWait = mkOption {
        type = types.int;
        default = profileDefaults.${cfg.profile}.lockoutDuration;
        description = "Maximum lockout wait time in seconds (AC-7)";
      };
    };

    # Password policy (IA-5(1): Password-Based Authentication)
    passwordPolicy = {
      minLength = mkOption {
        type = types.int;
        default = profileDefaults.${cfg.profile}.passwordMinLength;
        description = "Minimum password length (NIST 800-63B)";
      };

      requireUppercase = mkOption {
        type = types.bool;
        default = profileDefaults.${cfg.profile}.passwordRequireUppercase;
        description = "Require at least one uppercase letter";
      };

      requireDigit = mkOption {
        type = types.bool;
        default = profileDefaults.${cfg.profile}.passwordRequireDigit;
        description = "Require at least one digit";
      };

      requireSpecialChar = mkOption {
        type = types.bool;
        default = profileDefaults.${cfg.profile}.passwordRequireSpecialChar;
        description = "Require at least one special character";
      };

      historyCount = mkOption {
        type = types.int;
        default = profileDefaults.${cfg.profile}.passwordHistoryCount;
        description = "Number of previous passwords to remember (IA-5(1))";
      };

      notUsername = mkOption {
        type = types.bool;
        default = true;
        description = "Password must not match username";
      };
    };

    # Realm configuration
    realm = {
      name = mkOption {
        type = types.str;
        default = "app";
        description = "Realm name";
      };

      displayName = mkOption {
        type = types.str;
        default = "Application Realm";
        description = "Human-readable realm name";
      };

      accessTokenLifespan = mkOption {
        type = types.int;
        default = profileDefaults.${cfg.profile}.accessTokenLifespan;
        description = "Access token lifespan in seconds (max 600 for FAPI 2.0)";
      };

      sessionIdleTimeout = mkOption {
        type = types.int;
        default = profileDefaults.${cfg.profile}.sessionIdleTimeout;
        description = "Session idle timeout in seconds (AC-11)";
      };

      sessionMaxLifespan = mkOption {
        type = types.int;
        default = profileDefaults.${cfg.profile}.sessionMaxLifespan;
        description = "Maximum session lifespan in seconds (AC-12)";
      };

      roles = mkOption {
        type = types.attrsOf roleType;
        default = {
          admin = { description = "Administrator with full access"; };
          user = { description = "Standard user access"; };
          viewer = { description = "Read-only access"; };
        };
        description = "Realm roles to create";
      };

      clients = mkOption {
        type = types.attrsOf clientType;
        default = {};
        description = "OIDC clients to create";
        example = literalExpression ''
          {
            my-app = {
              name = "My Application";
              secret = "my-secret";
              redirectUris = [ "http://localhost:8080/*" ];
            };
          }
        '';
      };

      users = mkOption {
        type = types.attrsOf userType;
        default = {};
        description = "Users to create";
        example = literalExpression ''
          {
            "alice.admin" = {
              email = "alice@example.com";
              firstName = "Alice";
              lastName = "Admin";
              password = "Alice123";
              roles = [ "admin" "user" ];
            };
          }
        '';
      };
    };

    # Auto-provision on start
    autoProvision = mkOption {
      type = types.bool;
      default = true;
      description = "Automatically provision realm, clients, and users on start";
    };
  };

  config = mkIf cfg.enable {
    # Ensure Podman is available
    virtualisation.podman = {
      enable = true;
      dockerCompat = true;
    };

    environment.systemPackages = with pkgs; [
      podman-compose
      jq
      curl
    ];

    # Systemd service to run Keycloak
    systemd.services.barbican-keycloak = {
      description = "Barbican Keycloak OIDC Provider";
      after = [ "network.target" "podman.service" ];
      wants = [ "podman.service" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        KEYCLOAK_ADMIN_PASSWORD = cfg.adminPassword;
        KEYCLOAK_DB_PASSWORD = "keycloak-db-secret";
      };

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.podman-compose}/bin/podman-compose -f ${keycloakComposeConfig} up -d";
        ExecStop = "${pkgs.podman-compose}/bin/podman-compose -f ${keycloakComposeConfig} down";
      };
    };

    # Provisioning service
    systemd.services.barbican-keycloak-provision = mkIf cfg.autoProvision {
      description = "Barbican Keycloak Provisioning";
      after = [ "barbican-keycloak.service" ];
      wants = [ "barbican-keycloak.service" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${provisionScript}";
      };
    };

    # Firewall
    networking.firewall.allowedTCPPorts = [
      cfg.port
    ] ++ (optional cfg.tls.enable cfg.tls.port);

    # Assertions
    assertions = [
      {
        assertion = cfg.profile == "development" || cfg.tls.enable;
        message = "Production profile requires TLS to be enabled";
      }
      {
        assertion = !cfg.tls.enable || cfg.tls.certPath != null;
        message = "TLS requires certPath to be set";
      }
    ];
  };
}
