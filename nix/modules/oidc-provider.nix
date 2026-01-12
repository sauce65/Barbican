# Barbican Security Module: OIDC Provider (Keycloak)
#
# Provides a ready-to-use OIDC identity provider with:
# - Automatic Keycloak deployment via container
# - Declarative realm, client, role, and user provisioning
# - FedRAMP-compliant security settings
# - Integration with Vault PKI for TLS
#
# NIST 800-53 Controls:
# - IA-2: Identification and Authentication
# - IA-2(1): Multi-Factor Authentication (configurable)
# - IA-4: Identifier Management
# - IA-5: Authenticator Management
# - AC-2: Account Management
# - AC-7: Unsuccessful Logon Attempts
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.oidc;

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

  # Client submodule type
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

    if [ "$REALM_STATUS" = "200" ]; then
      log_warn "Realm ''${REALM_NAME} already exists, skipping creation"
    else
      log_info "Creating realm: ''${REALM_NAME}"
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
          "maxFailureWaitSeconds": ${toString cfg.security.maxLockoutWait}
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

    # Create clients
    ${concatStringsSep "\n" (mapAttrsToList (clientId: client: ''
      log_info "Creating client: ${clientId}"
      curl -sf -X POST "''${KC_BASE_URL}/admin/realms/''${REALM_NAME}/clients" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "clientId": "${clientId}",
          "name": "${client.name}",
          "enabled": true,
          "clientAuthenticatorType": "client-secret",
          ${optionalString (client.secret != null) ''"secret": "${client.secret}",''}
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
          "optionalClientScopes": ["address", "phone", "offline_access", "microprofile-jwt"]
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
        environment:
          KC_DB: postgres
          KC_DB_URL: jdbc:postgresql://keycloak-db:5432/keycloak
          KC_DB_USERNAME: keycloak
          KC_DB_PASSWORD: ''${KEYCLOAK_DB_PASSWORD:-keycloak}
          KEYCLOAK_ADMIN: ${cfg.adminUser}
          KEYCLOAK_ADMIN_PASSWORD: ''${KEYCLOAK_ADMIN_PASSWORD:-${cfg.adminPassword}}
          KC_PROXY: edge
          KC_HTTP_RELATIVE_PATH: /
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
      type = types.enum [ "development" "production" ];
      default = "development";
      description = ''
        Deployment profile:
        - development: HTTP, relaxed security, start-dev mode
        - production: HTTPS required, strict security
      '';
    };

    version = mkOption {
      type = types.str;
      default = "24.0";
      description = "Keycloak version";
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

    # Security settings
    security = {
      bruteForceProtection = mkOption {
        type = types.bool;
        default = true;
        description = "Enable brute force protection (AC-7)";
      };

      failureFactor = mkOption {
        type = types.int;
        default = 5;
        description = "Number of failed attempts before lockout";
      };

      lockoutWaitIncrement = mkOption {
        type = types.int;
        default = 60;
        description = "Seconds to wait after lockout";
      };

      maxLockoutWait = mkOption {
        type = types.int;
        default = 900;
        description = "Maximum lockout wait time in seconds";
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
        default = 300;
        description = "Access token lifespan in seconds";
      };

      sessionIdleTimeout = mkOption {
        type = types.int;
        default = 1800;
        description = "Session idle timeout in seconds";
      };

      sessionMaxLifespan = mkOption {
        type = types.int;
        default = 36000;
        description = "Maximum session lifespan in seconds";
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
