# Barbican Keycloak Realm JSON Generator
#
# Generates Keycloak realm export JSON from declarative Nix configuration.
# The generated JSON can be imported on Keycloak startup for immutable
# infrastructure deployments.
#
# Workflow:
#   1. App defines realm config in Nix (realms, clients, roles, users)
#   2. This library generates realm export JSON
#   3. JSON is baked into VM image
#   4. Keycloak imports on first boot
#   5. Secrets (client creds, passwords) injected from Vault at runtime
#
{ lib }:

with lib;

rec {
  # ===========================================================================
  # Realm JSON Generation
  # ===========================================================================

  # Generate complete realm export JSON
  mkRealmJson = {
    name,
    displayName ? name,
    enabled ? true,
    profile ? "fedramp-moderate",

    # Token settings
    accessTokenLifespan ? 300,
    refreshTokenLifespan ? 1800,
    ssoSessionIdleTimeout ? 1800,
    ssoSessionMaxLifespan ? 36000,

    # Security settings (FedRAMP)
    bruteForceProtected ? true,
    failureFactor ? 5,
    waitIncrementSeconds ? 60,
    maxFailureWaitSeconds ? 900,
    permanentLockout ? false,

    # MTLS settings
    mtlsEnabled ? (profile == "fedramp-moderate" || profile == "fedramp-high"),

    # Components
    roles ? {},
    clients ? {},
    users ? {},
    clientScopes ? {},
    identityProviders ? [],

    # Client policies (FAPI 2.0)
    clientPolicies ? null,
  }:
    let
      fapiLib = import ./keycloak-fapi.nix { inherit lib; };
      fapiProfile = fapiLib.profileForFedRAMP profile;

      defaultClientPolicies = fapiLib.mkRealmPolicies {
        profile = fapiProfile;
      };
    in {
      realm = name;
      inherit displayName enabled;

      # Token configuration
      inherit accessTokenLifespan ssoSessionIdleTimeout ssoSessionMaxLifespan;
      accessTokenLifespanForImplicitFlow = accessTokenLifespan;
      offlineSessionIdleTimeout = refreshTokenLifespan;

      # Security (AC-7: Unsuccessful Logon Attempts)
      inherit bruteForceProtected failureFactor waitIncrementSeconds
              maxFailureWaitSeconds permanentLockout;

      # Login settings
      loginWithEmailAllowed = true;
      duplicateEmailsAllowed = false;
      registrationAllowed = false;
      registrationEmailAsUsername = false;
      verifyEmail = true;
      resetPasswordAllowed = true;

      # Password policy (IA-5: Authenticator Management)
      passwordPolicy = concatStringsSep " and " [
        "length(12)"
        "digits(1)"
        "upperCase(1)"
        "lowerCase(1)"
        "specialChars(1)"
        "notUsername"
        "passwordHistory(5)"
      ];

      # OTP Policy (IA-2(1): MFA)
      otpPolicyType = "totp";
      otpPolicyAlgorithm = "HmacSHA256";
      otpPolicyDigits = 6;
      otpPolicyPeriod = 30;

      # MTLS configuration
      attributes = optionalAttrs mtlsEnabled {
        "client-x509.enable" = "true";
        "client-x509.check-enabled" = "true";
      };

      # Roles
      roles = {
        realm = mapAttrsToList (roleName: roleCfg: {
          name = roleName;
          description = roleCfg.description or "";
          composite = roleCfg.composite or false;
          composites = optionalAttrs (roleCfg.composite or false) {
            realm = roleCfg.compositeRoles or [];
          };
        }) roles;
      };

      # Default roles
      defaultRoles = [ "offline_access" "uma_authorization" ];

      # Clients
      clients = mapAttrsToList (clientId: clientCfg:
        mkClientJson {
          inherit clientId profile;
          inherit (clientCfg) name;
          secret = clientCfg.secret or null;
          secretFromVault = clientCfg.secretFromVault or null;
          redirectUris = clientCfg.redirectUris or [];
          webOrigins = clientCfg.webOrigins or [];
          publicClient = clientCfg.public or false;
          directAccessGrantsEnabled = clientCfg.directAccessGrantsEnabled or false;
          serviceAccountsEnabled = clientCfg.serviceAccountsEnabled or false;
          mtlsEnabled = clientCfg.mtls or mtlsEnabled;
          fapiCompliant = clientCfg.fapi or (profile != "development");
          clientAuthMethod = clientCfg.clientAuthMethod or (
            if (clientCfg.mtls or mtlsEnabled) then "client-x509"
            else if (clientCfg.public or false) then "none"
            else "client-secret"
          );
        }
      ) clients;

      # Users (only for development/test - production uses external IdP or manual)
      users = mapAttrsToList (username: userCfg: {
        inherit username;
        email = userCfg.email or "${username}@${name}.local";
        firstName = userCfg.firstName or username;
        lastName = userCfg.lastName or "";
        enabled = userCfg.enabled or true;
        emailVerified = true;
        credentials = if userCfg ? password then [{
          type = "password";
          value = userCfg.password;
          temporary = false;
        }] else if userCfg ? passwordFromVault then [{
          type = "password";
          # Placeholder - will be replaced at boot from Vault
          value = "VAULT:${userCfg.passwordFromVault}";
          temporary = false;
        }] else [];
        realmRoles = userCfg.roles or [ "user" ];
      }) users;

      # Client scopes
      clientScopes = (mapAttrsToList (scopeName: scopeCfg: {
        name = scopeName;
        description = scopeCfg.description or "";
        protocol = "openid-connect";
        attributes = {
          "include.in.token.scope" = "true";
          "display.on.consent.screen" = "true";
        };
        protocolMappers = scopeCfg.mappers or [];
      }) clientScopes) ++ defaultClientScopes;

      # Client policies (FAPI 2.0)
      clientPolicies = if clientPolicies != null then clientPolicies else defaultClientPolicies;

      # Events configuration (AU-2, AU-3: Audit Logging)
      eventsEnabled = true;
      eventsExpiration = 2592000;  # 30 days
      eventsListeners = [ "jboss-logging" ];
      enabledEventTypes = fapiLib.fapi2AuditEvents;
      adminEventsEnabled = true;
      adminEventsDetailsEnabled = true;

      # Identity providers
      inherit identityProviders;

      # Internationalization
      internationalizationEnabled = true;
      supportedLocales = [ "en" ];
      defaultLocale = "en";
    };

  # ===========================================================================
  # Client JSON Generation
  # ===========================================================================

  mkClientJson = {
    clientId,
    name ? clientId,
    profile ? "fedramp-moderate",
    secret ? null,
    secretFromVault ? null,
    redirectUris ? [],
    webOrigins ? [],
    publicClient ? false,
    directAccessGrantsEnabled ? false,
    serviceAccountsEnabled ? false,
    mtlsEnabled ? false,
    fapiCompliant ? true,
    clientAuthMethod ? (
      if mtlsEnabled then "client-x509"
      else if publicClient then "none"
      else "client-secret"
    ),
  }: {
    inherit clientId name;
    enabled = true;
    protocol = "openid-connect";

    # Client type
    publicClient = publicClient;
    bearerOnly = false;
    consentRequired = false;

    # Authentication - support private-key-jwt via client-secret-jwt authenticator
    clientAuthenticatorType =
      if clientAuthMethod == "private-key-jwt" then "client-secret-jwt"
      else clientAuthMethod;

    # Secret (will be replaced from Vault if secretFromVault is set)
    secret =
      if secret != null then secret
      else if secretFromVault != null then "VAULT:${secretFromVault}"
      else null;

    # URIs
    redirectUris = if redirectUris == [] then [ "/*" ] else redirectUris;
    webOrigins = if webOrigins == [] then [ "+" ] else webOrigins;

    # Flows
    standardFlowEnabled = true;
    implicitFlowEnabled = false;  # Disabled for FAPI 2.0
    directAccessGrantsEnabled = directAccessGrantsEnabled;
    serviceAccountsEnabled = serviceAccountsEnabled;

    # Authorization
    authorizationServicesEnabled = false;
    fullScopeAllowed = !fapiCompliant;  # FAPI requires explicit scopes

    # FAPI 2.0 settings
    attributes = {
      # PKCE
      "pkce.code.challenge.method" = if fapiCompliant then "S256" else "";

      # PAR
      "require.pushed.authorization.requests" = if fapiCompliant then "true" else "false";

      # Request object
      "request.object.required" = if fapiCompliant then "request or request_uri" else "not required";
      "request.object.signature.alg" = if fapiCompliant then "PS256" else "";

      # Token binding
      "tls.client.certificate.bound.access.tokens" = if mtlsEnabled then "true" else "false";

      # Token settings
      "access.token.signed.response.alg" = "PS256";
      "id.token.signed.response.alg" = "PS256";
      "access.token.lifespan" = "300";

      # Client certificate (for MTLS)
    } // optionalAttrs mtlsEnabled {
      "x509.subjectdn" = "";  # Will be configured per-client
      "x509.allow.regex.pattern.comparison" = "false";
    } // optionalAttrs (clientAuthMethod == "private-key-jwt") {
      "token.endpoint.auth.signing.alg" = "PS256";
    };

    # Default scopes
    defaultClientScopes = [
      "web-origins"
      "acr"
      "profile"
      "roles"
      "email"
    ];

    optionalClientScopes = [
      "address"
      "phone"
      "offline_access"
      "microprofile-jwt"
    ];
  };

  # ===========================================================================
  # Default Client Scopes
  # ===========================================================================

  defaultClientScopes = [
    {
      name = "web-origins";
      description = "OpenID Connect scope for add allowed web origins to the access token";
      protocol = "openid-connect";
      attributes = {
        "include.in.token.scope" = "false";
        "display.on.consent.screen" = "false";
      };
      protocolMappers = [{
        name = "allowed web origins";
        protocol = "openid-connect";
        protocolMapper = "oidc-allowed-origins-mapper";
        consentRequired = false;
      }];
    }
    {
      name = "roles";
      description = "OpenID Connect scope for add user roles to the access token";
      protocol = "openid-connect";
      attributes = {
        "include.in.token.scope" = "false";
        "display.on.consent.screen" = "true";
        "consent.screen.text" = "\${rolesScopeConsentText}";
      };
      protocolMappers = [
        {
          name = "realm roles";
          protocol = "openid-connect";
          protocolMapper = "oidc-usermodel-realm-role-mapper";
          consentRequired = false;
          config = {
            "multivalued" = "true";
            "user.attribute" = "roles";
            "id.token.claim" = "true";
            "access.token.claim" = "true";
            "claim.name" = "realm_access.roles";
            "jsonType.label" = "String";
          };
        }
        {
          name = "client roles";
          protocol = "openid-connect";
          protocolMapper = "oidc-usermodel-client-role-mapper";
          consentRequired = false;
          config = {
            "multivalued" = "true";
            "id.token.claim" = "true";
            "access.token.claim" = "true";
            "claim.name" = "resource_access.\${client_id}.roles";
            "jsonType.label" = "String";
          };
        }
        {
          name = "audience resolve";
          protocol = "openid-connect";
          protocolMapper = "oidc-audience-resolve-mapper";
          consentRequired = false;
        }
      ];
    }
    {
      name = "email";
      description = "OpenID Connect built-in scope: email";
      protocol = "openid-connect";
      attributes = {
        "include.in.token.scope" = "true";
        "display.on.consent.screen" = "true";
        "consent.screen.text" = "\${emailScopeConsentText}";
      };
      protocolMappers = [
        {
          name = "email";
          protocol = "openid-connect";
          protocolMapper = "oidc-usermodel-attribute-mapper";
          consentRequired = false;
          config = {
            "user.attribute" = "email";
            "id.token.claim" = "true";
            "access.token.claim" = "true";
            "claim.name" = "email";
            "jsonType.label" = "String";
          };
        }
        {
          name = "email verified";
          protocol = "openid-connect";
          protocolMapper = "oidc-usermodel-attribute-mapper";
          consentRequired = false;
          config = {
            "user.attribute" = "emailVerified";
            "id.token.claim" = "true";
            "access.token.claim" = "true";
            "claim.name" = "email_verified";
            "jsonType.label" = "boolean";
          };
        }
      ];
    }
    {
      name = "profile";
      description = "OpenID Connect built-in scope: profile";
      protocol = "openid-connect";
      attributes = {
        "include.in.token.scope" = "true";
        "display.on.consent.screen" = "true";
        "consent.screen.text" = "\${profileScopeConsentText}";
      };
      protocolMappers = [
        {
          name = "family name";
          protocol = "openid-connect";
          protocolMapper = "oidc-usermodel-attribute-mapper";
          consentRequired = false;
          config = {
            "user.attribute" = "lastName";
            "id.token.claim" = "true";
            "access.token.claim" = "true";
            "claim.name" = "family_name";
            "jsonType.label" = "String";
          };
        }
        {
          name = "given name";
          protocol = "openid-connect";
          protocolMapper = "oidc-usermodel-attribute-mapper";
          consentRequired = false;
          config = {
            "user.attribute" = "firstName";
            "id.token.claim" = "true";
            "access.token.claim" = "true";
            "claim.name" = "given_name";
            "jsonType.label" = "String";
          };
        }
        {
          name = "username";
          protocol = "openid-connect";
          protocolMapper = "oidc-usermodel-attribute-mapper";
          consentRequired = false;
          config = {
            "user.attribute" = "username";
            "id.token.claim" = "true";
            "access.token.claim" = "true";
            "claim.name" = "preferred_username";
            "jsonType.label" = "String";
          };
        }
      ];
    }
  ];

  # ===========================================================================
  # Vault Secret Injection
  # ===========================================================================

  # Generate a script to replace VAULT: placeholders with actual secrets
  mkVaultInjectionScript = { realmJsonPath, vaultAddr, vaultToken ? null }: ''
    #!/usr/bin/env bash
    set -euo pipefail

    REALM_JSON="${realmJsonPath}"
    VAULT_ADDR="${vaultAddr}"
    VAULT_TOKEN="''${VAULT_TOKEN:-${if vaultToken != null then vaultToken else ""}}"

    if [ -z "$VAULT_TOKEN" ]; then
      echo "ERROR: VAULT_TOKEN not set"
      exit 1
    fi

    # Find all VAULT: placeholders and replace with actual secrets
    while IFS= read -r line; do
      if [[ "$line" =~ VAULT:([a-zA-Z0-9/_-]+) ]]; then
        secret_path="''${BASH_REMATCH[1]}"
        echo "Fetching secret: $secret_path"
        secret_value=$(curl -sf -H "X-Vault-Token: $VAULT_TOKEN" \
          "$VAULT_ADDR/v1/$secret_path" | jq -r '.data.data.value // .data.value')
        if [ -n "$secret_value" ] && [ "$secret_value" != "null" ]; then
          sed -i "s|VAULT:$secret_path|$secret_value|g" "$REALM_JSON"
        else
          echo "WARNING: Could not fetch secret $secret_path"
        fi
      fi
    done < <(grep -o 'VAULT:[a-zA-Z0-9/_-]*' "$REALM_JSON" | sort -u)

    echo "Vault secret injection complete"
  '';

  # ===========================================================================
  # Realm Import Configuration
  # ===========================================================================

  # Generate Keycloak startup arguments for realm import
  mkRealmImportArgs = { realmJsonPath, overwrite ? false }: [
    "--import-realm"
  ];

  # Environment variables for realm import
  mkRealmImportEnv = { realmJsonPath }: {
    KC_IMPORT_REALM = realmJsonPath;
  };
}
