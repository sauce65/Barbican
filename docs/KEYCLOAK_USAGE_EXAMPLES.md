# Keycloak OIDC Provider - Usage Examples

This document provides practical examples for deploying the Barbican Keycloak OIDC provider with FedRAMP Low/Moderate/High profiles and FAPI 2.0 security.

## Quick Start - Development Mode

For local development with relaxed security:

```nix
{
  barbican.oidc = {
    enable = true;
    profile = "development";  # No FIPS, relaxed passwords, long sessions
    hostname = "localhost";
    port = 8080;

    realm.clients.dev-app = {
      name = "Development App";
      public = true;  # No client secret needed
      redirectUris = [ "http://localhost:3000/*" ];
      webOrigins = [ "http://localhost:3000" ];
    };

    realm.users."dev-user" = {
      email = "dev@example.com";
      password = "dev123";  # Weak password OK in development
      roles = [ "user" ];
    };
  };
}
```

Access:
- **Keycloak Admin Console**: http://localhost:8080/admin (admin/admin)
- **OIDC Discovery**: http://localhost:8080/realms/app/.well-known/openid-configuration

---

## FedRAMP Low - Basic Compliance

FedRAMP Low baseline with FIPS cryptography:

```nix
{
  barbican.oidc = {
    enable = true;
    profile = "fedramp-low";  # FIPS mode, 8-char passwords, 30-min sessions
    hostname = "auth.example.com";
    port = 8443;

    adminPassword = "MySecureAdminPassword123!";  # Use secrets in production

    tls = {
      enable = true;
      certPath = "/var/lib/certs";  # Contains server.crt and server.key
    };

    realm = {
      name = "myorg";
      displayName = "My Organization";
    };

    realm.clients.web-app = {
      name = "Web Application";
      secret = "web-app-secret-value";
      redirectUris = [ "https://app.example.com/auth/callback" ];
      webOrigins = [ "https://app.example.com" ];

      # FAPI 2.0 disabled for Low profile (legacy OAuth2 OK)
      enableFAPI = false;
      requirePKCE = true;  # Still recommended
    };

    realm.users."alice.admin" = {
      email = "alice@example.com";
      firstName = "Alice";
      lastName = "Admin";
      password = "AlicePass123!";  # Min 8 chars with upper/digit/special
      roles = [ "admin" "user" ];
    };
  };
}
```

Profile defaults applied:
- **FIPS Mode**: Enabled (BouncyCastle FIPS)
- **Password Policy**: Min 8 chars, uppercase, digit, special char, 24 history
- **Session Timeouts**: 30 min idle, 8 hours max
- **Token Lifetime**: 10 minutes
- **Brute Force**: 5 attempts, 15 min lockout

---

## FedRAMP Moderate - Financial Apps

FedRAMP Moderate with FAPI 2.0 for financial-grade security:

```nix
{
  barbican.oidc = {
    enable = true;
    profile = "fedramp-moderate";  # FAPI 2.0, 12-char passwords, 15-min sessions
    hostname = "auth.financial.example.com";

    adminPassword = "VerySecureAdminPassword456!";

    tls = {
      enable = true;
      certPath = "/var/lib/vault-pki";  # Vault-managed certificates
    };

    realm = {
      name = "finapp";
      displayName = "Financial Application";
    };

    realm.clients.finapp-web = {
      name = "Financial Web App";
      secret = "finapp-web-secret";
      redirectUris = [ "https://banking.example.com/callback" ];
      webOrigins = [ "https://banking.example.com" ];

      # FAPI 2.0 enabled by profile default
      enableFAPI = true;
      requirePKCE = true;
      pkceMethod = "S256";  # SHA-256 required for FAPI
      requirePAR = true;    # Pushed Authorization Requests
      certificateBoundTokens = true;  # RFC 8705
      useJWTAccessTokens = true;
    };

    realm.clients.finapp-api = {
      name = "Financial API Service";
      public = false;
      serviceAccountsEnabled = true;

      # mTLS for confidential clients
      requireMTLS = true;
      certificateBoundTokens = true;

      enableFAPI = true;
    };

    # No users in production - use LDAP/SAML federation
  };
}
```

Profile defaults applied:
- **FIPS Mode**: Enabled
- **Password Policy**: Min 12 chars, uppercase, digit, special char, 24 history
- **Session Timeouts**: 15 min idle, 4 hours max
- **Token Lifetime**: 10 minutes (FAPI 2.0 max)
- **Brute Force**: 3 attempts, 30 min lockout
- **FAPI 2.0**: Enabled by default for clients

---

## FedRAMP High - Maximum Security

FedRAMP High with MFA required and shortest sessions:

```nix
{
  barbican.oidc = {
    enable = true;
    profile = "fedramp-high";  # MFA mandatory, 15-char passwords, 10-min sessions
    hostname = "auth.classified.example.com";

    adminPassword = "UltraSecureAdminPassword789!";

    tls = {
      enable = true;
      certPath = "/var/lib/vault-pki";
    };

    realm = {
      name = "highsec";
      displayName = "High Security Application";
    };

    realm.clients.highsec-web = {
      name = "High Security Web App";
      secret = "highsec-web-secret";
      redirectUris = [ "https://secure.example.com/callback" ];
      webOrigins = [ "https://secure.example.com" ];

      # FAPI 2.0 mandatory for High
      enableFAPI = true;
      requirePKCE = true;
      pkceMethod = "S256";
      requirePAR = true;
      requireMTLS = true;
      certificateBoundTokens = true;
      useJWTAccessTokens = true;
    };

    # MFA configuration (manual setup in Keycloak admin console)
    # FedRAMP High requires MFA for all users (IA-2(1))
  };
}
```

Profile defaults applied:
- **FIPS Mode**: Enabled
- **Password Policy**: Min 15 chars, uppercase, digit, special char, 24 history
- **Session Timeouts**: 10 min idle, 2 hours max
- **Token Lifetime**: 5 minutes (stricter than FAPI)
- **Brute Force**: 3 attempts, 30 min lockout
- **FAPI 2.0**: Enabled and mandatory
- **MFA**: Required for all users

**Important**: FedRAMP High requires MFA configuration. After realm creation:

1. Go to Admin Console → Realm Settings → Authentication
2. Create a new authentication flow with TOTP or WebAuthn
3. Bind the flow to Browser/Direct Grant
4. Set the flow as Required

---

## Custom Configuration - Override Profile Defaults

You can override any profile default:

```nix
{
  barbican.oidc = {
    enable = true;
    profile = "fedramp-moderate";  # Start with Moderate baseline

    # Override specific settings
    realm.accessTokenLifespan = 300;  # Shorten to 5 minutes
    realm.sessionIdleTimeout = 600;   # Shorten to 10 minutes

    passwordPolicy = {
      minLength = 16;  # Increase from 12 to 16
      historyCount = 36;  # Remember more passwords
    };

    security = {
      failureFactor = 2;  # Stricter: lock after 2 attempts
      maxLockoutWait = 3600;  # Lock for 1 hour instead of 30 min
    };

    realm.clients.custom-app = {
      name = "Custom App";
      secret = "custom-secret";
      redirectUris = [ "https://app.example.com/callback" ];

      # Override FAPI settings
      enableFAPI = true;
      requirePAR = false;  # Disable PAR for this client
      requireMTLS = true;  # But keep mTLS
    };
  };
}
```

---

## Multiple Realms and Clients

Support multiple applications with separate realms:

```nix
{
  barbican.oidc = {
    enable = true;
    profile = "fedramp-moderate";
    hostname = "auth.example.com";

    # Default realm (still required)
    realm = {
      name = "default";
      displayName = "Default Realm";
    };

    # TODO: Multi-realm support requires extending the module
    # Currently, only one realm is supported per Keycloak instance
    # For multiple apps, create separate clients in the same realm:

    realm.clients = {
      app1-web = {
        name = "Application 1 - Web";
        secret = "app1-secret";
        redirectUris = [ "https://app1.example.com/callback" ];
        enableFAPI = true;
      };

      app1-api = {
        name = "Application 1 - API";
        serviceAccountsEnabled = true;
        requireMTLS = true;
        enableFAPI = true;
      };

      app2-web = {
        name = "Application 2 - Web";
        secret = "app2-secret";
        redirectUris = [ "https://app2.example.com/callback" ];
        enableFAPI = true;
      };
    };
  };
}
```

**Note**: For true multi-tenancy with separate realms, deploy multiple Keycloak instances or use Keycloak's realm management API post-deployment.

---

## Integration with Barbican Modules

### With Secure PostgreSQL

Replace embedded PostgreSQL with Barbican's secure-postgres:

```nix
{
  # Use Barbican's hardened PostgreSQL
  barbican.securePostgres = {
    enable = true;
    database = "keycloak";
    username = "keycloak";
    passwordFile = "/var/lib/secrets/keycloak-db-password";
    enableSSL = true;
    enableClientCert = true;  # mTLS to database
  };

  # TODO: Module needs enhancement to support external PostgreSQL
  # Currently uses embedded PostgreSQL container
  # Future: Add options for external database connection

  barbican.oidc = {
    enable = true;
    profile = "fedramp-high";
    hostname = "auth.example.com";

    # TODO: Add these options:
    # database = {
    #   useExternal = true;
    #   host = "localhost";
    #   port = 5432;
    #   name = "keycloak";
    #   username = "keycloak";
    #   passwordFile = "/var/lib/secrets/keycloak-db-password";
    #   sslMode = "verify-full";
    #   clientCertFile = "/var/lib/vault-pki/keycloak-db-client.pem";
    # };
  };
}
```

### With Vault PKI

Auto-renew certificates from Vault:

```nix
{
  # Vault PKI for automatic certificate management
  barbican.vaultPki = {
    enable = true;
    vaultAddr = "https://vault.example.com";

    certificates.keycloak = {
      commonName = "auth.example.com";
      altNames = [ "keycloak.internal" ];
      ttl = "720h";  # 30 days
    };
  };

  barbican.oidc = {
    enable = true;
    profile = "fedramp-high";
    hostname = "auth.example.com";

    tls = {
      enable = true;
      certPath = config.barbican.vaultPki.certificates.keycloak.certDir;
    };
  };
}
```

### With Observability

Send Keycloak events to Loki:

```nix
{
  # Observability stack
  barbican.observability = {
    enable = true;
    loki.enable = true;
    prometheus.enable = true;
  };

  barbican.oidc = {
    enable = true;
    profile = "fedramp-high";

    # TODO: Add observability integration options
    # observability = {
    #   enable = true;
    #   lokiEndpoint = "http://localhost:3100";
    #   prometheusEndpoint = "http://localhost:9090";
    #   auditEvents = [
    #     "LOGIN" "LOGIN_ERROR" "LOGOUT"
    #     "UPDATE_PASSWORD" "UPDATE_PROFILE"
    #     "FEDERATED_IDENTITY_LINK"
    #   ];
    # };
  };
}
```

---

## OAuth2 Client Configuration

### For Rust/Axum Apps

Use Barbican's auth library with generated config:

```rust
use barbican::auth::{JwtValidator, JwtValidatorConfig};

#[tokio::main]
async fn main() {
    let validator_config = JwtValidatorConfig {
        issuer_url: "https://auth.example.com/realms/myorg".to_string(),
        client_id: "web-app".to_string(),
        jwks_uri: "https://auth.example.com/realms/myorg/protocol/openid-connect/certs".to_string(),
        algorithms: vec!["RS256".to_string()],
    };

    let validator = JwtValidator::new(validator_config).await.unwrap();

    // Use in Axum router
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(Extension(validator));

    // ...
}

async fn protected_handler(
    Extension(validator): Extension<JwtValidator>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<String, StatusCode> {
    let claims = validator.validate(auth.token())
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(format!("Hello, {}!", claims.sub))
}
```

### Authorization Code Flow (FAPI 2.0)

Example OAuth2 flow with PKCE and PAR:

```rust
use oauth2::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;

async fn initiate_login() -> (String, PkceCodeVerifier, CsrfToken) {
    let client = BasicClient::new(
        ClientId::new("web-app".to_string()),
        Some(ClientSecret::new("web-app-secret".to_string())),
        AuthUrl::new("https://auth.example.com/realms/myorg/protocol/openid-connect/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://auth.example.com/realms/myorg/protocol/openid-connect/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new("https://app.example.com/callback".to_string()).unwrap());

    // Generate PKCE challenge (required for FAPI 2.0)
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // TODO: Implement PAR (Pushed Authorization Request)
    // For now, using standard authorization endpoint

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    (auth_url.to_string(), pkce_verifier, csrf_token)
}

async fn handle_callback(
    code: AuthorizationCode,
    pkce_verifier: PkceCodeVerifier,
) -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let client = /* same as above */;

    let token_result = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    Ok(token_result)
}
```

---

## Troubleshooting

### Check Keycloak Health

```bash
curl -f https://auth.example.com/health/ready
```

### View Keycloak Logs

```bash
podman logs barbican-keycloak
```

### Test OIDC Discovery

```bash
curl https://auth.example.com/realms/myorg/.well-known/openid-configuration | jq
```

### Verify FIPS Mode

Check Keycloak logs for:
```
FIPS mode: STRICT
BouncyCastle FIPS provider initialized
```

### Verify FAPI 2.0 Client Configuration

```bash
# Get admin token
TOKEN=$(curl -X POST "https://auth.example.com/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
  | jq -r '.access_token')

# Get client configuration
curl -X GET "https://auth.example.com/admin/realms/myorg/clients" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.[] | select(.clientId=="web-app") | .attributes'
```

Look for:
- `fapi-profile: fapi-2-security-profile`
- `pkce.code.challenge.method: S256`
- `require.pushed.authorization.requests: true`
- `tls.client.certificate.bound.access.tokens: true`

---

## Next Steps

1. **Configure MFA**: For FedRAMP Moderate/High, set up TOTP or WebAuthn
2. **User Federation**: Integrate with LDAP/Active Directory
3. **Custom Themes**: Brand the login pages
4. **Event Logging**: Forward Keycloak events to Loki for audit trails
5. **Backup**: Configure automated realm exports and database backups
6. **Monitoring**: Set up Prometheus alerts for failed logins, token errors

---

## Limitations and Future Enhancements

### Current Limitations

1. **Single Realm**: Only one realm supported per configuration (use multiple clients)
2. **Embedded Database**: Uses Podman PostgreSQL container (not Barbican's secure-postgres)
3. **No Federation**: LDAP/SAML federation requires manual configuration in admin console
4. **Manual MFA Setup**: MFA policies must be configured via admin console
5. **No PAR Implementation**: PAR (Pushed Authorization Requests) configured but requires client implementation

### Planned Enhancements

- [ ] Support for multiple realms in single deployment
- [ ] Integration with Barbican's secure-postgres module
- [ ] LDAP federation configuration via NixOS options
- [ ] Automated MFA policy setup per profile
- [ ] Event forwarding to Barbican observability stack
- [ ] CLI tool for realm/client generation from `barbican.toml`
- [ ] NixOS VM tests for FAPI 2.0 compliance
- [ ] Kubernetes/Nomad deployment options

---

For more details, see:
- [Keycloak Deployment Design](./KEYCLOAK_DEPLOYMENT_DESIGN.md)
- [Barbican Architecture](../CLAUDE.md)
- [NIST Control Research](../NIST_800_53_CONTROL_RESEARCH.md)
