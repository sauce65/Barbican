# Keycloak Deployment Design - FIPS/NIST/FAPI 2.0 Compliant

## Executive Summary

This document outlines the design for a turnkey, compliance-ready Keycloak deployment system within Barbican. The goal is to provide application developers with a secure-by-default identity provider that meets:

- **FIPS 140-3** cryptographic requirements
- **NIST SP 800-53 Rev 5** security controls (FedRAMP Low/Moderate/High)
- **FAPI 2.0** (Financial-grade API) security profile
- Zero-trust architecture principles

The system will be delivered as:
1. A NixOS module (`barbican.keycloak`) for infrastructure deployment
2. Pre-configured realms and clients for common use cases
3. Integration with Barbican's observability, secrets management, and audit logging
4. CLI support in `barbican-cli` for realm/client configuration generation

### Key Design Principles

- **Secure by Default**: All security features enabled out of the box
- **Profile-Driven**: FedRAMP Low/Moderate/High presets via `barbican.toml`
- **Declarative Configuration**: GitOps-friendly, reproducible deployments
- **Zero-Trust Ready**: mTLS, certificate-bound tokens, PAR support
- **Developer-Friendly**: One-command deployment, auto-generated client configs

---

## 1. Security Requirements

### 1.1 FIPS 140-3 Cryptography

**Requirement**: All cryptographic operations must use FIPS-validated modules.

**Implementation**:
- Use **Keycloak with BouncyCastle FIPS** provider
- Alternatively, use Keycloak with **AWS-LC FIPS** via custom JVM configuration
- Disable non-FIPS cipher suites (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 only)
- Use FIPS-validated PostgreSQL with `ssl_ciphers` restricted to FIPS algorithms

**Nix Integration**:
```nix
services.keycloak = {
  fipsMode = true;  # New option we'll add
  security.provider = "bouncycastle-fips";  # or "aws-lc-fips"
};
```

### 1.2 NIST 800-53 Rev 5 Controls

Controls directly addressed by Keycloak deployment:

| Control | Implementation |
|---------|----------------|
| **AC-2** Account Management | Keycloak user lifecycle, automated provisioning via SCIM |
| **AC-3** Access Enforcement | Role-based access control (RBAC), OAuth2 scopes |
| **AC-7** Unsuccessful Login Attempts | Brute force detection (3 attempts, 30 min lockout) |
| **AC-11** Session Lock | Idle timeout enforcement via token lifetime |
| **AC-12** Session Termination | Configurable session timeouts, revocation |
| **AU-2/3** Audit Events | Keycloak event logging → Loki via syslog |
| **IA-2** Identification & Authentication | Multi-factor authentication (TOTP, WebAuthn) |
| **IA-2(1)** MFA for Privileged Accounts | Conditional MFA policies for admin realm |
| **IA-2(2)** MFA for Non-Privileged Accounts | FedRAMP High requires MFA for all users |
| **IA-5** Authenticator Management | Password policy enforcement (NIST 800-63B) |
| **IA-5(1)** Password-Based Authentication | Argon2id hashing, 15-char minimum for FedRAMP High |
| **IA-8** Identification & Authentication (Non-Org Users) | Federation via SAML/OIDC |
| **SC-8** Transmission Confidentiality | TLS 1.3 required, certificate-bound access tokens |
| **SC-13** Cryptographic Protection | FIPS-validated algorithms only |
| **SC-23** Session Authenticity | Signed JWTs, token binding |

### 1.3 FAPI 2.0 Security Profile

**Requirements** (from OpenID FAPI 2.0 spec):

1. **Mutual TLS (mTLS) for client authentication**
   - Certificate-bound access tokens (RFC 8705)
   - Client certificate validation

2. **Pushed Authorization Requests (PAR)**
   - Clients must push authorization parameters to a backchannel endpoint
   - Prevents authorization request tampering

3. **JWT Secured Authorization Response Mode (JARM)**
   - Authorization responses must be signed JWTs
   - Protects against response injection attacks

4. **Proof Key for Code Exchange (PKCE)**
   - Required for all authorization code flows
   - SHA-256 challenge method mandatory

5. **Restricted Scopes and Claims**
   - OpenID Connect scope required
   - Signed and encrypted ID tokens

6. **Short-lived Access Tokens**
   - Max 10-minute lifetime for access tokens
   - Refresh tokens with rotation

**Keycloak FAPI 2.0 Configuration**:
- Enable FAPI 2.0 client profile (built into Keycloak 25+)
- Configure PAR endpoint
- Enable MTLS client authentication
- Set token lifetimes per FAPI requirements
- Disable weak cipher suites

---

## 2. Architecture Overview

### 2.1 Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application Stack                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐         ┌──────────────┐                      │
│  │  User App    │◄───────►│  Barbican    │                      │
│  │  (Axum)      │  OAuth  │  Auth Lib    │                      │
│  └──────┬───────┘         └──────┬───────┘                      │
│         │                         │                              │
│         │     JWT Validation      │                              │
│         └─────────────────────────┘                              │
│                   │                                               │
│                   │ OIDC/OAuth2                                  │
│                   ▼                                               │
│  ┌─────────────────────────────────────────────┐                │
│  │         Keycloak Identity Provider          │                │
│  ├─────────────────────────────────────────────┤                │
│  │  • FAPI 2.0 Security Profile                │                │
│  │  • mTLS Client Authentication                │                │
│  │  • Pushed Authorization Requests (PAR)      │                │
│  │  • Certificate-Bound Tokens (RFC 8705)      │                │
│  │  • MFA (TOTP, WebAuthn, SMS)                │                │
│  │  • Brute Force Protection                   │                │
│  │  • Session Management                        │                │
│  └──────┬──────────────────────────────────┬───┘                │
│         │                                   │                    │
│         │ PostgreSQL                        │ Event Logging      │
│         ▼                                   ▼                    │
│  ┌─────────────┐                    ┌──────────────┐            │
│  │  Postgres   │                    │ Audit/Event  │            │
│  │  (TLS+mTLS) │                    │   Logging    │            │
│  └─────────────┘                    └──────┬───────┘            │
│                                             │                    │
│                                             ▼                    │
│                                     ┌──────────────┐            │
│                                     │ Loki/OTLP    │            │
│                                     └──────────────┘            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Infrastructure Layer (NixOS)                  │
├─────────────────────────────────────────────────────────────────┤
│  • VM Firewall (egress filtering)                                │
│  • Hardened SSH                                                  │
│  • Kernel Hardening                                              │
│  • SystemD Isolation                                             │
│  • AIDE Intrusion Detection                                      │
│  • Vault PKI (certificate management)                            │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Deployment Topologies

**Topology 1: Embedded Keycloak (Single VM)**
```
┌─────────────────────────────┐
│       Application VM         │
├─────────────────────────────┤
│  • User App (Axum)          │
│  • Keycloak                 │
│  • PostgreSQL (shared)      │
│  • Nginx (reverse proxy)    │
└─────────────────────────────┘
```
- **Use Case**: Development, low-traffic apps, cost-sensitive deployments
- **FedRAMP Profile**: Low/Moderate
- **Scaling**: Vertical only

**Topology 2: Dedicated Keycloak VM**
```
┌──────────────────┐        ┌──────────────────┐
│  Application VM  │        │   Keycloak VM    │
├──────────────────┤        ├──────────────────┤
│  • User App      │◄──────►│  • Keycloak      │
│  • PostgreSQL    │  mTLS  │  • PostgreSQL    │
└──────────────────┘        └──────────────────┘
```
- **Use Case**: Production, multi-app environments
- **FedRAMP Profile**: Moderate/High
- **Scaling**: Horizontal (multiple app VMs share Keycloak)

**Topology 3: HA Keycloak Cluster**
```
┌──────────────────┐        ┌──────────────────┐
│  Application VM  │        │  Keycloak VM 1   │
├──────────────────┤        ├──────────────────┤
│  • User App      │◄───┬──►│  • Keycloak      │
│  • PostgreSQL    │    │   └──────────────────┘
└──────────────────┘    │
                        │   ┌──────────────────┐
                        │   │  Keycloak VM 2   │
                        │   ├──────────────────┤
                        ├──►│  • Keycloak      │
                        │   └──────────────────┘
                        │
                        │   ┌──────────────────┐
                        │   │   PostgreSQL HA  │
                        │   ├──────────────────┤
                        └──►│  • Primary + Rep │
                            └──────────────────┘
```
- **Use Case**: High availability, FedRAMP High
- **FedRAMP Profile**: High
- **Scaling**: Full horizontal scaling with failover

### 2.3 Data Flow

**OAuth2 Authorization Code Flow (FAPI 2.0)**:

1. **User initiates login** → App redirects to Keycloak
2. **App creates PKCE challenge** (SHA-256)
3. **App pushes authorization request** to PAR endpoint (backchannel)
4. **Keycloak returns request_uri**
5. **App redirects user** to authorization endpoint with `request_uri`
6. **User authenticates** (username/password + MFA)
7. **Keycloak returns signed authorization response** (JARM)
8. **App exchanges authorization code** for tokens (mTLS + PKCE verifier)
9. **Keycloak issues certificate-bound access token** (RFC 8705)
10. **App validates JWT** using Keycloak's JWKS endpoint
11. **App makes API calls** with access token + client certificate

---

## 3. NixOS Module Design

### 3.1 Module Structure

```
nix/modules/keycloak/
├── default.nix                 # Main module interface
├── service.nix                 # Keycloak service configuration
├── database.nix                # PostgreSQL setup for Keycloak
├── networking.nix              # Firewall, reverse proxy
├── fips.nix                    # FIPS mode configuration
├── realms/                     # Realm templates
│   ├── default-realm.nix       # Base realm config
│   ├── fedramp-low.nix         # FedRAMP Low policies
│   ├── fedramp-moderate.nix    # FedRAMP Moderate policies
│   └── fedramp-high.nix        # FedRAMP High policies
├── clients/                    # Client templates
│   ├── web-app.nix             # Public web app client
│   ├── api-service.nix         # Confidential API client (mTLS)
│   └── cli-tool.nix            # Device authorization flow
└── observability.nix           # Event logging integration
```

### 3.2 Module Options

```nix
{
  barbican.keycloak = {
    enable = mkEnableOption "Barbican Keycloak deployment";

    # Security Profile
    profile = mkOption {
      type = types.enum [ "fedramp-low" "fedramp-moderate" "fedramp-high" ];
      default = "fedramp-moderate";
      description = "FedRAMP compliance profile";
    };

    fipsMode = mkOption {
      type = types.bool;
      default = true;
      description = "Enable FIPS 140-3 cryptography";
    };

    # Deployment Mode
    deploymentMode = mkOption {
      type = types.enum [ "embedded" "dedicated" "cluster" ];
      default = "dedicated";
      description = "Deployment topology";
    };

    # Networking
    hostname = mkOption {
      type = types.str;
      example = "auth.example.com";
      description = "Public hostname for Keycloak";
    };

    listenAddress = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Listen address";
    };

    port = mkOption {
      type = types.port;
      default = 8443;
      description = "HTTPS port";
    };

    # Database
    database = {
      host = mkOption {
        type = types.str;
        default = "localhost";
        description = "PostgreSQL host";
      };

      port = mkOption {
        type = types.port;
        default = 5432;
      };

      name = mkOption {
        type = types.str;
        default = "keycloak";
      };

      username = mkOption {
        type = types.str;
        default = "keycloak";
      };

      passwordFile = mkOption {
        type = types.path;
        description = "Path to database password file";
      };

      requireSSL = mkOption {
        type = types.bool;
        default = true;
      };

      clientCertificateFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Client certificate for mTLS to PostgreSQL";
      };
    };

    # TLS Configuration
    tls = {
      certificateFile = mkOption {
        type = types.path;
        description = "Server TLS certificate";
      };

      keyFile = mkOption {
        type = types.path;
        description = "Server TLS private key";
      };

      caFile = mkOption {
        type = types.path;
        description = "CA certificate for client verification";
      };

      enableMTLS = mkOption {
        type = types.bool;
        default = true;
        description = "Require client certificates for confidential clients";
      };
    };

    # Realms
    realms = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          name = mkOption {
            type = types.str;
            description = "Realm name";
          };

          displayName = mkOption {
            type = types.str;
            description = "Human-readable realm name";
          };

          # Session Policies (from profile or override)
          sessionIdleTimeout = mkOption {
            type = types.int;
            description = "Idle timeout in minutes";
          };

          sessionMaxLifespan = mkOption {
            type = types.int;
            description = "Max session lifespan in minutes";
          };

          accessTokenLifespan = mkOption {
            type = types.int;
            default = 10;
            description = "Access token lifetime in minutes (FAPI 2.0: max 10)";
          };

          # Password Policy (NIST 800-63B)
          passwordMinLength = mkOption {
            type = types.int;
            description = "Minimum password length";
          };

          passwordRequireUppercase = mkOption {
            type = types.bool;
            default = true;
          };

          passwordRequireDigit = mkOption {
            type = types.bool;
            default = true;
          };

          passwordRequireSpecialChar = mkOption {
            type = types.bool;
            default = true;
          };

          passwordHistoryCount = mkOption {
            type = types.int;
            default = 24;
            description = "Number of previous passwords to remember";
          };

          # Brute Force Protection
          bruteForceEnabled = mkOption {
            type = types.bool;
            default = true;
          };

          bruteForceMaxAttempts = mkOption {
            type = types.int;
            description = "Max failed login attempts";
          };

          bruteForceLockoutDuration = mkOption {
            type = types.int;
            description = "Account lockout duration in minutes";
          };

          # MFA Policy
          requireMFA = mkOption {
            type = types.bool;
            description = "Require multi-factor authentication";
          };

          mfaMethods = mkOption {
            type = types.listOf (types.enum [ "totp" "webauthn" "sms" ]);
            default = [ "totp" "webauthn" ];
            description = "Allowed MFA methods";
          };
        };
      });
      default = {};
      description = "Keycloak realms to configure";
    };

    # Clients
    clients = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          realm = mkOption {
            type = types.str;
            description = "Realm this client belongs to";
          };

          clientId = mkOption {
            type = types.str;
            description = "OAuth2 client ID";
          };

          name = mkOption {
            type = types.str;
            description = "Human-readable client name";
          };

          type = mkOption {
            type = types.enum [ "public" "confidential" "bearer-only" ];
            default = "confidential";
            description = "Client type";
          };

          # FAPI 2.0 Settings
          enableFAPI = mkOption {
            type = types.bool;
            default = true;
            description = "Enable FAPI 2.0 security profile";
          };

          requirePKCE = mkOption {
            type = types.bool;
            default = true;
          };

          requirePAR = mkOption {
            type = types.bool;
            default = true;
            description = "Require Pushed Authorization Requests";
          };

          requireMTLS = mkOption {
            type = types.bool;
            default = true;
            description = "Require mutual TLS for token endpoint";
          };

          certificateBoundTokens = mkOption {
            type = types.bool;
            default = true;
            description = "Issue certificate-bound access tokens (RFC 8705)";
          };

          # Redirect URIs
          redirectUris = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Allowed redirect URIs";
          };

          webOrigins = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Allowed CORS origins";
          };

          # Client Secret (for confidential clients)
          clientSecretFile = mkOption {
            type = types.nullOr types.path;
            default = null;
            description = "Path to client secret file";
          };
        };
      });
      default = {};
      description = "OAuth2/OIDC clients to configure";
    };

    # Admin User
    adminUser = {
      username = mkOption {
        type = types.str;
        default = "admin";
      };

      passwordFile = mkOption {
        type = types.path;
        description = "Path to admin password file";
      };
    };

    # Observability Integration
    observability = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable event logging to Loki/OTLP";
      };

      lokiEndpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "http://localhost:3100";
        description = "Grafana Loki endpoint";
      };

      otlpEndpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "http://localhost:4318";
        description = "OpenTelemetry collector endpoint";
      };

      auditEvents = mkOption {
        type = types.listOf types.str;
        default = [
          "LOGIN"
          "LOGIN_ERROR"
          "LOGOUT"
          "REGISTER"
          "UPDATE_PASSWORD"
          "UPDATE_PROFILE"
          "FEDERATED_IDENTITY_LINK"
          "REMOVE_FEDERATED_IDENTITY"
        ];
        description = "Events to log";
      };
    };

    # Resource Limits
    resources = {
      heapSize = mkOption {
        type = types.str;
        default = "2g";
        description = "JVM heap size";
      };

      maxConnections = mkOption {
        type = types.int;
        default = 100;
        description = "Max database connections";
      };
    };
  };
}
```

### 3.3 Profile Defaults

**FedRAMP Low**:
```nix
{
  sessionIdleTimeout = 30;        # 30 min idle
  sessionMaxLifespan = 480;       # 8 hours
  accessTokenLifespan = 10;       # 10 min (FAPI max)
  passwordMinLength = 8;          # NIST 800-63B minimum
  bruteForceMaxAttempts = 5;      # 5 attempts
  bruteForceLockoutDuration = 15; # 15 min lockout
  requireMFA = false;             # MFA not required for Low
  enableFAPI = false;             # Basic OAuth2
}
```

**FedRAMP Moderate**:
```nix
{
  sessionIdleTimeout = 15;        # 15 min idle (AC-11)
  sessionMaxLifespan = 240;       # 4 hours (AC-12)
  accessTokenLifespan = 10;       # 10 min
  passwordMinLength = 12;         # 12 characters
  bruteForceMaxAttempts = 3;      # 3 attempts (AC-7)
  bruteForceLockoutDuration = 30; # 30 min lockout (AC-7)
  requireMFA = false;             # Optional for Moderate
  enableFAPI = true;              # FAPI 2.0 for financial apps
}
```

**FedRAMP High**:
```nix
{
  sessionIdleTimeout = 10;        # 10 min idle
  sessionMaxLifespan = 120;       # 2 hours
  accessTokenLifespan = 5;        # 5 min (stricter than FAPI)
  passwordMinLength = 15;         # 15 characters
  bruteForceMaxAttempts = 3;      # 3 attempts
  bruteForceLockoutDuration = 30; # 30 min lockout
  requireMFA = true;              # MFA mandatory (IA-2(1))
  enableFAPI = true;              # FAPI 2.0 mandatory
  requireMTLS = true;             # mTLS mandatory
  certificateBoundTokens = true;  # RFC 8705 mandatory
}
```

---

## 4. Integration Patterns

### 4.1 Pattern 1: Embedded Keycloak (Simplest)

**Use Case**: Single-app deployment, development, cost-sensitive

**Flake Structure**:
```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    barbican.url = "github:Sauce65/barbican";
  };

  outputs = { nixpkgs, barbican, ... }: {
    nixosConfigurations.myapp = nixpkgs.lib.nixosSystem {
      modules = [
        barbican.nixosModules.all
        ./nix/generated/barbican.nix
        {
          # Enable Keycloak with app
          barbican.keycloak = {
            enable = true;
            profile = "fedramp-moderate";
            deploymentMode = "embedded";
            hostname = "auth.myapp.com";

            # Reuse app's PostgreSQL
            database.passwordFile = config.age.secrets.keycloak-db-password.path;

            # Reuse app's TLS certs from Vault
            tls = {
              certificateFile = "/var/lib/vault-pki/server-cert.pem";
              keyFile = "/var/lib/vault-pki/server-key.pem";
              caFile = "/var/lib/vault-pki/ca-cert.pem";
            };

            # Configure realm from barbican.toml
            realms.myapp = {
              name = "myapp";
              displayName = "My Application";
            };

            # Configure client
            clients.myapp-web = {
              realm = "myapp";
              clientId = "myapp-web";
              type = "public";
              redirectUris = [ "https://myapp.com/auth/callback" ];
            };
          };
        }
      ];
    };
  };
}
```

**barbican.toml**:
```toml
[app]
name = "myapp"
profile = "fedramp-moderate"

[keycloak]
enable = true
deployment_mode = "embedded"
hostname = "auth.myapp.com"

[keycloak.realm.myapp]
display_name = "My Application"

[keycloak.client.myapp-web]
realm = "myapp"
type = "public"
redirect_uris = ["https://myapp.com/auth/callback"]
```

**Generated Rust Config** (`src/generated/barbican_config.rs`):
```rust
pub struct KeycloakConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub jwks_uri: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
}

impl KeycloakConfig {
    pub fn from_env() -> Self {
        Self {
            issuer_url: "https://auth.myapp.com/realms/myapp".to_string(),
            client_id: "myapp-web".to_string(),
            jwks_uri: "https://auth.myapp.com/realms/myapp/protocol/openid-connect/certs".to_string(),
            authorization_endpoint: "https://auth.myapp.com/realms/myapp/protocol/openid-connect/auth".to_string(),
            token_endpoint: "https://auth.myapp.com/realms/myapp/protocol/openid-connect/token".to_string(),
            userinfo_endpoint: "https://auth.myapp.com/realms/myapp/protocol/openid-connect/userinfo".to_string(),
        }
    }
}
```

### 4.2 Pattern 2: Dedicated Keycloak VM

**Use Case**: Multi-app environment, shared identity provider

**Infrastructure Layout**:
```
apps/
├── keycloak/
│   ├── flake.nix           # Keycloak-only deployment
│   ├── barbican.toml       # Keycloak configuration
│   └── secrets/            # Age-encrypted secrets
│
└── myapp/
    ├── flake.nix           # App deployment (no Keycloak)
    ├── barbican.toml       # References external Keycloak
    └── secrets/
```

**Keycloak VM** (`apps/keycloak/barbican.toml`):
```toml
[app]
name = "keycloak-idp"
profile = "fedramp-high"

[keycloak]
enable = true
deployment_mode = "dedicated"
hostname = "auth.myorg.com"
fips_mode = true

# Serve multiple apps
[keycloak.realm.app1]
display_name = "Application 1"

[keycloak.realm.app2]
display_name = "Application 2"

[keycloak.client.app1-web]
realm = "app1"
type = "confidential"
require_mtls = true
redirect_uris = ["https://app1.myorg.com/auth/callback"]

[keycloak.client.app2-api]
realm = "app2"
type = "confidential"
require_mtls = true
redirect_uris = ["https://app2.myorg.com/auth/callback"]
```

**App VM** (`apps/myapp/barbican.toml`):
```toml
[app]
name = "myapp"
profile = "fedramp-high"

[auth]
# Reference external Keycloak
issuer_url = "https://auth.myorg.com/realms/app1"
client_id = "app1-web"
jwks_uri = "https://auth.myorg.com/realms/app1/protocol/openid-connect/certs"

# Client certificate for mTLS
client_cert_path = "/var/lib/vault-pki/client-cert.pem"
client_key_path = "/var/lib/vault-pki/client-key.pem"
```

### 4.3 Pattern 3: HA Cluster

**Use Case**: High availability, FedRAMP High, large scale

**Keycloak Cluster** (3 nodes + PostgreSQL HA):
```nix
# flake.nix for Keycloak cluster
{
  nixosConfigurations = {
    keycloak-1 = nixpkgs.lib.nixosSystem {
      modules = [
        barbican.nixosModules.all
        {
          barbican.keycloak = {
            enable = true;
            profile = "fedramp-high";
            deploymentMode = "cluster";
            hostname = "auth.myorg.com";

            # External PostgreSQL HA
            database = {
              host = "postgres-primary.myorg.com";
              port = 5432;
              requireSSL = true;
              clientCertificateFile = "/var/lib/vault-pki/keycloak-db-client.pem";
            };

            # Infinispan cluster config
            clustering = {
              enable = true;
              nodes = [
                "keycloak-1.myorg.com"
                "keycloak-2.myorg.com"
                "keycloak-3.myorg.com"
              ];
              jgroupsBindAddr = "0.0.0.0";
            };
          };
        }
      ];
    };

    keycloak-2 = /* similar */;
    keycloak-3 = /* similar */;
  };
}
```

---

## 5. Configuration Management

### 5.1 CLI Commands

**New `barbican-cli` commands**:

```bash
# Generate Keycloak module from barbican.toml
barbican generate keycloak

# Generate realm configuration
barbican keycloak realm create --name myapp --profile fedramp-moderate

# Generate client configuration
barbican keycloak client create \
  --realm myapp \
  --client-id myapp-web \
  --type public \
  --redirect-uri https://myapp.com/callback

# Export realm to JSON (for GitOps)
barbican keycloak realm export --name myapp > realm-myapp.json

# Validate Keycloak configuration
barbican keycloak validate

# Show effective Keycloak config
barbican keycloak show-config
```

### 5.2 Realm Export/Import

**Declarative Realm Management**:
- Store realm configurations as JSON in `nix/realms/*.json`
- Import during NixOS activation via `keycloak-import` script
- Version control realm changes with Git

**Realm JSON Structure**:
```json
{
  "realm": "myapp",
  "enabled": true,
  "sslRequired": "all",
  "registrationAllowed": false,
  "bruteForceProtected": true,
  "failureFactor": 3,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 1800,
  "accessTokenLifespan": 600,
  "ssoSessionIdleTimeout": 900,
  "ssoSessionMaxLifespan": 14400,
  "passwordPolicy": "length(12) and digits(1) and upperCase(1) and specialChars(1) and notUsername and passwordHistory(24)",
  "otpPolicyType": "totp",
  "clients": [
    {
      "clientId": "myapp-web",
      "protocol": "openid-connect",
      "publicClient": false,
      "attributes": {
        "tls.client.certificate.bound.access.tokens": "true",
        "require.pushed.authorization.requests": "true",
        "pkce.code.challenge.method": "S256"
      }
    }
  ]
}
```

### 5.3 Secret Management

**Integration with age/sops**:

```toml
# barbican.toml
[secrets]
backend = "age"  # or "sops"

[keycloak.secrets]
admin_password = "age:secrets/keycloak-admin-password.age"
db_password = "age:secrets/keycloak-db-password.age"

[keycloak.client.myapp-web.secrets]
client_secret = "age:secrets/myapp-web-client-secret.age"
```

**Certificate Management** (via Vault PKI):
- Keycloak server certificates: auto-renewed from Vault
- Client certificates for mTLS: issued by Vault PKI CA
- Database client certificates: issued by PostgreSQL internal CA

**Rotation Policy**:
- Admin password: manual rotation, stored in age-encrypted file
- Client secrets: 90-day rotation via Keycloak API
- TLS certificates: 30-day auto-renewal via Vault
- Database passwords: 90-day rotation via Vault dynamic secrets

---

## 6. Deployment Workflows

### 6.1 Developer Workflow

**Step 1: Configure `barbican.toml`**
```toml
[app]
name = "myapp"
profile = "fedramp-moderate"

[keycloak]
enable = true
hostname = "auth.myapp.com"

[keycloak.realm.myapp]
display_name = "My Application"

[keycloak.client.myapp-web]
realm = "myapp"
type = "public"
redirect_uris = ["https://myapp.com/callback"]
```

**Step 2: Generate configuration**
```bash
barbican generate rust
barbican generate nix
barbican generate keycloak
```

**Step 3: Build and deploy**
```bash
nix build .#nixosConfigurations.myapp.config.system.build.toplevel
nixos-rebuild switch --flake .#myapp
```

**Step 4: Access admin console**
```bash
# Admin console at: https://auth.myapp.com/admin
# Credentials from: secrets/keycloak-admin-password.age
```

**Step 5: Test OAuth2 flow**
```bash
# Use generated test script
./scripts/test-oauth2-flow.sh
```

### 6.2 Administrator Workflow

**Initial Setup**:
1. Generate secrets: `barbican keycloak init-secrets`
2. Configure DNS: Point `auth.myorg.com` to Keycloak VM IP
3. Issue certificates: Vault PKI provisions TLS cert
4. Deploy: `nixos-rebuild switch`
5. Verify: `curl https://auth.myorg.com/.well-known/openid-configuration`

**Adding a New App**:
1. Create realm: `barbican keycloak realm create --name newapp`
2. Create client: `barbican keycloak client create --realm newapp --client-id newapp-web`
3. Export config: `barbican keycloak client export --client-id newapp-web > newapp-client.json`
4. Share with app team: Provide `newapp-client.json` and issuer URL

**Monitoring**:
1. Check Keycloak health: `curl https://auth.myorg.com/health/ready`
2. View metrics: Prometheus `/metrics` endpoint
3. View logs: Grafana Loki dashboard
4. View audit trail: Keycloak admin events

**Backup and Recovery**:
1. Database backup: Automated via `barbican.databaseBackup` module
2. Realm export: `barbican keycloak realm export --all > backup.json`
3. Restore: `barbican keycloak realm import < backup.json`

### 6.3 GitOps Workflow

**Repository Structure**:
```
infra/
├── keycloak/
│   ├── barbican.toml
│   ├── flake.nix
│   ├── realms/
│   │   ├── app1-realm.json
│   │   ├── app2-realm.json
│   │   └── app3-realm.json
│   └── secrets/
│       └── secrets.nix  # age-encrypted
│
└── apps/
    ├── app1/
    ├── app2/
    └── app3/
```

**CI/CD Pipeline**:
```yaml
# .github/workflows/deploy-keycloak.yml
name: Deploy Keycloak
on:
  push:
    branches: [main]
    paths:
      - 'infra/keycloak/**'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Nix
        uses: cachix/install-nix-action@v24

      - name: Validate configuration
        run: |
          cd infra/keycloak
          nix run .#barbican-cli -- keycloak validate

      - name: Build system
        run: |
          cd infra/keycloak
          nix build .#nixosConfigurations.keycloak.config.system.build.toplevel

      - name: Deploy to staging
        run: |
          nix copy --to ssh://keycloak-staging ./result
          ssh keycloak-staging "sudo nixos-rebuild switch --flake /etc/nixos"

      - name: Run smoke tests
        run: |
          curl -f https://keycloak-staging/.well-known/openid-configuration

      - name: Deploy to production
        if: github.ref == 'refs/heads/main'
        run: |
          nix copy --to ssh://keycloak-prod ./result
          ssh keycloak-prod "sudo nixos-rebuild switch --flake /etc/nixos"
```

---

## 7. Secrets Management

### 7.1 Secret Types

| Secret | Type | Storage | Rotation |
|--------|------|---------|----------|
| Admin password | Static | age/sops | Manual |
| Database password | Dynamic | Vault | 90 days |
| Client secrets | Static | age/sops | 90 days |
| TLS certificates | Dynamic | Vault PKI | 30 days |
| Client certificates | Dynamic | Vault PKI | 30 days |
| Signing keys | Static | Keycloak DB | Annual |

### 7.2 Vault Integration

**Dynamic Database Credentials**:
```nix
barbican.keycloak = {
  database = {
    # Use Vault dynamic credentials
    usernameFile = config.services.vault-agent.secrets.keycloak-db-username;
    passwordFile = config.services.vault-agent.secrets.keycloak-db-password;
  };
};

# Vault agent configuration
services.vault-agent = {
  enable = true;
  templates = {
    keycloak-db-username = {
      source = pkgs.writeText "username.tmpl" ''
        {{ with secret "database/creds/keycloak" }}{{ .Data.username }}{{ end }}
      '';
      destination = "/run/secrets/keycloak-db-username";
    };
    keycloak-db-password = {
      source = pkgs.writeText "password.tmpl" ''
        {{ with secret "database/creds/keycloak" }}{{ .Data.password }}{{ end }}
      '';
      destination = "/run/secrets/keycloak-db-password";
    };
  };
};
```

**Certificate Auto-Renewal**:
```nix
barbican.keycloak = {
  tls = {
    # Certificates auto-renewed from Vault PKI
    certificateFile = config.barbican.vaultPki.certificates.keycloak.certPath;
    keyFile = config.barbican.vaultPki.certificates.keycloak.keyPath;
    caFile = config.barbican.vaultPki.caPath;
  };
};

barbican.vaultPki = {
  certificates.keycloak = {
    commonName = "auth.myorg.com";
    altNames = [ "keycloak.internal" ];
    ttl = "720h";  # 30 days
  };
};
```

### 7.3 Age-Encrypted Secrets

**Setup**:
```bash
# Generate age key
age-keygen > secrets/keys.txt

# Encrypt admin password
echo "super-secret-password" | age -r $(cat secrets/keys.txt | grep public) > secrets/keycloak-admin-password.age

# Encrypt client secret
echo "client-secret-value" | age -r $(cat secrets/keys.txt | grep public) > secrets/myapp-web-client-secret.age
```

**NixOS Configuration**:
```nix
{
  age.secrets = {
    keycloak-admin-password = {
      file = ./secrets/keycloak-admin-password.age;
      owner = "keycloak";
      group = "keycloak";
      mode = "0400";
    };

    myapp-web-client-secret = {
      file = ./secrets/myapp-web-client-secret.age;
      owner = "keycloak";
      group = "keycloak";
      mode = "0400";
    };
  };

  barbican.keycloak = {
    adminUser.passwordFile = config.age.secrets.keycloak-admin-password.path;
    clients.myapp-web.clientSecretFile = config.age.secrets.myapp-web-client-secret.path;
  };
}
```

---

## 8. Observability Integration

### 8.1 Event Logging to Loki

**Keycloak Event SPI**:
- Implement custom Keycloak event listener SPI
- Forward events to Loki via HTTP API
- Structure logs as JSON with labels for filtering

**Event Log Format**:
```json
{
  "timestamp": "2026-01-13T10:30:45Z",
  "event_type": "LOGIN",
  "realm": "myapp",
  "user_id": "12345",
  "username": "alice@example.com",
  "ip_address": "203.0.113.42",
  "client_id": "myapp-web",
  "session_id": "a1b2c3d4",
  "success": true,
  "details": {
    "auth_method": "password",
    "mfa_method": "totp"
  }
}
```

**Loki Labels**:
```json
{
  "job": "keycloak",
  "realm": "myapp",
  "event_type": "LOGIN",
  "success": "true"
}
```

**Grafana Dashboard Queries**:
```logql
# Failed login attempts by user
{job="keycloak", event_type="LOGIN_ERROR"} | json | line_format "{{.username}} from {{.ip_address}}"

# MFA enrollment rate
sum(count_over_time({job="keycloak", event_type="UPDATE_TOTP"}[1d])) by (realm)

# Session lifetime histogram
histogram_quantile(0.95, sum(rate({job="keycloak", event_type="LOGOUT"}[5m])) by (le))
```

### 8.2 Metrics (Prometheus)

**Keycloak Metrics** (via Micrometer):
- `keycloak_logins_total{realm, client_id, result}`
- `keycloak_sessions_active{realm}`
- `keycloak_token_issued_total{realm, token_type}`
- `keycloak_user_registrations_total{realm}`
- `keycloak_admin_events_total{resource_type, operation}`

**Database Metrics**:
- Connection pool utilization
- Query latency
- Lock contention

**JVM Metrics**:
- Heap usage
- GC pauses
- Thread count

### 8.3 Health Checks

**Endpoints**:
- `/health/live` - Liveness probe (JVM running)
- `/health/ready` - Readiness probe (database connected, caches loaded)
- `/metrics` - Prometheus metrics

**NixOS Health Check Integration**:
```nix
barbican.health = {
  checks = {
    keycloak = {
      enable = true;
      url = "https://localhost:8443/health/ready";
      interval = 30;
      timeout = 5;
      retries = 3;
    };
  };
};
```

---

## 9. Testing Strategy

### 9.1 NixOS VM Tests

**Test Structure** (`nix/tests/keycloak-test.nix`):
```nix
import <nixpkgs/nixos/tests/make-test-python.nix> {
  name = "keycloak-fapi-test";

  nodes = {
    keycloak = { config, pkgs, ... }: {
      imports = [ ../../modules/keycloak/default.nix ];

      barbican.keycloak = {
        enable = true;
        profile = "fedramp-high";
        hostname = "keycloak.test";
        fipsMode = true;

        realms.test = {
          name = "test";
          displayName = "Test Realm";
        };

        clients.test-client = {
          realm = "test";
          clientId = "test-client";
          type = "confidential";
          redirectUris = [ "https://client.test/callback" ];
        };
      };
    };

    client = { ... }: {
      # Test client VM
    };
  };

  testScript = ''
    start_all()

    # Wait for Keycloak to be ready
    keycloak.wait_for_unit("keycloak.service")
    keycloak.wait_for_open_port(8443)
    keycloak.wait_until_succeeds("curl -f -k https://localhost:8443/health/ready")

    # Test OIDC discovery
    keycloak.succeed("curl -k https://localhost:8443/realms/test/.well-known/openid-configuration | jq -e '.issuer'")

    # Test FIPS mode
    keycloak.succeed("curl -k https://localhost:8443/realms/test/.well-known/openid-configuration | jq -e '.token_endpoint_auth_signing_alg_values_supported | contains([\"PS256\"])'")

    # Test PAR endpoint
    keycloak.succeed("curl -k https://localhost:8443/realms/test/.well-known/openid-configuration | jq -e '.pushed_authorization_request_endpoint'")

    # Test mTLS endpoint
    keycloak.succeed("curl -k https://localhost:8443/realms/test/.well-known/openid-configuration | jq -e '.mtls_endpoint_aliases'")

    # Test OAuth2 flow
    client.succeed("python /test-scripts/oauth2-flow.py")

    # Verify audit logging
    keycloak.succeed("journalctl -u keycloak | grep 'LOGIN_ERROR'")
  '';
}
```

### 9.2 Compliance Tests

**FAPI 2.0 Conformance Suite**:
```bash
# Run OpenID Foundation FAPI conformance tests
docker run -it --rm \
  -e KEYCLOAK_BASE_URL=https://auth.myorg.com \
  -e REALM=test \
  openid/conformance-suite:release \
  --test-plan fapi2-advanced
```

**FedRAMP Control Tests** (`tests/compliance/keycloak-controls.nix`):
```nix
{
  # AC-7: Unsuccessful Login Attempts
  testBruteForce = ''
    # Attempt 4 logins with wrong password
    for i in {1..4}; do
      curl -X POST https://keycloak/realms/test/login \
        -d "username=testuser&password=wrong"
    done

    # 4th attempt should fail with account locked
    result=$(curl -X POST https://keycloak/realms/test/login \
      -d "username=testuser&password=correct")

    echo "$result" | grep -q "account_locked"
  '';

  # AC-11/AC-12: Session Timeouts
  testSessionTimeout = ''
    # Create session
    token=$(curl -X POST https://keycloak/realms/test/protocol/openid-connect/token \
      -d "grant_type=password&username=testuser&password=correct&client_id=test-client" \
      | jq -r '.access_token')

    # Wait 11 minutes (idle timeout is 10 min)
    sleep 660

    # Token should be invalid
    curl -H "Authorization: Bearer $token" https://api/protected | grep -q "401"
  '';

  # IA-5(1): Password Policy
  testPasswordPolicy = ''
    # Attempt to set weak password
    result=$(curl -X PUT https://keycloak/admin/realms/test/users/123/reset-password \
      -H "Authorization: Bearer $admin_token" \
      -d '{"value": "weak"}')

    echo "$result" | grep -q "password policy"
  '';
}
```

### 9.3 Integration Tests

**OAuth2 Client Library Tests** (`tests/integration/oauth2_test.rs`):
```rust
#[tokio::test]
async fn test_authorization_code_flow() {
    let keycloak_url = "https://keycloak.test/realms/test";
    let client_id = "test-client";
    let redirect_uri = "https://client.test/callback";

    // Step 1: Create PKCE challenge
    let verifier = PkceCodeVerifier::new_random();
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);

    // Step 2: Push authorization request (PAR)
    let par_response = client
        .post(format!("{}/protocol/openid-connect/ext/par", keycloak_url))
        .form(&[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", "openid profile"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await?;

    let request_uri = par_response.json::<ParResponse>().await?.request_uri;

    // Step 3: Redirect user to authorization endpoint
    let auth_url = format!(
        "{}/protocol/openid-connect/auth?client_id={}&request_uri={}",
        keycloak_url, client_id, request_uri
    );

    // Step 4: Simulate user login and consent
    let code = simulate_user_auth(&auth_url).await?;

    // Step 5: Exchange code for token (with mTLS)
    let token_response = client
        .post(format!("{}/protocol/openid-connect/token", keycloak_url))
        .cert(client_cert)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier.secret()),
        ])
        .send()
        .await?;

    let tokens = token_response.json::<TokenResponse>().await?;

    // Step 6: Validate JWT
    let claims = barbican::auth::validate_jwt(
        &tokens.access_token,
        &keycloak_url,
        client_id,
    ).await?;

    assert_eq!(claims.iss, keycloak_url);
    assert!(claims.cnf.is_some()); // Certificate binding
}
```

---

## 10. Implementation Roadmap

### Phase 1: Core Keycloak Module (Weeks 1-2)

**Deliverables**:
- [ ] NixOS module skeleton (`nix/modules/keycloak/default.nix`)
- [ ] Service configuration with FIPS mode
- [ ] PostgreSQL integration
- [ ] TLS configuration
- [ ] Basic realm/client provisioning
- [ ] Profile defaults (Low/Moderate/High)

**Acceptance Criteria**:
- Keycloak starts successfully on NixOS
- HTTPS endpoint accessible
- Database migrations applied
- Admin console accessible
- Basic OAuth2 flow works

### Phase 2: FAPI 2.0 Support (Weeks 3-4)

**Deliverables**:
- [ ] mTLS client authentication
- [ ] PAR (Pushed Authorization Requests) configuration
- [ ] JARM (JWT Authorization Response Mode)
- [ ] Certificate-bound tokens (RFC 8705)
- [ ] PKCE enforcement
- [ ] Token lifetime configuration per FAPI

**Acceptance Criteria**:
- mTLS handshake succeeds for confidential clients
- PAR endpoint returns request_uri
- Access tokens include x5t#S256 confirmation claim
- FAPI 2.0 conformance suite passes

### Phase 3: CLI Integration (Week 5)

**Deliverables**:
- [ ] `barbican generate keycloak` command
- [ ] `barbican keycloak realm create`
- [ ] `barbican keycloak client create`
- [ ] `barbican keycloak validate`
- [ ] `barbican keycloak export`
- [ ] Rust config generation for auth library
- [ ] Nix config generation

**Acceptance Criteria**:
- CLI generates valid NixOS configuration from barbican.toml
- Generated Rust config compiles and works with barbican::auth
- Realm export produces valid JSON

### Phase 4: Observability Integration (Week 6)

**Deliverables**:
- [ ] Keycloak event listener SPI for Loki
- [ ] Prometheus metrics exporter
- [ ] Health check endpoints
- [ ] Audit logging configuration
- [ ] Grafana dashboard templates

**Acceptance Criteria**:
- Login events appear in Loki
- Metrics scraped by Prometheus
- Health checks respond correctly
- Grafana dashboard displays key metrics

### Phase 5: Secrets Management (Week 7)

**Deliverables**:
- [ ] Age/sops integration for static secrets
- [ ] Vault dynamic database credentials
- [ ] Vault PKI certificate auto-renewal
- [ ] Client secret rotation automation
- [ ] Documentation for secret lifecycle

**Acceptance Criteria**:
- Age-encrypted secrets decrypted at boot
- Vault issues DB credentials on service start
- Certificates auto-renew before expiry
- No plaintext secrets in Nix store

### Phase 6: Testing & Documentation (Week 8)

**Deliverables**:
- [ ] NixOS VM tests for all profiles
- [ ] FAPI 2.0 conformance tests
- [ ] FedRAMP control compliance tests
- [ ] Integration test suite
- [ ] Developer quickstart guide
- [ ] Administrator operations manual
- [ ] Security hardening checklist

**Acceptance Criteria**:
- `nix flake check` passes all tests
- FAPI conformance suite shows 100% pass rate
- FedRAMP control evidence artifacts generated
- Documentation covers all deployment patterns

### Phase 7: Examples & Dogfooding (Week 9)

**Deliverables**:
- [ ] Update `examples/fedramp-low` with embedded Keycloak
- [ ] Add `examples/keycloak-standalone` for dedicated deployment
- [ ] Add `examples/keycloak-ha` for cluster deployment
- [ ] Integration with example apps
- [ ] End-to-end user flows

**Acceptance Criteria**:
- All examples build with `nix build`
- Examples deploy successfully to VMs
- OAuth2 flows work in example apps
- Documentation reflects example patterns

---

## 11. Open Questions & Design Decisions

### 11.1 Keycloak Version

**Question**: Which Keycloak version to target?

**Options**:
1. **Keycloak 25.x (latest stable)** - Full FAPI 2.0 support, modern features
2. **Keycloak 24.x (LTS)** - Longer support window, more stable
3. **Keycloak 26.x (upcoming)** - Cutting-edge, may have breaking changes

**Recommendation**: **Keycloak 25.x**
- FAPI 2.0 client profiles built-in
- Good nixpkgs support in 24.11
- Balance of features and stability

### 11.2 FIPS Crypto Provider

**Question**: Which FIPS-validated crypto provider?

**Options**:
1. **BouncyCastle FIPS** - Java-native, mature, well-tested with Keycloak
2. **AWS-LC FIPS** - Modern, high-performance, used by AWS
3. **OpenSSL FIPS module** - Industry standard, but JNI overhead

**Recommendation**: **BouncyCastle FIPS**
- Best Keycloak integration
- Pure Java (no JNI complexity)
- FIPS 140-3 validated

### 11.3 Clustering Strategy

**Question**: How to handle multi-node clustering?

**Options**:
1. **Infinispan embedded cache** - Keycloak default, requires multicast or TCP discovery
2. **External Infinispan cluster** - More scalable, adds operational complexity
3. **Sticky sessions + database** - Simplest, but limited scalability

**Recommendation**: **Infinispan embedded with TCP discovery**
- Good balance of simplicity and scalability
- No additional services required
- Well-supported by Keycloak

### 11.4 Theme Customization

**Question**: Should Barbican provide custom Keycloak themes?

**Options**:
1. **Default Keycloak theme** - Minimal work, generic look
2. **Custom "Barbican" theme** - Branded, professional
3. **Configurable themes per realm** - Most flexible, most complex

**Recommendation**: **Default theme for v1, custom theme for v2**
- Focus on security/compliance first
- Add branding later
- Provide theme customization hooks in module options

### 11.5 User Federation

**Question**: Should we support LDAP/Active Directory federation?

**Options**:
1. **No federation** - Keep it simple, users in Keycloak DB only
2. **LDAP federation** - Common enterprise requirement
3. **Full federation (LDAP + SAML + OIDC)** - Maximum flexibility

**Recommendation**: **LDAP federation in Phase 2**
- Many enterprises need AD integration
- LDAP is well-supported by Keycloak
- Defer SAML/OIDC federation to later phase

### 11.6 Multi-Tenancy

**Question**: How should multi-app deployments work?

**Options**:
1. **One realm per app** - Maximum isolation, more admin overhead
2. **Shared realm with multiple clients** - Simpler, less isolation
3. **Configurable per deployment** - Flexible, more complex

**Recommendation**: **Configurable, default to one realm per app**
- Provide both patterns in examples
- Document trade-offs
- Let users choose based on their needs

---

## 12. Security Considerations

### 12.1 Threat Model

**Assets**:
- User credentials (passwords, MFA secrets)
- Session tokens (access tokens, refresh tokens, ID tokens)
- Client secrets
- Admin credentials
- Private keys (signing keys, TLS keys)

**Threats**:
1. **Credential stuffing** - Attacker tries leaked passwords
   - Mitigation: Brute force protection, HIBP integration
2. **Token theft** - Attacker steals access token
   - Mitigation: Certificate-bound tokens (RFC 8705), short lifetimes
3. **Session hijacking** - Attacker steals session cookie
   - Mitigation: Secure cookies, idle timeouts, device fingerprinting
4. **Authorization bypass** - Attacker manipulates authorization request
   - Mitigation: PAR (Pushed Authorization Requests), signed requests
5. **Database compromise** - Attacker gains access to PostgreSQL
   - Mitigation: Encrypted at rest, mTLS, credential rotation
6. **Admin console compromise** - Attacker gains admin access
   - Mitigation: MFA mandatory for admin, IP allowlist, audit logging

### 12.2 Defense in Depth

**Network Layer**:
- Firewall restricts inbound traffic to port 443 only
- Egress filtering prevents data exfiltration
- mTLS for all internal communication

**Application Layer**:
- FAPI 2.0 security profile
- PKCE + PAR + certificate-bound tokens
- Rate limiting on authentication endpoints
- Security headers (HSTS, CSP, X-Frame-Options)

**Data Layer**:
- PostgreSQL TLS + client certificates
- Encrypted backups
- Audit logging with HMAC integrity chain

**Host Layer**:
- Kernel hardening (ASLR, DEP, seccomp)
- SystemD sandboxing
- AIDE intrusion detection
- Minimal attack surface (no unnecessary packages)

### 12.3 Security Testing

**Automated Scans**:
- OWASP ZAP scan of Keycloak endpoints
- Nmap port scan to verify firewall rules
- SSL Labs assessment of TLS configuration
- Nuclei template scan for common vulns

**Manual Tests**:
- Authorization bypass attempts
- Token tampering
- Session fixation
- CSRF attacks
- XSS in admin console

**Compliance Validation**:
- FAPI 2.0 conformance suite
- FedRAMP control evidence generation
- NIST 800-53 control audit

---

## 13. Performance & Scalability

### 13.1 Capacity Planning

**Baseline Configuration** (FedRAMP Moderate, single VM):
- **Hardware**: 4 vCPU, 8 GB RAM, 50 GB SSD
- **Expected Load**: 1000 users, 100 concurrent sessions, 10 logins/sec
- **Database**: PostgreSQL 14, shared with app (4 GB buffer)

**Performance Metrics**:
- Login latency: p50 < 200ms, p99 < 1000ms
- Token validation: p50 < 10ms, p99 < 50ms
- Admin API calls: p50 < 100ms, p99 < 500ms

### 13.2 Scaling Strategies

**Vertical Scaling** (up to 10,000 users):
- Increase heap size to 4-8 GB
- More vCPUs for concurrent requests
- Separate database VM for PostgreSQL

**Horizontal Scaling** (10,000+ users):
- 3-node Keycloak cluster
- PostgreSQL HA (primary + replica)
- External Infinispan cluster (optional)
- Load balancer (nginx or HAProxy)

### 13.3 Optimization Tuning

**JVM Settings**:
```
-Xms2g -Xmx2g  # Fixed heap size for predictable GC
-XX:+UseG1GC   # G1 garbage collector for low latency
-XX:MaxGCPauseMillis=200  # Target GC pause time
```

**Database Tuning**:
```sql
-- Connection pooling
shared_buffers = 2GB
max_connections = 200

-- Query optimization
effective_cache_size = 6GB
random_page_cost = 1.1  # SSD
```

**Cache Tuning**:
```
# Infinispan cache sizes
spi-connections-infinispan-default-cache-owners=2
spi-connections-infinispan-default-cache-segments=256
```

---

## 14. Migration & Upgrade Strategy

### 14.1 Upgrading Keycloak

**Zero-Downtime Upgrade** (for HA cluster):
1. Deploy new Keycloak version to staging
2. Run database migrations on staging DB copy
3. Validate new version in staging
4. Upgrade production cluster node-by-node:
   - Remove node 1 from load balancer
   - Upgrade node 1
   - Validate node 1
   - Add node 1 back to load balancer
   - Repeat for nodes 2 and 3

**Single-Node Upgrade** (downtime acceptable):
1. Backup database: `barbican keycloak backup`
2. Update flake input: `barbican.url = "github:Sauce65/barbican/v0.2.0"`
3. Rebuild: `nixos-rebuild switch`
4. Validate: `barbican keycloak validate`

### 14.2 Migrating from External IDP

**Scenario**: App currently uses Auth0, Okta, or custom auth

**Migration Steps**:
1. Deploy Barbican Keycloak in parallel
2. Import users via Keycloak User Federation (LDAP) or bulk import
3. Configure app to support both IDPs (dual-issuer mode)
4. Gradually migrate users (e.g., by department)
5. Sunset old IDP once all users migrated

**User Import Script** (`scripts/import-users.py`):
```python
# Export users from old IDP
users = old_idp.export_users()

# Transform to Keycloak format
keycloak_users = [
    {
        "username": u["email"],
        "email": u["email"],
        "emailVerified": True,
        "enabled": True,
        "credentials": [{"type": "password", "temporary": True, "value": generate_temp_password()}]
    }
    for u in users
]

# Import to Keycloak
keycloak.admin.import_users(realm="myapp", users=keycloak_users)
```

---

## 15. Cost Analysis

### 15.1 Infrastructure Costs

**AWS EC2 (example)**:

| Deployment | Instance Type | Monthly Cost | Users Supported |
|------------|---------------|--------------|-----------------|
| Embedded | t3.medium (2 vCPU, 4 GB) | $30 | 100 |
| Dedicated | t3.large (2 vCPU, 8 GB) | $60 | 1,000 |
| HA Cluster | 3x t3.xlarge (4 vCPU, 16 GB) | $360 | 10,000+ |

**Comparison to SaaS**:
- Auth0: $240/month (1000 MAU) + $0.05/MAU beyond
- Okta: $300/month (1000 users)
- **Barbican Keycloak**: $60/month (1000 users) - **80% cost savings**

### 15.2 Operational Costs

**Time Investment**:
- Initial setup: 4 hours (with Barbican), 40 hours (without)
- Monthly maintenance: 2 hours (patching, monitoring)
- User support: Variable (self-service reduces this)

**Expertise Required**:
- NixOS familiarity (mitigated by Barbican abstraction)
- OAuth2/OIDC understanding (documentation provided)
- Basic Keycloak administration (Barbican CLI simplifies)

---

## 16. Success Metrics

**Developer Experience**:
- Time to first OAuth2 flow: < 30 minutes
- Lines of config required: < 50 (in barbican.toml)
- Developer satisfaction: > 4.5/5

**Security Compliance**:
- FedRAMP control coverage: 100% (56 controls)
- FAPI 2.0 conformance: 100% pass rate
- Security audit findings: 0 critical, 0 high

**Operational Excellence**:
- Deployment success rate: > 99%
- Service uptime: > 99.9%
- MTTR (mean time to recovery): < 15 minutes

**Adoption**:
- Number of Barbican apps using Keycloak module: Target 50+ in year 1
- Community contributions: Target 10+ PRs in year 1

---

## 17. References

**Standards & Specifications**:
- NIST SP 800-53 Rev 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- NIST SP 800-63B (Digital Identity Guidelines): https://pages.nist.gov/800-63-3/sp800-63b.html
- OpenID FAPI 2.0 Security Profile: https://openid.net/specs/fapi-2_0-security-profile.html
- RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication): https://www.rfc-editor.org/rfc/rfc8705.html
- RFC 7636 (PKCE): https://www.rfc-editor.org/rfc/rfc7636.html
- RFC 9126 (PAR): https://www.rfc-editor.org/rfc/rfc9126.html

**Keycloak Documentation**:
- Keycloak Server Administration Guide: https://www.keycloak.org/docs/latest/server_admin/
- FAPI 2.0 Support in Keycloak: https://www.keycloak.org/docs/latest/securing_apps/#fapi-support

**Barbican Resources**:
- Barbican Repository: https://github.com/Sauce65/barbican
- NIST Control Research: `NIST_800_53_CONTROL_RESEARCH.md`
- Audit Guide: `docs/AUDIT_GUIDE.md`

---

## Appendix A: Example barbican.toml (Full)

```toml
[app]
name = "myapp"
profile = "fedramp-high"

[keycloak]
enable = true
deployment_mode = "dedicated"
hostname = "auth.myapp.com"
fips_mode = true

[keycloak.database]
host = "localhost"
name = "keycloak"
require_ssl = true
enable_client_cert = true

[keycloak.tls]
# Managed by Vault PKI
certificate_file = "/var/lib/vault-pki/keycloak-cert.pem"
key_file = "/var/lib/vault-pki/keycloak-key.pem"
ca_file = "/var/lib/vault-pki/ca-cert.pem"
enable_mtls = true

[keycloak.realm.myapp]
name = "myapp"
display_name = "My Application"
# Profile defaults applied (fedramp-high)

[keycloak.realm.myapp.overrides]
session_idle_timeout = 5  # Override to 5 min (stricter than default 10)

[keycloak.client.myapp-web]
realm = "myapp"
client_id = "myapp-web"
type = "public"
redirect_uris = ["https://myapp.com/auth/callback"]
enable_fapi = true
require_pkce = true

[keycloak.client.myapp-api]
realm = "myapp"
client_id = "myapp-api"
type = "confidential"
redirect_uris = ["https://api.myapp.com/auth/callback"]
enable_fapi = true
require_mtls = true
certificate_bound_tokens = true

[keycloak.observability]
enable = true
loki_endpoint = "http://localhost:3100"
otlp_endpoint = "http://localhost:4318"

[keycloak.admin]
username = "admin"
# password_file managed by age

[secrets]
backend = "age"
keycloak_admin_password = "age:secrets/keycloak-admin.age"
keycloak_db_password = "age:secrets/keycloak-db.age"
myapp_api_client_secret = "age:secrets/myapp-api-secret.age"
```

---

## Appendix B: Example NixOS Configuration

```nix
{ config, pkgs, lib, ... }:

{
  imports = [
    <barbican/modules/keycloak>
  ];

  barbican.keycloak = {
    enable = true;
    profile = "fedramp-high";
    deploymentMode = "dedicated";
    hostname = "auth.myapp.com";
    fipsMode = true;

    database = {
      passwordFile = config.age.secrets.keycloak-db-password.path;
      requireSSL = true;
      clientCertificateFile = "/var/lib/vault-pki/keycloak-db-client.pem";
    };

    tls = {
      certificateFile = config.barbican.vaultPki.certificates.keycloak.certPath;
      keyFile = config.barbican.vaultPki.certificates.keycloak.keyPath;
      caFile = config.barbican.vaultPki.caPath;
      enableMTLS = true;
    };

    realms.myapp = {
      name = "myapp";
      displayName = "My Application";
      # All settings inherited from fedramp-high profile
    };

    clients.myapp-web = {
      realm = "myapp";
      clientId = "myapp-web";
      type = "public";
      redirectUris = [ "https://myapp.com/auth/callback" ];
      enableFAPI = true;
      requirePKCE = true;
    };

    clients.myapp-api = {
      realm = "myapp";
      clientId = "myapp-api";
      type = "confidential";
      redirectUris = [ "https://api.myapp.com/auth/callback" ];
      enableFAPI = true;
      requireMTLS = true;
      certificateBoundTokens = true;
      clientSecretFile = config.age.secrets.myapp-api-secret.path;
    };

    adminUser = {
      username = "admin";
      passwordFile = config.age.secrets.keycloak-admin-password.path;
    };

    observability = {
      enable = true;
      lokiEndpoint = "http://localhost:3100";
      otlpEndpoint = "http://localhost:4318";
    };
  };

  # Firewall rules
  networking.firewall.allowedTCPPorts = [ 443 ];
}
```

---

**End of Design Document**

This design provides a comprehensive blueprint for implementing a production-ready, compliance-focused Keycloak deployment system within Barbican. The phased implementation approach allows for iterative development while ensuring each component is thoroughly tested and documented.
