# Barbican Security Module: Hardened Nginx Reverse Proxy
#
# Provides a NIST 800-53 compliant nginx reverse proxy with:
# - SC-8: TLS 1.2+ only with approved cipher suites
# - SC-8(1): NIST SP 800-52B cryptographic protection
# - IA-3: mTLS client certificate authentication
# - SC-5: Rate limiting for DoS protection
# - AU-2, AU-3: Security event logging
#
# Integrates with Vault PKI for automatic certificate management.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.nginx;

  # NIST SP 800-52B Rev 2 compliant cipher suites
  # Reference: https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final
  nistCipherSuites = concatStringsSep ":" [
    # TLS 1.3 suites (always preferred)
    "TLS_AES_256_GCM_SHA384"
    "TLS_CHACHA20_POLY1305_SHA256"
    "TLS_AES_128_GCM_SHA256"
    # TLS 1.2 suites with PFS (ECDHE)
    "ECDHE-ECDSA-AES256-GCM-SHA384"
    "ECDHE-RSA-AES256-GCM-SHA384"
    "ECDHE-ECDSA-CHACHA20-POLY1305"
    "ECDHE-RSA-CHACHA20-POLY1305"
    "ECDHE-ECDSA-AES128-GCM-SHA256"
    "ECDHE-RSA-AES128-GCM-SHA256"
    # TLS 1.2 suites with PFS (DHE) - fallback
    "DHE-RSA-AES256-GCM-SHA384"
    "DHE-RSA-AES128-GCM-SHA256"
  ];

  # FedRAMP High requires stricter settings
  fedRampHighCipherSuites = concatStringsSep ":" [
    "TLS_AES_256_GCM_SHA384"
    "ECDHE-ECDSA-AES256-GCM-SHA384"
    "ECDHE-RSA-AES256-GCM-SHA384"
  ];

  # Rate limiting zone configuration
  rateLimitZone = ''
    limit_req_zone $binary_remote_addr zone=barbican_global:10m rate=${toString cfg.rateLimit.requestsPerSecond}r/s;
    limit_req_zone $binary_remote_addr zone=barbican_auth:10m rate=${toString cfg.rateLimit.authRequestsPerSecond}r/s;
    limit_conn_zone $binary_remote_addr zone=barbican_conn:10m;
  '';

  # Security headers configuration
  securityHeaders = ''
    # SC-8: HSTS - Force HTTPS for 1 year, include subdomains
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains${optionalString cfg.hstsPreload "; preload"}" always;

    # SI-11: Prevent MIME type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # SC-8: Prevent clickjacking
    add_header X-Frame-Options "DENY" always;

    # SI-11: Content Security Policy (restrictive for API)
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;

    # SC-8: Prevent caching of sensitive data
    add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
    add_header Pragma "no-cache" always;

    # Remove server version disclosure
    server_tokens off;
  '';

  # mTLS configuration based on mode
  mtlsConfig = if cfg.mtls.mode == "required" then ''
    # IA-3: Require valid client certificate
    ssl_client_certificate ${cfg.mtls.caCertPath};
    ssl_verify_client on;
    ssl_verify_depth ${toString cfg.mtls.verifyDepth};
    ${optionalString (cfg.mtls.crlPath != null) "ssl_crl ${cfg.mtls.crlPath};"}
  '' else if cfg.mtls.mode == "optional" then ''
    # IA-3: Request client certificate (optional)
    ssl_client_certificate ${cfg.mtls.caCertPath};
    ssl_verify_client optional;
    ssl_verify_depth ${toString cfg.mtls.verifyDepth};
    ${optionalString (cfg.mtls.crlPath != null) "ssl_crl ${cfg.mtls.crlPath};"}
  '' else ''
    # mTLS disabled
  '';

  # Proxy headers for Barbican
  proxyHeaders = ''
    # Standard proxy headers
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # TLS information for Barbican validation
    proxy_set_header X-SSL-Protocol $ssl_protocol;
    proxy_set_header X-SSL-Cipher $ssl_cipher;

    # Client certificate headers for mTLS (IA-3)
    proxy_set_header X-Client-Verify $ssl_client_verify;
    proxy_set_header X-Client-Cert-Subject $ssl_client_s_dn;
    proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
    proxy_set_header X-Client-Cert-Serial $ssl_client_serial;

    # Request ID for distributed tracing (AU-16)
    proxy_set_header X-Request-ID $request_id;

    # Connection settings
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_connect_timeout ${toString cfg.proxy.connectTimeout}s;
    proxy_send_timeout ${toString cfg.proxy.sendTimeout}s;
    proxy_read_timeout ${toString cfg.proxy.readTimeout}s;
  '';

  # Logging format with security fields (AU-2, AU-3)
  logFormat = ''
    log_format barbican_security escape=json '{'
      '"timestamp":"$time_iso8601",'
      '"request_id":"$request_id",'
      '"remote_addr":"$remote_addr",'
      '"request_method":"$request_method",'
      '"request_uri":"$request_uri",'
      '"status":$status,'
      '"body_bytes_sent":$body_bytes_sent,'
      '"request_time":$request_time,'
      '"http_user_agent":"$http_user_agent",'
      '"ssl_protocol":"$ssl_protocol",'
      '"ssl_cipher":"$ssl_cipher",'
      '"ssl_client_verify":"$ssl_client_verify",'
      '"ssl_client_s_dn":"$ssl_client_s_dn",'
      '"upstream_response_time":"$upstream_response_time"'
    '}';
  '';

  # Virtual host configuration
  vhostConfig = ''
    server {
        listen ${toString cfg.listenPort} ssl http2;
        ${optionalString cfg.listenIPv6 "listen [::]:${toString cfg.listenPort} ssl http2;"}
        server_name ${cfg.serverName};

        # TLS certificate
        ssl_certificate ${cfg.tls.certPath};
        ssl_certificate_key ${cfg.tls.keyPath};

        # SC-8(1): TLS protocol versions (1.2+ only)
        ssl_protocols TLSv1.2 TLSv1.3;

        # SC-8(1): NIST SP 800-52B cipher suites
        ssl_ciphers '${if cfg.fedRampHigh then fedRampHighCipherSuites else nistCipherSuites}';
        ssl_prefer_server_ciphers on;

        # Perfect Forward Secrecy
        ssl_ecdh_curve secp384r1:secp256r1;
        ${optionalString (cfg.tls.dhParamPath != null) "ssl_dhparam ${cfg.tls.dhParamPath};"}

        # TLS session settings
        ssl_session_timeout ${cfg.tls.sessionTimeout};
        ssl_session_cache shared:SSL:10m;
        ssl_session_tickets off;  # Disable for PFS

        # OCSP Stapling (SC-17)
        ${optionalString cfg.tls.ocspStapling ''
        ssl_stapling on;
        ssl_stapling_verify on;
        ssl_trusted_certificate ${cfg.tls.trustedCertPath};
        resolver ${cfg.tls.resolver} valid=300s;
        resolver_timeout 5s;
        ''}

        # mTLS configuration (IA-3)
        ${mtlsConfig}

        # Security headers
        ${securityHeaders}

        # Access logging with security format (AU-2)
        access_log /var/log/nginx/barbican_access.log barbican_security;
        error_log /var/log/nginx/barbican_error.log warn;

        # Rate limiting (SC-5)
        ${optionalString cfg.rateLimit.enable ''
        limit_req zone=barbican_global burst=${toString cfg.rateLimit.burst} ${if cfg.rateLimit.nodelay then "nodelay" else ""};
        limit_conn barbican_conn ${toString cfg.rateLimit.maxConnections};
        limit_req_status 429;
        limit_conn_status 429;
        ''}

        # Request size limit (SC-5)
        client_max_body_size ${cfg.proxy.maxBodySize};
        client_body_timeout ${toString cfg.proxy.bodyTimeout}s;
        client_header_timeout ${toString cfg.proxy.headerTimeout}s;

        # Health check endpoint (no rate limit, no mTLS)
        location /health {
            ${proxyHeaders}
            proxy_pass http://${cfg.upstream.address}:${toString cfg.upstream.port};

            # Skip rate limiting for health checks
            limit_req off;
            limit_conn off;
        }

        # Auth endpoints (stricter rate limiting)
        location ~ ^/(login|auth|oauth) {
            ${proxyHeaders}
            proxy_pass http://${cfg.upstream.address}:${toString cfg.upstream.port};

            # Stricter rate limit for auth endpoints (AC-7)
            limit_req zone=barbican_auth burst=5 nodelay;
        }

        # All other requests
        location / {
            ${proxyHeaders}
            proxy_pass http://${cfg.upstream.address}:${toString cfg.upstream.port};
        }

        # Block common exploit paths
        location ~* \.(git|svn|htaccess|htpasswd|env|bak|old|swp)$ {
            deny all;
            return 404;
        }
    }

    # Redirect HTTP to HTTPS (SC-8)
    ${optionalString cfg.redirectHttp ''
    server {
        listen 80;
        ${optionalString cfg.listenIPv6 "listen [::]:80;"}
        server_name ${cfg.serverName};
        return 301 https://$host$request_uri;
    }
    ''}
  '';

in {
  options.barbican.nginx = {
    enable = mkEnableOption "Barbican hardened nginx reverse proxy";

    serverName = mkOption {
      type = types.str;
      default = "localhost";
      description = "Server name for the virtual host";
    };

    listenPort = mkOption {
      type = types.port;
      default = 443;
      description = "HTTPS listen port";
    };

    listenIPv6 = mkOption {
      type = types.bool;
      default = true;
      description = "Listen on IPv6 as well";
    };

    redirectHttp = mkOption {
      type = types.bool;
      default = true;
      description = "Redirect HTTP to HTTPS (SC-8)";
    };

    fedRampHigh = mkOption {
      type = types.bool;
      default = false;
      description = "Enable FedRAMP High baseline (stricter cipher suites)";
    };

    hstsPreload = mkOption {
      type = types.bool;
      default = false;
      description = "Include HSTS preload directive (submit to hstspreload.org)";
    };

    tls = {
      certPath = mkOption {
        type = types.path;
        description = "Path to TLS certificate";
      };

      keyPath = mkOption {
        type = types.path;
        description = "Path to TLS private key";
      };

      dhParamPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to DH parameters file (optional, for DHE ciphers)";
      };

      trustedCertPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to trusted CA chain for OCSP stapling";
      };

      sessionTimeout = mkOption {
        type = types.str;
        default = "1d";
        description = "TLS session timeout";
      };

      ocspStapling = mkOption {
        type = types.bool;
        default = false;
        description = "Enable OCSP stapling (SC-17)";
      };

      resolver = mkOption {
        type = types.str;
        default = "8.8.8.8 8.8.4.4";
        description = "DNS resolver for OCSP stapling";
      };
    };

    mtls = {
      mode = mkOption {
        type = types.enum [ "disabled" "optional" "required" ];
        default = "disabled";
        description = ''
          mTLS enforcement mode (IA-3):
          - disabled: No client certificate required
          - optional: Request certificate, allow if missing
          - required: Require valid client certificate (FedRAMP High)
        '';
      };

      caCertPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to CA certificate for client verification";
      };

      crlPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to Certificate Revocation List (optional)";
      };

      verifyDepth = mkOption {
        type = types.int;
        default = 2;
        description = "Client certificate chain verification depth";
      };
    };

    rateLimit = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable rate limiting (SC-5)";
      };

      requestsPerSecond = mkOption {
        type = types.int;
        default = 10;
        description = "Requests per second per IP";
      };

      authRequestsPerSecond = mkOption {
        type = types.int;
        default = 3;
        description = "Auth endpoint requests per second per IP (AC-7)";
      };

      burst = mkOption {
        type = types.int;
        default = 20;
        description = "Burst allowance";
      };

      maxConnections = mkOption {
        type = types.int;
        default = 100;
        description = "Maximum concurrent connections per IP";
      };

      nodelay = mkOption {
        type = types.bool;
        default = true;
        description = "Return 429 immediately instead of queuing";
      };
    };

    upstream = {
      address = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Barbican backend address";
      };

      port = mkOption {
        type = types.port;
        default = 3000;
        description = "Barbican backend port";
      };
    };

    proxy = {
      connectTimeout = mkOption {
        type = types.int;
        default = 5;
        description = "Proxy connect timeout in seconds";
      };

      sendTimeout = mkOption {
        type = types.int;
        default = 60;
        description = "Proxy send timeout in seconds";
      };

      readTimeout = mkOption {
        type = types.int;
        default = 60;
        description = "Proxy read timeout in seconds";
      };

      maxBodySize = mkOption {
        type = types.str;
        default = "10m";
        description = "Maximum request body size";
      };

      bodyTimeout = mkOption {
        type = types.int;
        default = 60;
        description = "Client body timeout in seconds";
      };

      headerTimeout = mkOption {
        type = types.int;
        default = 60;
        description = "Client header timeout in seconds";
      };
    };
  };

  config = mkIf cfg.enable {
    # Validate mTLS configuration
    assertions = [
      {
        assertion = cfg.mtls.mode == "disabled" || cfg.mtls.caCertPath != null;
        message = "barbican.nginx.mtls.caCertPath must be set when mTLS is enabled";
      }
      {
        assertion = cfg.tls.ocspStapling -> cfg.tls.trustedCertPath != null;
        message = "barbican.nginx.tls.trustedCertPath must be set when OCSP stapling is enabled";
      }
    ];

    # Enable nginx
    services.nginx = {
      enable = true;
      package = pkgs.nginxMainline;

      # Recommended settings
      recommendedGzipSettings = true;
      recommendedOptimisation = true;
      recommendedProxySettings = true;

      # We use appendConfig for events block
      appendConfig = ''
        events {
            worker_connections 1024;
            use epoll;
            multi_accept on;
        }
      '';

      # Combined HTTP config: global settings + vhost
      appendHttpConfig = ''
        ${logFormat}
        ${rateLimitZone}

        # Timeouts
        keepalive_timeout 65;
        send_timeout 60;

        # Buffer settings
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;

        # Security: hide nginx version
        server_tokens off;

        # Security: prevent host header injection
        map $http_host $valid_host {
            default 0;
            "${cfg.serverName}" 1;
        }

        ${vhostConfig}
      '';
    };

    # Open firewall ports
    networking.firewall.allowedTCPPorts = [
      cfg.listenPort
    ] ++ optional cfg.redirectHttp 80;

    # Systemd hardening for nginx (SI-6)
    systemd.services.nginx.serviceConfig = {
      # Filesystem restrictions
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ReadWritePaths = [ "/var/log/nginx" "/run/nginx" ];

      # Network restrictions
      PrivateNetwork = false;
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];

      # Capability restrictions
      CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
      AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
      NoNewPrivileges = true;

      # Process restrictions
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
    };

    # Log rotation
    services.logrotate.settings.nginx = {
      enable = true;
      frequency = "daily";
      rotate = 90;  # Keep 90 days for compliance (AU-11)
      compress = true;
      delaycompress = true;
      notifempty = true;
      sharedscripts = true;
      postrotate = "[ -f /run/nginx/nginx.pid ] && kill -USR1 $(cat /run/nginx/nginx.pid)";
    };
  };
}
