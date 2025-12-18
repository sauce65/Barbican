# Barbican Security Module: Secure PostgreSQL
# Addresses: CRT-003 (trust auth), CRT-011 (listen all), CRT-012 (no audit), CRT-013 (no TLS)
# Standards: NIST IA-5, SC-8, AU-2, CIS PostgreSQL
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.securePostgres;
in {
  options.barbican.securePostgres = {
    enable = mkEnableOption "Barbican secure PostgreSQL configuration";

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "IP address to listen on";
    };

    allowedClients = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "CIDR ranges allowed to connect";
      example = [ "10.0.100.6/32" ];
    };

    database = mkOption {
      type = types.str;
      description = "Database name to create";
    };

    username = mkOption {
      type = types.str;
      description = "Database username to create";
    };

    passwordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to file containing the database password";
    };

    enableSSL = mkOption {
      type = types.bool;
      default = true;
      description = "Enable SSL/TLS for connections";
    };

    sslCertFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to SSL certificate";
    };

    sslKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to SSL private key";
    };

    enableAuditLog = mkOption {
      type = types.bool;
      default = true;
      description = "Enable comprehensive audit logging";
    };

    maxConnections = mkOption {
      type = types.int;
      default = 50;
      description = "Maximum database connections";
    };

    statementTimeout = mkOption {
      type = types.int;
      default = 30000;
      description = "Statement timeout in milliseconds";
    };
  };

  config = mkIf cfg.enable {
    services.postgresql = {
      enable = true;
      package = pkgs.postgresql_16;
      enableTCPIP = true;

      # Secure authentication - NO trust, require scram-sha-256
      authentication = mkForce ''
        # Local postgres user for admin via peer
        local all postgres peer
        # Local connections require password
        local all all scram-sha-256
        # Network connections require SSL + password
        ${concatMapStringsSep "\n" (cidr:
          "hostssl all all ${cidr} scram-sha-256"
        ) cfg.allowedClients}
        # Reject everything else
        host all all 0.0.0.0/0 reject
        host all all ::/0 reject
      '';

      settings = {
        # Listen only on specified address (force override default)
        listen_addresses = mkForce "'${cfg.listenAddress}'";

        # Password encryption
        password_encryption = "scram-sha-256";

        # Connection limits
        max_connections = cfg.maxConnections;
        superuser_reserved_connections = 3;

        # Memory
        shared_buffers = "256MB";
        work_mem = "4MB";
        maintenance_work_mem = "64MB";

        # Query limits
        statement_timeout = cfg.statementTimeout;
        idle_in_transaction_session_timeout = 60000;

        # SSL/TLS
        ssl = cfg.enableSSL;
        ssl_min_protocol_version = "TLSv1.2";
        ssl_ciphers = "HIGH:!aNULL:!MD5:!3DES:!DES:!RC4";
      } // optionalAttrs (cfg.sslCertFile != null) {
        ssl_cert_file = cfg.sslCertFile;
      } // optionalAttrs (cfg.sslKeyFile != null) {
        ssl_key_file = cfg.sslKeyFile;
      } // optionalAttrs cfg.enableAuditLog {
        # Audit logging
        logging_collector = true;
        log_destination = "stderr";
        log_directory = "pg_log";
        log_filename = "postgresql-%Y-%m-%d.log";
        log_rotation_age = "1d";
        log_rotation_size = "100MB";

        log_connections = true;
        log_disconnections = true;
        log_statement = "all";
        log_duration = true;
        log_line_prefix = "%t [%p]: user=%u,db=%d,app=%a,client=%h ";

        log_checkpoints = true;
        log_lock_waits = true;
        log_temp_files = 0;
      };

      # Initial database setup (password set via secret)
      initialScript = pkgs.writeText "init.sql" ''
        CREATE DATABASE ${cfg.database};
        CREATE USER ${cfg.username};
        GRANT ALL PRIVILEGES ON DATABASE ${cfg.database} TO ${cfg.username};
        ALTER DATABASE ${cfg.database} OWNER TO ${cfg.username};
      '';
    };

    # Set password from file if provided
    systemd.services.postgresql-set-password = mkIf (cfg.passwordFile != null) {
      description = "Set PostgreSQL password from secret";
      after = [ "postgresql.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        User = "postgres";
        RemainAfterExit = true;
      };
      script = ''
        PASSWORD=$(cat ${cfg.passwordFile})
        ${pkgs.postgresql_16}/bin/psql -c "ALTER USER ${cfg.username} WITH PASSWORD '$PASSWORD';"
      '';
    };

    # Firewall rules
    networking.firewall.allowedTCPPorts = [ 5432 ];
  };
}
