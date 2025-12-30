{
  description = "FedRAMP High baseline example - maximum database security";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    barbican.url = "path:../../..";
  };

  outputs = { self, nixpkgs, barbican }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};

    # Use Barbican's PKI library for certificate generation
    pkiLib = barbican.lib.pki;

    # Generate PKI setup script with both server and client certs for mTLS
    pkiSetupScript = pkiLib.mkPKISetupScript {
      name = "fedramp-high";
      servers = [{
        name = "postgres";
        commonName = "localhost";
        sans = [ "localhost" "127.0.0.1" ];
      }];
      # Client certificate for mTLS (IA-5(2))
      clients = [{
        name = "app-client";
        commonName = "fedramp-high-app";
      }];
      outputDir = ".";
    };
  in {
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        rustc cargo sqlx-cli postgresql_16 openssl pkg-config
      ];

      shellHook = ''
        export PGDATA="$PWD/.pgdata"
        export PGHOST="$PWD/.pgdata"
        export PGSSLMODE="require"
        export DATABASE_URL="postgres:///fedramp_high?host=$PGDATA&sslmode=require"
        export ENCRYPTION_KEY=$(openssl rand -hex 32)
        export AUDIT_SIGNING_KEY=$(openssl rand -hex 32)

        if [ ! -d "$PGDATA" ]; then
          echo "Initializing PostgreSQL..."
          initdb -D "$PGDATA" --no-locale --encoding=UTF8

          # Generate PKI using Barbican's PKI library (SC-8, SC-17, IA-5(2))
          echo "Generating PKI using Barbican (with mTLS support)..."
          mkdir -p "$PGDATA/certs"
          pushd "$PGDATA/certs" > /dev/null
          ${pkiSetupScript}
          popd > /dev/null

          # Copy server certs to PostgreSQL data directory
          cp "$PGDATA/certs/postgres.pem" "$PGDATA/server.crt"
          cp "$PGDATA/certs/postgres-key.pem" "$PGDATA/server.key"
          cp "$PGDATA/certs/fedramp-high-ca.pem" "$PGDATA/root.crt"
          chmod 600 "$PGDATA/server.key"

          # Configure PostgreSQL for TLS with strict settings (SC-8)
          cat >> "$PGDATA/postgresql.conf" << EOF
unix_socket_directories = '$PGDATA'
listen_addresses = '''
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'root.crt'
ssl_min_protocol_version = 'TLSv1.3'
ssl_ciphers = 'HIGH:!aNULL:!MD5:!3DES:!DES:!RC4:!SHA1'
EOF
        fi

        if ! pg_ctl status -D "$PGDATA" > /dev/null 2>&1; then
          pg_ctl start -D "$PGDATA" -l "$PGDATA/postgresql.log" -o "-k $PGDATA"
          sleep 1
        fi

        if ! psql -lqt | cut -d \| -f 1 | grep -qw fedramp_high; then
          createdb fedramp_high
        fi

        psql fedramp_high -f schema.sql 2>/dev/null || true

        # Verify TLS is working
        SSL_STATUS=$(psql -c "SHOW ssl" -t fedramp_high 2>/dev/null | tr -d ' ')
        TLS_VERSION=$(psql -c "SHOW ssl_min_protocol_version" -t fedramp_high 2>/dev/null | tr -d ' ')

        echo ""
        echo "FedRAMP HIGH Baseline Example"
        echo "=============================="
        echo "Controls: SC-8, SC-12, SC-13, SC-17, SC-28, AU-2/3/9, AC-3/6/11/12, IA-2, IA-5(2)"
        echo ""
        echo "DATABASE_URL=$DATABASE_URL"
        echo "ENCRYPTION_KEY=[generated]"
        echo "AUDIT_SIGNING_KEY=[generated]"
        echo "PostgreSQL TLS: $SSL_STATUS (min: $TLS_VERSION)"
        echo "PKI: Barbican-generated EC certificates (secp384r1)"
        echo "mTLS: Client cert available at $PGDATA/certs/app-client.pem"
        echo ""
        echo "Commands:"
        echo "  cargo run                    # Start server (non-FIPS)"
        echo "  cargo run --features fips    # Start server (FIPS mode)"
        echo ""
        echo "NOTE: Production FedRAMP High REQUIRES --features fips"
        echo ""
      '';
    };

    nixosModules.default = { config, lib, pkgs, ... }: {
      imports = [
        barbican.nixosModules.securePostgres
        barbican.nixosModules.databaseBackup
      ];

      barbican.securePostgres = {
        enable = true;
        database = "fedramp_high";
        username = "fedramp_high";

        # FedRAMP High: TLS required, mTLS preferred
        enableSSL = true;

        # Full audit logging with pgaudit
        enableAuditLog = true;
        enablePgaudit = true;

        # Maximum process isolation
        enableProcessIsolation = true;
      };

      # Encrypted backups with strict retention
      barbican.databaseBackup = {
        enable = true;
        databases = [ "fedramp_high" ];
        enableEncryption = true;
        retentionDays = 90;  # Longer retention for High
      };
    };
  };
}
