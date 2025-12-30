{
  description = "FedRAMP Moderate baseline example - enhanced database security";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    barbican.url = "path:../../..";
  };

  outputs = { self, nixpkgs, barbican }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};

    # Use Barbican's PKI library for certificate generation
    pkiLib = barbican.lib.pki;

    # Generate PKI setup script using Barbican's helpers
    pkiSetupScript = pkiLib.mkPKISetupScript {
      name = "fedramp-moderate";
      servers = [{
        name = "postgres";
        commonName = "localhost";
        sans = [ "localhost" "127.0.0.1" ];
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
        export PGHOST="localhost"
        export PGPORT="5432"
        export PGSSLMODE="require"
        export PGSSLROOTCERT="$PGDATA/certs/fedramp-moderate-ca.pem"
        export DATABASE_URL="postgres://localhost:5432/fedramp_moderate?sslmode=require&sslrootcert=$PGDATA/certs/fedramp-moderate-ca.pem"
        export ENCRYPTION_KEY=$(openssl rand -hex 32)

        if [ ! -d "$PGDATA" ]; then
          echo "Initializing PostgreSQL..."
          initdb -D "$PGDATA" --no-locale --encoding=UTF8

          # Generate PKI using Barbican's PKI library (SC-8, SC-17)
          echo "Generating PKI using Barbican..."
          mkdir -p "$PGDATA/certs"
          pushd "$PGDATA/certs" > /dev/null
          ${pkiSetupScript}
          popd > /dev/null

          # Copy certs to PostgreSQL data directory
          cp "$PGDATA/certs/postgres.pem" "$PGDATA/server.crt"
          cp "$PGDATA/certs/postgres-key.pem" "$PGDATA/server.key"
          cp "$PGDATA/certs/fedramp-moderate-ca.pem" "$PGDATA/root.crt"
          chmod 600 "$PGDATA/server.key"

          # Configure PostgreSQL for TLS (SC-8) - TCP with TLS
          cat >> "$PGDATA/postgresql.conf" << EOF
listen_addresses = 'localhost'
port = 5432
unix_socket_directories = '$PGDATA'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'root.crt'
ssl_min_protocol_version = 'TLSv1.2'
ssl_ciphers = 'HIGH:!aNULL:!MD5:!3DES:!DES:!RC4'
EOF
          # Configure pg_hba.conf to require SSL for TCP connections
          cat > "$PGDATA/pg_hba.conf" << EOF
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust
hostssl all             all             127.0.0.1/32            trust
hostssl all             all             ::1/128                 trust
EOF
        fi

        if ! pg_ctl status -D "$PGDATA" > /dev/null 2>&1; then
          pg_ctl start -D "$PGDATA" -l "$PGDATA/postgresql.log"
          sleep 1
        fi

        if ! psql -h localhost -lqt | cut -d \| -f 1 | grep -qw fedramp_moderate; then
          createdb -h localhost fedramp_moderate
        fi

        psql -h localhost fedramp_moderate -f schema.sql 2>/dev/null || true

        # Verify TLS is working
        SSL_STATUS=$(psql -h localhost -c "SHOW ssl" -t fedramp_moderate 2>/dev/null | tr -d ' ')

        echo ""
        echo "FedRAMP MODERATE Baseline Example"
        echo "=================================="
        echo "Controls: SC-8 (TLS), SC-17 (PKI), SC-28, AU-2/3/9, AC-3/6/11/12"
        echo ""
        echo "DATABASE_URL=$DATABASE_URL"
        echo "ENCRYPTION_KEY=[generated]"
        echo "PostgreSQL TLS: $SSL_STATUS"
        echo "PKI: Barbican-generated EC certificates (secp384r1)"
        echo ""
        echo "Commands:"
        echo "  cargo run    # Start server on :3000"
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
        database = "fedramp_moderate";
        username = "fedramp_moderate";

        # FedRAMP Moderate: TLS required
        enableSSL = true;

        # Comprehensive audit logging
        enableAuditLog = true;
        enablePgaudit = true;

        # Process isolation
        enableProcessIsolation = true;
      };

      # Encrypted backups (CP-9)
      barbican.databaseBackup = {
        enable = true;
        databases = [ "fedramp_moderate" ];
        enableEncryption = true;
        retentionDays = 30;
      };
    };
  };
}
