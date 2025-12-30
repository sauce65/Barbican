{
  description = "FedRAMP High baseline example - maximum database security";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    barbican.url = "path:../../..";
  };

  outputs = { self, nixpkgs, barbican }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in {
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        rustc cargo sqlx-cli postgresql_16 openssl pkg-config
      ];

      shellHook = ''
        export PGDATA="$PWD/.pgdata"
        export PGHOST="$PWD/.pgdata"
        export DATABASE_URL="postgres:///fedramp_high?host=$PGDATA"
        export ENCRYPTION_KEY=$(openssl rand -hex 32)
        export AUDIT_SIGNING_KEY=$(openssl rand -hex 32)

        if [ ! -d "$PGDATA" ]; then
          echo "Initializing PostgreSQL..."
          initdb -D "$PGDATA" --no-locale --encoding=UTF8
          echo "unix_socket_directories = '$PGDATA'" >> "$PGDATA/postgresql.conf"
          echo "listen_addresses = '''" >> "$PGDATA/postgresql.conf"
        fi

        if ! pg_ctl status -D "$PGDATA" > /dev/null 2>&1; then
          pg_ctl start -D "$PGDATA" -l "$PGDATA/postgresql.log" -o "-k $PGDATA"
          sleep 1
        fi

        if ! psql -lqt | cut -d \| -f 1 | grep -qw fedramp_high; then
          createdb fedramp_high
        fi

        psql fedramp_high -f schema.sql 2>/dev/null || true

        echo ""
        echo "FedRAMP HIGH Baseline Example"
        echo "=============================="
        echo "Controls: SC-8, SC-12, SC-13, SC-28, AU-2/3/9, AC-3/6/11/12, IA-2"
        echo ""
        echo "DATABASE_URL=$DATABASE_URL"
        echo "ENCRYPTION_KEY=[generated]"
        echo "AUDIT_SIGNING_KEY=[generated]"
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
