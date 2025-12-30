{
  description = "FedRAMP Moderate baseline example - enhanced database security";

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
        export DATABASE_URL="postgres:///fedramp_moderate?host=$PGDATA"
        export ENCRYPTION_KEY=$(openssl rand -hex 32)

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

        if ! psql -lqt | cut -d \| -f 1 | grep -qw fedramp_moderate; then
          createdb fedramp_moderate
        fi

        psql fedramp_moderate -f schema.sql 2>/dev/null || true

        echo ""
        echo "FedRAMP MODERATE Baseline Example"
        echo "=================================="
        echo "Controls: SC-8, SC-28, AU-2/3/9, AC-3/6/11/12"
        echo ""
        echo "DATABASE_URL=$DATABASE_URL"
        echo "ENCRYPTION_KEY=[generated]"
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
