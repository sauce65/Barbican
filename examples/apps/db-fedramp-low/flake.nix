{
  description = "FedRAMP Low baseline example - basic database security";

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
        export DATABASE_URL="postgres:///fedramp_low?host=$PGDATA"

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

        if ! psql -lqt | cut -d \| -f 1 | grep -qw fedramp_low; then
          createdb fedramp_low
        fi

        psql fedramp_low -f schema.sql 2>/dev/null || true

        echo ""
        echo "FedRAMP LOW Baseline Example"
        echo "============================"
        echo "Controls: SC-8 (TLS), SC-28 (infra), AU-2/AU-3 (audit)"
        echo ""
        echo "DATABASE_URL=$DATABASE_URL"
        echo ""
        echo "Commands:"
        echo "  cargo run    # Start server on :3000"
        echo ""
      '';
    };

    nixosModules.default = { config, lib, pkgs, ... }: {
      imports = [ barbican.nixosModules.securePostgres ];

      barbican.securePostgres = {
        enable = true;
        database = "fedramp_low";
        username = "fedramp_low";

        # FedRAMP Low: TLS preferred but not required
        enableSSL = true;

        # Basic audit logging
        enableAuditLog = true;
        enablePgaudit = false;  # Not required at Low

        # Standard isolation
        enableProcessIsolation = true;
      };
    };
  };
}
