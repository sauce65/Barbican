{
  description = "db-minimal: Secure PostgreSQL example using Barbican";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Use local path for development
    barbican.url = "path:../../..";
    # For published usage:
    # barbican.url = "github:sauce65/Barbican";
  };

  outputs = { self, nixpkgs, barbican }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in {
    # Development shell with database available
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        rustc
        cargo
        sqlx-cli
        postgresql_16
        openssl
        pkg-config
      ];

      shellHook = ''
        # Set up local PostgreSQL for development
        export PGDATA="$PWD/.pgdata"
        export PGHOST="$PWD/.pgdata"
        export DATABASE_URL="postgres:///dbminimal?host=$PGDATA"

        if [ ! -d "$PGDATA" ]; then
          echo "Initializing PostgreSQL..."
          initdb -D "$PGDATA" --no-locale --encoding=UTF8
          echo "unix_socket_directories = '$PGDATA'" >> "$PGDATA/postgresql.conf"
          echo "listen_addresses = '''" >> "$PGDATA/postgresql.conf"
        fi

        # Start PostgreSQL if not running
        if ! pg_ctl status -D "$PGDATA" > /dev/null 2>&1; then
          pg_ctl start -D "$PGDATA" -l "$PGDATA/postgresql.log" -o "-k $PGDATA"
          sleep 1
        fi

        # Create database if it doesn't exist
        if ! psql -lqt | cut -d \| -f 1 | grep -qw dbminimal; then
          createdb dbminimal
          echo "Created database 'dbminimal'"
        fi

        # Apply schema
        psql dbminimal -f schema.sql 2>/dev/null || true

        echo ""
        echo "PostgreSQL ready!"
        echo "  DATABASE_URL=$DATABASE_URL"
        echo ""
        echo "Commands:"
        echo "  cargo build          # Compile with query checking"
        echo "  cargo run            # Run the application"
        echo "  cargo sqlx prepare   # Generate offline query cache"
        echo "  psql dbminimal       # Connect to database"
        echo ""
      '';
    };

    # NixOS module for production deployment
    nixosModules.default = { config, lib, pkgs, ... }: {
      imports = [
        barbican.nixosModules.securePostgres
        barbican.nixosModules.databaseBackup
      ];

      # Enable Barbican's secure PostgreSQL
      barbican.securePostgres = {
        enable = true;
        database = "dbminimal";
        username = "dbminimal";
        listenAddress = "127.0.0.1";
        allowedClients = [ "127.0.0.1/32" ];

        # Security settings (SC-8, SC-28)
        enableSSL = true;
        enableAuditLog = true;
        enablePgaudit = true;

        # Process isolation (SC-39)
        enableProcessIsolation = true;
      };

      # Enable encrypted backups (CP-9, MP-5)
      barbican.databaseBackup = {
        enable = true;
        databases = [ "dbminimal" ];
        enableEncryption = true;
        retentionDays = 30;
      };
    };

    # Container/VM for testing
    nixosConfigurations.db-minimal-vm = nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        self.nixosModules.default
        ({ pkgs, ... }: {
          # VM configuration
          virtualisation.vmVariant = {
            virtualisation.memorySize = 2048;
            virtualisation.forwardPorts = [
              { from = "host"; host.port = 3000; guest.port = 3000; }
              { from = "host"; host.port = 5432; guest.port = 5432; }
            ];
          };

          # For development, allow local connections without SSL
          barbican.securePostgres.enableSSL = false;

          # System packages
          environment.systemPackages = with pkgs; [
            postgresql_16
          ];

          # Basic system config
          system.stateVersion = "24.05";
        })
      ];
    };
  };
}
