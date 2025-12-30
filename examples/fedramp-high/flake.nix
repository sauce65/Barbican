{
  description = "FedRAMP High Example - Hello World with maximum security controls";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    # Import barbican from parent directory
    barbican.url = "path:../..";
    barbican.inputs.nixpkgs.follows = "nixpkgs";

    # Rust toolchain
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

    # Secret management
    agenix.url = "github:ryantm/agenix";
    agenix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, barbican, rust-overlay, agenix, ... }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          rust-overlay.overlays.default
          self.overlays.default
        ];
      };

      # Rust toolchain for building the application
      rustToolchain = pkgs.rust-bin.stable.latest.default;

      # =======================================================================
      # WORKAROUND: Local Path Dependency in Nix Sandbox
      # =======================================================================
      # This example uses `barbican = { path = "../.." }` in Cargo.toml to
      # reference the parent barbican crate. However, Nix builds packages in
      # an isolated sandbox where only the declared `src` is available.
      #
      # Solution: Use the full barbican repo as source, with sourceRoot pointing
      # to this example. The relative path "../.." then resolves correctly.
      #
      # FUTURE: When barbican is published to crates.io, change Cargo.toml to:
      #   barbican = { version = "0.1", features = ["postgres"] }
      # Then simplify this to just use `src = ./.` directly.
      # =======================================================================

    in
    {
      # Overlay that provides the hello-fedramp-high package
      overlays.default = final: prev:
        let
          # Use latest stable Rust from rust-overlay for edition2024 support
          rustPlatformLatest = prev.makeRustPlatform {
            cargo = final.rust-bin.stable.latest.default;
            rustc = final.rust-bin.stable.latest.default;
          };
        in {
        hello-fedramp-high = rustPlatformLatest.buildRustPackage {
          pname = "hello-fedramp-high";
          version = "0.1.0";

          # Use full barbican repo as source (see WORKAROUND comment above)
          # We copy to a new derivation to avoid flake input source handling issues
          src = final.runCommand "barbican-src" {} ''
            cp -r ${barbican} $out
            chmod -R u+w $out
          '';

          postUnpack = ''
            sourceRoot="$sourceRoot/examples/fedramp-high"
          '';

          cargoLock = {
            # Use the example's own Cargo.lock since it has [workspace] in Cargo.toml
            lockFile = ./Cargo.lock;
          };

          # Note: postgres feature is specified in Cargo.toml on the barbican dependency
          # No need for buildFeatures here

          nativeBuildInputs = with final; [ pkg-config ];
          buildInputs = with final; [ openssl ];

          meta = with final.lib; {
            description = "FedRAMP High baseline example application";
            license = licenses.mit;
          };
        };
      };

      # The application package
      packages.${system} = {
        default = pkgs.hello-fedramp-high;
        hello-fedramp-high = pkgs.hello-fedramp-high;
      };

      # Development shell
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          rustToolchain
          pkg-config
          openssl
          postgresql
        ];

        shellHook = ''
          echo "FedRAMP High Example Development Shell"
          echo "======================================="
          echo "Profile: FedRAMP High"
          echo "Controls: SC-8, SC-13, SC-28, AC-7, AC-11, AC-12, AU-2, AU-9, IA-2, IA-5"
          echo ""
          echo "Commands:"
          echo "  cargo run              - Run the application"
          echo "  cargo test             - Run tests"
          echo "  nix build              - Build the package"
          echo "  nix flake check        - Validate the flake"
        '';
      };

      # NixOS module for deploying this application
      nixosModules.default = { config, lib, pkgs, ... }: {
        imports = [
          # Import all barbican NixOS modules
          barbican.nixosModules.all

          # Import the generated configuration
          ./nix/generated/barbican.nix
        ];

        # Ensure our package is available
        nixpkgs.overlays = [ self.overlays.default ];
      };

      # Example NixOS configuration for a VM
      nixosConfigurations.fedramp-high-vm = nixpkgs.lib.nixosSystem {
        inherit system;

        modules = [
          # Barbican modules (all security modules)
          barbican.nixosModules.all

          # Agenix for secrets
          agenix.nixosModules.default

          # Our generated config
          ./nix/generated/barbican.nix

          # VM-specific configuration
          ({ config, pkgs, lib, ... }: {
            # Ensure our overlay is applied
            nixpkgs.overlays = [
              rust-overlay.overlays.default
              self.overlays.default
            ];

            # Basic system configuration
            system.stateVersion = "24.05";

            # Boot configuration for VM
            boot.loader.systemd-boot.enable = true;
            boot.loader.efi.canTouchEfiVariables = true;

            # Filesystem (for VM)
            fileSystems."/" = {
              device = "/dev/disk/by-label/nixos";
              fsType = "ext4";
            };

            # Networking
            networking = {
              hostName = "fedramp-high-example";
              firewall.enable = true;
              # Firewall rules are managed by barbican.vmFirewall
            };

            # PostgreSQL is configured by barbican.securePostgres
            # but we need to set up the secrets

            # Agenix identity configuration
            # In production, use SSH host keys or dedicated age keys
            age.identityPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];

            # Secrets configuration (you would replace these paths)
            age.secrets = {
              db-password = {
                file = ./secrets/db-password.age;
                owner = "postgres";
                group = "postgres";
              };
              # Name must match generated barbican.nix (uses snake_case)
              hello_fedramp_high-env = {
                file = ./secrets/app-env.age;
                owner = "root";
                group = "root";
              };
            };

            # Enable the application (already done in generated config)
            # The systemd service is defined in barbican.nix

            # Users
            users.users.root.initialPassword = "changeme";
          })
        ];
      };

      # Checks
      checks.${system} = {
        # Verify the package builds
        package = self.packages.${system}.default;

        # Verify the NixOS configuration is valid
        vm-config = self.nixosConfigurations.fedramp-high-vm.config.system.build.toplevel;
      };
    };
}
