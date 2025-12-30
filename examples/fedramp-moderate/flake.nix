{
  description = "FedRAMP Moderate Example - Hello World with enhanced security controls";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    barbican.url = "path:../..";
    barbican.inputs.nixpkgs.follows = "nixpkgs";

    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

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
      overlays.default = final: prev:
        let
          # Use latest stable Rust from rust-overlay for edition2024 support
          rustPlatformLatest = prev.makeRustPlatform {
            cargo = final.rust-bin.stable.latest.default;
            rustc = final.rust-bin.stable.latest.default;
          };
        in {
        hello-fedramp-moderate = rustPlatformLatest.buildRustPackage {
          pname = "hello-fedramp-moderate";
          version = "0.1.0";

          # Use full barbican repo as source (see WORKAROUND comment above)
          src = final.runCommand "barbican-src" {} ''
            cp -r ${barbican} $out
            chmod -R u+w $out
          '';

          postUnpack = ''
            sourceRoot="$sourceRoot/examples/fedramp-moderate"
          '';

          cargoLock = {
            # Use the example's own Cargo.lock since it has [workspace] in Cargo.toml
            lockFile = ./Cargo.lock;
          };

          # Note: postgres feature is specified in Cargo.toml on the barbican dependency
          # No need for buildFeatures here

          nativeBuildInputs = with final; [ pkg-config ];
          buildInputs = with final; [ openssl ];
        };
      };

      packages.${system} = {
        default = pkgs.hello-fedramp-moderate;
        hello-fedramp-moderate = pkgs.hello-fedramp-moderate;
      };

      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          (rust-bin.stable.latest.default)
          pkg-config
          openssl
          postgresql
        ];
        shellHook = ''
          echo "FedRAMP Moderate Example - Development Shell"
          echo "Profile: FedRAMP Moderate (SERIOUS impact)"
        '';
      };

      nixosModules.default = { ... }: {
        imports = [
          barbican.nixosModules.all
          ./nix/generated/barbican.nix
        ];
        nixpkgs.overlays = [ self.overlays.default ];
      };

      nixosConfigurations.fedramp-moderate-vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          barbican.nixosModules.all
          agenix.nixosModules.default
          ./nix/generated/barbican.nix
          ({ config, pkgs, ... }: {
            nixpkgs.overlays = [ rust-overlay.overlays.default self.overlays.default ];
            system.stateVersion = "24.11";
            boot.loader.systemd-boot.enable = true;
            fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
            networking.hostName = "fedramp-moderate-example";

            age.identityPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];
            age.secrets = {
              db-password = { file = ./secrets/db-password.age; owner = "postgres"; };
              hello_fedramp_moderate-env = { file = ./secrets/app-env.age; };
            };

            users.users.root.initialPassword = "changeme";
          })
        ];
      };

      checks.${system} = {
        package = self.packages.${system}.default;
        vm-config = self.nixosConfigurations.fedramp-moderate-vm.config.system.build.toplevel;
      };
    };
}
