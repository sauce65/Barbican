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
    in
    {
      overlays.default = final: prev: {
        hello-fedramp-moderate = final.rustPlatform.buildRustPackage {
          pname = "hello-fedramp-moderate";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          buildFeatures = [ "postgres" ];
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
