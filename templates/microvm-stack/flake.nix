{
  description = "Secure MicroVM stack with Barbican hardening";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    barbican.url = "github:your-org/barbican";
    microvm.url = "github:astro/microvm.nix";
  };

  outputs = { self, nixpkgs, barbican, microvm, ... }: {
    nixosConfigurations.microvm = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        microvm.nixosModules.microvm
        barbican.nixosModules.hardened
        {
          microvm = {
            hypervisor = "qemu";
            mem = 512;
            vcpu = 1;
          };

          # Apply Barbican security profile
          barbican.secureUsers.enable = true;
          barbican.hardenedSSH.enable = true;
          barbican.kernelHardening.enable = true;
          barbican.resourceLimits.enable = true;

          system.stateVersion = "24.11";
        }
      ];
    };
  };
}
