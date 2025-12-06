# Barbican Minimal Security Profile
# For development and testing environments
# Provides basic security without impacting developer workflow
{ config, lib, ... }:

{
  imports = [
    ../modules/secure-users.nix
    ../modules/time-sync.nix
  ];

  barbican = {
    secureUsers = {
      enable = true;
      # Allow empty authorized keys in minimal profile
    };

    timeSync.enable = true;
  };

  # Basic firewall
  networking.firewall.enable = true;

  # Allow SSH for development access
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = lib.mkDefault true;  # Allow in dev
      PermitRootLogin = lib.mkDefault "yes";  # Allow in dev
    };
  };
}
