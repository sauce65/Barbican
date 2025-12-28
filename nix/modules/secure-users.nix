# Barbican Security Module: Secure Users
# Addresses: CRT-001 (empty root password), CRT-002 (auto-login)
# Standards: NIST AC-2, IA-5(1), CIS 5.4.1
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.secureUsers;
in {
  options.barbican.secureUsers = {
    enable = mkEnableOption "Barbican secure user configuration";

    authorizedKeys = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "SSH public keys for root access";
      example = [ "ssh-ed25519 AAAAC3... admin@example.com" ];
    };

    allowPasswordAuth = mkOption {
      type = types.bool;
      default = false;
      description = "Allow password authentication (not recommended)";
    };

    loginBanner = mkOption {
      type = types.str;
      default = ''
        ******************************************
        AUTHORIZED ACCESS ONLY
        All activities are monitored and logged.
        ******************************************
      '';
      description = "Login banner for SSH and console";
    };
  };

  config = mkIf cfg.enable {
    # Lock root password - require SSH keys only
    users.users.root = {
      # Lock password login (! means locked)
      # Use mkForce to override any hashedPasswordFile from test framework
      hashedPassword = mkForce "!";
      hashedPasswordFile = mkForce null;
      password = mkForce null;
      # Set up SSH key auth
      openssh.authorizedKeys.keys = cfg.authorizedKeys;
    };

    # Disable auto-login
    services.getty = {
      autologinUser = mkForce null;
      helpLine = cfg.loginBanner;
    };

    # Add legal banner
    environment.etc."issue".text = cfg.loginBanner;
    environment.etc."issue.net".text = cfg.loginBanner;
  };
}
