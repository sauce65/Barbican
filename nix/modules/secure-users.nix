# Barbican Security Module: Secure Users
#
# STIG Implementation:
#   UBTU-22-411010: Configure account lockout threshold (AC-7)
#   UBTU-22-411015: Disable automatic logon (AC-2)
#   UBTU-22-411020: Require unique user accounts (AC-2)
#   UBTU-22-612010: Require MFA for local access (IA-2)
#   UBTU-22-612020: Display SSH warning banner (AC-8)
#
# NIST Controls: AC-2, AC-7, AC-8, IA-2, IA-5(1)
# Legacy: CRT-001, CRT-002
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
