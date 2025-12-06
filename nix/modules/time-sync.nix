# Barbican Security Module: Time Synchronization
# Addresses: HIGH-011 (no time synchronization)
# Standards: NIST AU-8, CIS 2.2.1.x
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.timeSync;
in {
  options.barbican.timeSync = {
    enable = mkEnableOption "Barbican time synchronization";

    servers = mkOption {
      type = types.listOf types.str;
      default = [
        "time.cloudflare.com"
        "time.google.com"
        "time.nist.gov"
      ];
      description = "NTP servers to use";
    };

    minPoll = mkOption {
      type = types.int;
      default = 4;
      description = "Minimum polling interval (2^n seconds)";
    };

    maxPoll = mkOption {
      type = types.int;
      default = 8;
      description = "Maximum polling interval (2^n seconds)";
    };
  };

  config = mkIf cfg.enable {
    # Disable systemd-timesyncd in favor of chrony
    services.timesyncd.enable = false;

    services.chrony = {
      enable = true;
      servers = cfg.servers;

      extraConfig = ''
        # Minimum and maximum polling intervals
        minpoll ${toString cfg.minPoll}
        maxpoll ${toString cfg.maxPoll}

        # Allow only local management
        cmdallow 127.0.0.1
        cmdallow ::1

        # Log clock changes
        log tracking measurements statistics

        # Make first sync faster
        makestep 1.0 3

        # Enable RTC sync
        rtcsync
      '';
    };

    # Set timezone explicitly
    time.timeZone = mkDefault "UTC";
  };
}
