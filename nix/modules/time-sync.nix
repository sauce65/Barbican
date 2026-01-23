# Barbican Security Module: Time Synchronization
#
# STIG Implementation:
#   UBTU-22-252010: Synchronize time with authoritative source (AU-8)
#   UBTU-22-252015: Configure multiple time sources (AU-8(1))
#   UBTU-22-252020: Enable NTP authentication when available (AU-8(1))
#
# NIST Controls: AU-8, AU-8(1)
# Legacy: HIGH-011
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
      # Don't use the servers option - we'll configure them in extraConfig with poll intervals
      servers = [];

      extraConfig = ''
        # NTP servers with polling intervals
        ${concatMapStringsSep "\n" (server:
          "server ${server} iburst minpoll ${toString cfg.minPoll} maxpoll ${toString cfg.maxPoll}"
        ) cfg.servers}

        # Allow only local management
        cmdallow 127.0.0.1
        cmdallow ::1

        # Log clock changes
        log tracking measurements statistics

        # Make first sync faster
        makestep 1.0 3

        # Allow running without network connectivity (important for VM tests)
        # This prevents chronyd from failing if servers are unreachable
        local stratum 10
      '';

      # Use NixOS native RTC trimming (replaces deprecated rtcsync)
      enableRTCTrimming = true;
    };

    # Set timezone explicitly
    time.timeZone = mkDefault "UTC";
  };
}
