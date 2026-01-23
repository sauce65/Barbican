# Barbican Security Module: VM Firewall
#
# STIG Implementation:
#   UBTU-22-251010: Configure firewall to deny by default (SC-7)
#   UBTU-22-251015: Enable inbound connection filtering (SC-7)
#   UBTU-22-251020: Enable outbound connection filtering (SC-7(5))
#   UBTU-22-251025: Log dropped packets (AU-2)
#   UBTU-22-251030: Allow only essential services (CM-7)
#
# NIST Controls: SC-7, SC-7(5), CM-7, AU-2
# Legacy: CRT-007, HIGH-005
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.vmFirewall;
in {
  options.barbican.vmFirewall = {
    enable = mkEnableOption "Barbican VM firewall";

    defaultPolicy = mkOption {
      type = types.enum [ "accept" "drop" ];
      default = "drop";
      description = "Default policy for incoming connections";
    };

    allowedInbound = mkOption {
      type = types.listOf (types.submodule {
        options = {
          port = mkOption {
            type = types.int;
            description = "TCP port to allow";
          };
          from = mkOption {
            type = types.str;
            default = "any";
            description = "Source CIDR or 'any'";
          };
          proto = mkOption {
            type = types.enum [ "tcp" "udp" ];
            default = "tcp";
            description = "Protocol";
          };
        };
      });
      default = [];
      description = "Inbound firewall rules";
    };

    allowedOutbound = mkOption {
      type = types.listOf (types.submodule {
        options = {
          port = mkOption {
            type = types.int;
            description = "TCP port to allow";
          };
          to = mkOption {
            type = types.str;
            default = "any";
            description = "Destination CIDR or 'any'";
          };
          proto = mkOption {
            type = types.enum [ "tcp" "udp" ];
            default = "tcp";
            description = "Protocol";
          };
        };
      });
      default = [];
      description = "Outbound firewall rules";
    };

    enableEgressFiltering = mkOption {
      type = types.bool;
      default = true;
      description = "Enable outbound traffic filtering (whitelist mode)";
    };

    allowDNS = mkOption {
      type = types.bool;
      default = true;
      description = "Allow DNS queries (UDP 53)";
    };

    allowNTP = mkOption {
      type = types.bool;
      default = true;
      description = "Allow NTP (UDP 123)";
    };

    logDropped = mkOption {
      type = types.bool;
      default = true;
      description = "Log dropped packets";
    };
  };

  config = mkIf cfg.enable {
    networking.firewall = {
      enable = true;

      # We add all rules via extraCommands to ensure they appear in the INPUT chain
      # (allowedTCPPorts goes to nixos-fw chain which isn't visible in INPUT -L)

      extraCommands = let
        # Separate source-restricted rules from "any" rules
        sourceRestrictedRules = filter (r: r.from != "any") cfg.allowedInbound;
        anySourceRules = filter (r: r.from == "any") cfg.allowedInbound;
        outboundRules = if cfg.enableEgressFiltering then cfg.allowedOutbound else [];
      in ''
        # Default policies
        iptables -P INPUT ${if cfg.defaultPolicy == "drop" then "DROP" else "ACCEPT"}
        iptables -P FORWARD DROP
        ${optionalString cfg.enableEgressFiltering "iptables -P OUTPUT DROP"}

        # Allow loopback
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT

        # Allow established connections
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

        # DNS
        ${optionalString cfg.allowDNS ''
          iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
          iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
        ''}

        # NTP
        ${optionalString cfg.allowNTP ''
          iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
        ''}

        # Source-restricted inbound rules
        ${concatMapStringsSep "\n" (r: ''
          iptables -A INPUT -p ${r.proto} --dport ${toString r.port} -s ${r.from} -j ACCEPT
        '') sourceRestrictedRules}

        # Inbound rules from any source (added to INPUT chain for visibility)
        ${concatMapStringsSep "\n" (r: ''
          iptables -A INPUT -p ${r.proto} --dport ${toString r.port} -j ACCEPT
        '') anySourceRules}

        # Outbound rules (if egress filtering enabled)
        ${concatMapStringsSep "\n" (r: ''
          iptables -A OUTPUT -p ${r.proto} --dport ${toString r.port} ${
            if r.to != "any" then "-d ${r.to}" else ""
          } -j ACCEPT
        '') outboundRules}

        # Log and drop
        ${optionalString cfg.logDropped ''
          iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT_INPUT_DROP: " --log-level 4
          iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IPT_OUTPUT_DROP: " --log-level 4
        ''}
      '';

      # Cleanup
      extraStopCommands = ''
        iptables -P INPUT ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -F
      '';
    };
  };
}
