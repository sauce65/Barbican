# Barbican Network Zones Library
# Provides helpers for defining network segmentation
{ lib }:

with lib;

{
  # Create a network zone configuration
  # Usage:
  #   zones = barbican.lib.networkZones.mkZones {
  #     dmz = { subnet = "10.0.10.0/24"; gateway = "10.0.10.1"; };
  #     backend = { subnet = "10.0.20.0/24"; gateway = "10.0.20.1"; };
  #   };
  mkZones = zoneConfigs:
    mapAttrs (name: cfg: {
      inherit name;
      subnet = cfg.subnet;
      gateway = cfg.gateway or (
        let parts = splitString "/" cfg.subnet;
            ip = head parts;
            octets = splitString "." ip;
        in "${elemAt octets 0}.${elemAt octets 1}.${elemAt octets 2}.1"
      );
      bridge = cfg.bridge or "br-${name}";
      prefix = cfg.prefix or (
        let parts = splitString "/" cfg.subnet;
        in if length parts > 1 then toInt (elemAt parts 1) else 24
      );
    }) zoneConfigs;

  # Generate IP address within a zone
  # Usage:
  #   mkIP zones.backend 6  # Returns "10.0.20.6"
  mkIP = zone: host:
    let
      parts = splitString "/" zone.subnet;
      ip = head parts;
      octets = splitString "." ip;
    in "${elemAt octets 0}.${elemAt octets 1}.${elemAt octets 2}.${toString host}";

  # Generate firewall rules for zone isolation
  mkZoneFirewallRules = zones: allowedFlows:
    let
      # allowedFlows is a list of { from = "zoneName"; to = "zoneName"; ports = [...]; }
      rules = concatMapStringsSep "\n" (flow: ''
        # Allow ${flow.from} -> ${flow.to}
        ${concatMapStringsSep "\n" (port:
          "iptables -A FORWARD -s ${zones.${flow.from}.subnet} -d ${zones.${flow.to}.subnet} -p tcp --dport ${toString port} -j ACCEPT"
        ) flow.ports}
      '') allowedFlows;
    in ''
      # Default deny between zones
      iptables -P FORWARD DROP

      # Allow established connections
      iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

      ${rules}
    '';

  # Generate bridge setup commands
  mkBridgeSetup = zones:
    concatStringsSep "\n" (mapAttrsToList (name: zone: ''
      # Setup bridge for ${name} zone
      ip link add ${zone.bridge} type bridge 2>/dev/null || true
      ip addr add ${zone.gateway}/${toString zone.prefix} dev ${zone.bridge} 2>/dev/null || true
      ip link set ${zone.bridge} up
    '') zones);
}
