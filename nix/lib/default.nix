# Barbican Library Functions
{ lib ? (import <nixpkgs> {}).lib }:

{
  # Network zone helpers
  networkZones = import ./network-zones.nix { inherit lib; };

  # PKI helpers
  pki = import ./pki.nix { inherit lib; };

  # Systemd hardening presets
  systemdHardening = import ./systemd-hardening-lib.nix { inherit lib; };
}
