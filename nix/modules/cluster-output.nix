# Barbican Cluster Output Module
#
# Generates deployment artifacts from the cluster configuration.
# This module is typically used in a flake to produce runnable outputs.
#
# Usage in flake.nix:
#   outputs = { barbican, nixpkgs, ... }: {
#     packages.cluster = barbican.lib.cluster.generateOutput {
#       inherit pkgs;
#       clusterConfig = {
#         name = "my-cluster";
#         profile = "fedramp-moderate";
#         services = { ... };
#         images = { ... };
#       };
#     };
#   };
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.cluster;

  # Import libraries
  constraints = import ../lib/cluster-constraints.nix { inherit lib; };
  images = import ../lib/cluster-images.nix { inherit lib; };
  resolver = import ../lib/cluster-resolver.nix { inherit lib; };
  orchestration = import ../lib/cluster-orchestration.nix { inherit lib pkgs; };

in {
  options.barbican.cluster.output = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = "Generate cluster output artifacts";
    };

    package = mkOption {
      type = types.package;
      readOnly = true;
      description = "Generated cluster deployment package";
    };

    topology = mkOption {
      type = types.attrs;
      readOnly = true;
      description = "Resolved cluster topology";
    };
  };

  config = mkIf (cfg.enable && cfg.output.enable) {
    barbican.cluster.output = {
      # Resolve the topology
      topology =
        let
          # Merge profile constraints with user overrides
          mergedConstraints = constraints.merge {
            profileConstraints = constraints.forProfile cfg.profile;
            userOverrides = cfg.constraints;
          };

          # Collect enabled services
          enabledServices = filterAttrs (_: svc: svc.enable or false) cfg.services;

        in resolver.resolve {
          services = cfg.services;
          application = cfg.application;
          images = cfg.images;
          constraints = mergedConstraints;
          network = cfg.network;
        };

      # Generate the deployment package
      package = orchestration.generate {
        topology = cfg.output.topology;
        clusterName = cfg.name;
        profile = cfg.profile;
        outputDir = cfg.output.directory or "/tmp/cluster-output";
        vmModules = {};
        secretsConfig = {};
      };
    };
  };
}
