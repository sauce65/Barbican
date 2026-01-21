# Barbican Cluster Builder
#
# High-level function to create a complete cluster deployment from a declaration.
# This is the main entry point for consumers using barbican.lib.cluster.mkCluster.
#
# Usage:
#   cluster = barbican.lib.cluster.mkCluster {
#     inherit pkgs;
#     name = "my-app-cluster";
#     profile = "fedramp-moderate";
#
#     services = {
#       vault.enable = true;
#       postgres = {
#         enable = true;
#         dependsOn = [ "vault" ];
#       };
#     };
#
#     application = {
#       name = "my-app";
#       module = ./app.nix;
#       dependsOn = [ "postgres" ];
#     };
#
#     # Optional: use default minimal registry if not specified
#     images = { ... };
#   };
#
# Returns:
#   {
#     # Derivation containing all deployment artifacts
#     package = <derivation>;
#
#     # Individual components for inspection/customization
#     topology = { vms, bootOrder, flows, network };
#     scripts = { deploy, status, teardown, lib };
#     vmConfigs = { ... };
#
#     # Apps for nix run
#     apps = {
#       deploy = { type = "app"; program = "..."; };
#       status = { type = "app"; program = "..."; };
#       teardown = { type = "app"; program = "..."; };
#     };
#   }
{ lib }:

with lib;

{
  mkCluster = {
    pkgs,
    name,
    profile ? "fedramp-moderate",
    services ? {},
    application ? null,
    network ? {},
    images ? null,
    constraints ? {},
  }:
    let
      # Import libraries
      constraintsLib = import ./cluster-constraints.nix { inherit lib; };
      imagesLib = import ./cluster-images.nix { inherit lib; };
      resolver = import ./cluster-resolver.nix { inherit lib; };
      orchestration = import ./cluster-orchestration.nix { inherit lib pkgs; };

      # Use default minimal registry if no images provided
      effectiveImages = if images != null then images else {
        full = {
          provides = [ "vault" "postgres" "redis" "keycloak" "observability" "app-runtime" ];
          module = null;  # Will be populated by consumer
          resources = {
            memory = "4G";
            cpus = 4;
            disk = "50G";
          };
        };
      };

      # Normalize services structure
      normalizedServices = {
        vault = {
          enable = services.vault.enable or false;
          placement = services.vault.placement or "auto";
          colocateWith = services.vault.colocateWith or null;
          priority = services.vault.priority or 10;
          dependsOn = services.vault.dependsOn or [];
          healthCheck = services.vault.healthCheck or null;
          ports = services.vault.ports or [{ port = 8200; protocol = "http"; public = false; }];
          resources = services.vault.resources or {};
          config = services.vault.config or {};
        };
        postgres = {
          enable = services.postgres.enable or false;
          placement = services.postgres.placement or "auto";
          colocateWith = services.postgres.colocateWith or null;
          priority = services.postgres.priority or 50;
          dependsOn = services.postgres.dependsOn or [ "vault" ];
          healthCheck = services.postgres.healthCheck or null;
          ports = services.postgres.ports or [{ port = 5432; protocol = "tcp"; public = false; }];
          resources = services.postgres.resources or {};
          config = services.postgres.config or {};
        };
        redis = {
          enable = services.redis.enable or false;
          placement = services.redis.placement or "auto";
          colocateWith = services.redis.colocateWith or null;
          priority = services.redis.priority or 50;
          dependsOn = services.redis.dependsOn or [ "vault" ];
          healthCheck = services.redis.healthCheck or null;
          ports = services.redis.ports or [{ port = 6379; protocol = "tcp"; public = false; }];
          resources = services.redis.resources or {};
          config = services.redis.config or {};
        };
        keycloak = {
          enable = services.keycloak.enable or false;
          placement = services.keycloak.placement or "auto";
          colocateWith = services.keycloak.colocateWith or null;
          priority = services.keycloak.priority or 60;
          dependsOn = services.keycloak.dependsOn or [ "vault" "postgres" ];
          healthCheck = services.keycloak.healthCheck or null;
          ports = services.keycloak.ports or [{ port = 8080; protocol = "http"; public = true; }];
          resources = services.keycloak.resources or {};
          config = services.keycloak.config or {};
        };
        observability = {
          enable = services.observability.enable or false;
          placement = services.observability.placement or "auto";
          colocateWith = services.observability.colocateWith or null;
          priority = services.observability.priority or 150;
          dependsOn = services.observability.dependsOn or [ "vault" ];
          healthCheck = services.observability.healthCheck or null;
          ports = services.observability.ports or [
            { port = 9090; protocol = "http"; public = false; }
            { port = 3000; protocol = "http"; public = true; }
            { port = 3100; protocol = "http"; public = false; }
          ];
          resources = services.observability.resources or {};
          config = services.observability.config or {};
        };
      };

      # Normalize network
      normalizedNetwork = {
        subnet = network.subnet or "10.100.0.0/24";
        gateway = network.gateway or "10.100.0.1";
        dns = network.dns or [ "10.100.0.1" ];
        domain = network.domain or "cluster.local";
      };

      # Merge constraints
      mergedConstraints = constraintsLib.merge {
        profileConstraints = constraintsLib.forProfile profile;
        userOverrides = {
          overrides = constraints.overrides or {};
          allowSharing = constraints.allowSharing or [];
          denySharing = constraints.denySharing or [];
        };
      };

      # Resolve topology
      topology = resolver.resolve {
        services = normalizedServices;
        inherit application;
        images = effectiveImages;
        constraints = mergedConstraints;
        network = normalizedNetwork;
      };

      # Generate orchestration artifacts
      generated = orchestration.generate {
        inherit topology;
        clusterName = name;
        inherit profile;
        outputDir = "/tmp/cluster-${name}";
        vmModules = {};
        secretsConfig = {};
      };

      # Validate the configuration
      validation = constraintsLib.validatePlacement {
        constraints = mergedConstraints;
        placement = mapAttrs (_: vm: vm.services) topology.vms;
      };

    in {
      # Main package with all artifacts
      package = generated.all;

      # Components for inspection
      inherit topology;
      inherit (generated) bootOrder networkConfig secretsBootstrap vmConfigs scripts;

      # Validation results
      inherit validation;

      # Apps for nix run
      apps = {
        deploy = {
          type = "app";
          program = "${generated.scripts.deploy}";
        };
        status = {
          type = "app";
          program = "${generated.scripts.status}";
        };
        teardown = {
          type = "app";
          program = "${generated.scripts.teardown}";
        };
      };

      # Metadata
      meta = {
        inherit name profile;
        enabledServices = attrNames (filterAttrs (_: svc: svc.enable) normalizedServices);
        vmCount = length (attrNames topology.vms);
        hasApplication = application != null;
      };

      # Helper to generate a specific VM's NixOS configuration
      mkVmConfig = vmName: { config, pkgs, ... }: {
        imports = [
          # Profile module would be imported here
          # barbican.nixosModules.${profileToModule profile}
        ];

        networking = generated.vmConfigs.${vmName}.nixosConfig.networking;
        barbican = generated.vmConfigs.${vmName}.nixosConfig.barbican;
      };
    };

  # Profile name to module name mapping
  profileToModule = profile: {
    "development" = "development";
    "fedramp-low" = "fedrampLow";
    "fedramp-moderate" = "fedrampModerate";
    "fedramp-high" = "fedrampHigh";
  }.${profile};
}
