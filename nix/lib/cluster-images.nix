# Barbican Cluster VM Image Registry Library
#
# Provides default VM image definitions and utilities for working with
# the image registry. Images define what services they can provide and
# the resolver uses this information to map services to VMs.
#
# Image Granularity Evolution:
#   Phase 1 (Current): Single "full" image provides all services
#   Phase 2: Separate vault, database, app images
#   Phase 3: Fine-grained single-service images
#
# The cluster module is designed to work at any granularity level,
# automatically colocating services when images are coarse and
# separating them when images are granular.
{ lib }:

with lib;

rec {
  # ==========================================================================
  # Default Image Definitions
  # ==========================================================================

  # Full image - provides everything (Phase 1: coarse granularity)
  # This is what most deployments will start with
  fullImage = {
    provides = [
      "vault"
      "postgres"
      "redis"
      "keycloak"
      "observability"
      "app-runtime"
    ];
    description = "Complete stack image with all services";
    resources = {
      memory = "4G";
      cpus = 4;
      disk = "50G";
    };
    profiles = [ "development" "fedramp-low" "fedramp-moderate" ];
  };

  # Vault-dedicated image (Phase 2+)
  vaultImage = {
    provides = [ "vault" ];
    description = "Dedicated Vault PKI and secrets management";
    resources = {
      memory = "1G";
      cpus = 2;
      disk = "10G";
    };
    profiles = [ "fedramp-moderate" "fedramp-high" ];
    # Vault has no service dependencies
    consumes = [];
  };

  # Database image (Phase 2+)
  databaseImage = {
    provides = [ "postgres" "redis" ];
    description = "Database services (PostgreSQL, Redis)";
    resources = {
      memory = "2G";
      cpus = 2;
      disk = "100G";
    };
    profiles = [ "fedramp-moderate" "fedramp-high" ];
    # Database needs Vault for certificate issuance
    consumes = [ "vault" ];
  };

  # PostgreSQL-only image (Phase 3: fine-grained)
  postgresImage = {
    provides = [ "postgres" ];
    description = "Dedicated PostgreSQL database";
    resources = {
      memory = "2G";
      cpus = 2;
      disk = "100G";
    };
    profiles = [ "fedramp-high" ];
    consumes = [ "vault" ];
  };

  # Redis-only image (Phase 3)
  redisImage = {
    provides = [ "redis" ];
    description = "Dedicated Redis instance";
    resources = {
      memory = "1G";
      cpus = 1;
      disk = "10G";
    };
    profiles = [ "fedramp-high" ];
    consumes = [ "vault" ];
  };

  # Identity provider image (Phase 2+)
  identityImage = {
    provides = [ "keycloak" ];
    description = "Keycloak identity and access management";
    resources = {
      memory = "2G";
      cpus = 2;
      disk = "20G";
    };
    profiles = [ "fedramp-moderate" "fedramp-high" ];
    consumes = [ "vault" "postgres" ];
  };

  # Application runtime image (Phase 2+)
  appRuntimeImage = {
    provides = [ "app-runtime" "observability" ];
    description = "Application runtime with observability";
    resources = {
      memory = "2G";
      cpus = 2;
      disk = "20G";
    };
    profiles = [ "fedramp-moderate" "fedramp-high" ];
    consumes = [ "vault" "postgres" ];
  };

  # Observability-only image (Phase 3)
  observabilityImage = {
    provides = [ "observability" ];
    description = "Dedicated observability stack (Prometheus, Grafana, Loki)";
    resources = {
      memory = "2G";
      cpus = 2;
      disk = "50G";
    };
    profiles = [ "fedramp-high" ];
    consumes = [ "vault" ];
  };

  # ==========================================================================
  # Preset Image Registries
  # ==========================================================================

  # Minimal registry - single VM for everything
  minimalRegistry = {
    full = fullImage;
  };

  # Standard registry - separate vault and database
  standardRegistry = {
    vault = vaultImage;
    database = databaseImage;
    app = appRuntimeImage;
  };

  # Full registry - maximum granularity
  fullRegistry = {
    vault = vaultImage;
    postgres = postgresImage;
    redis = redisImage;
    keycloak = identityImage;
    observability = observabilityImage;
    app = appRuntimeImage // { provides = [ "app-runtime" ]; };
  };

  # ==========================================================================
  # Registry Utilities
  # ==========================================================================

  # Find images that can provide a given service
  findImagesForService = registry: service:
    filterAttrs (_: img: elem service img.provides) registry;

  # Check if a registry can provide all requested services
  canProvideAll = registry: services:
    let
      allProvided = unique (concatMap (img: img.provides) (attrValues registry));
    in
      all (svc: elem svc allProvided) services;

  # Get the dependency order for images based on 'consumes'
  # Returns list of image names in boot order (dependencies first)
  getBootOrder = registry:
    let
      # Build dependency graph
      deps = mapAttrs (name: img: img.consumes or []) registry;

      # Topological sort
      sorted = toposort
        (a: b: any (dep: elem dep (registry.${b}.provides or [])) (deps.${a} or []))
        (attrNames registry);
    in
      if sorted ? cycle then
        throw "Circular dependency detected in image registry: ${toString sorted.cycle}"
      else
        sorted.sorted or (attrNames registry);

  # Get services provided by an image
  getProvides = registry: imageName:
    (registry.${imageName} or { provides = []; }).provides;

  # Get services consumed by an image (dependencies)
  getConsumes = registry: imageName:
    (registry.${imageName} or { consumes = []; }).consumes or [];

  # ==========================================================================
  # Registry Validation
  # ==========================================================================

  # Validate that a registry is internally consistent
  # Returns { valid: bool, errors: [string] }
  validateRegistry = registry:
    let
      allProvided = unique (concatMap (img: img.provides) (attrValues registry));

      # Check that all consumed services are provided
      consumptionErrors = concatLists (mapAttrsToList (name: img:
        let
          consumed = img.consumes or [];
          missing = filter (svc: !elem svc allProvided) consumed;
        in
          map (svc: "Image '${name}' consumes '${svc}' but no image provides it") missing
      ) registry);

      # Check for duplicate providers (warning, not error)
      duplicateWarnings =
        let
          serviceCounts = foldl' (acc: img:
            foldl' (a: svc: a // { ${svc} = (a.${svc} or 0) + 1; }) acc img.provides
          ) {} (attrValues registry);
          duplicates = filterAttrs (_: count: count > 1) serviceCounts;
        in
          mapAttrsToList (svc: count:
            "Service '${svc}' is provided by ${toString count} images"
          ) duplicates;
    in {
      valid = length consumptionErrors == 0;
      errors = consumptionErrors;
      warnings = duplicateWarnings;
    };

  # ==========================================================================
  # Registry Selection
  # ==========================================================================

  # Select appropriate registry based on profile and requested services
  # Returns the most granular registry that satisfies constraints
  selectRegistry = { profile, services, constraints }:
    let
      # Start with full registry and filter based on what's needed
      candidateRegistries = [
        { name = "full"; registry = fullRegistry; }
        { name = "standard"; registry = standardRegistry; }
        { name = "minimal"; registry = minimalRegistry; }
      ];

      # Filter to registries that can provide all services
      capable = filter (r: canProvideAll r.registry services) candidateRegistries;

      # For FedRAMP High, prefer granular registries
      # For development, prefer minimal
      preferred =
        if profile == "fedramp-high" then
          head (filter (r: r.name == "full") capable ++ capable)
        else if profile == "development" then
          last capable
        else
          # Moderate/Low: use standard if available
          head (filter (r: r.name == "standard") capable ++ capable);
    in
      preferred.registry;

  # ==========================================================================
  # Image Compatibility
  # ==========================================================================

  # Check if an image is compatible with a security profile
  isCompatibleWithProfile = image: profile:
    elem profile (image.profiles or [ "development" "fedramp-low" "fedramp-moderate" "fedramp-high" ]);

  # Filter registry to images compatible with a profile
  filterByProfile = registry: profile:
    filterAttrs (_: img: isCompatibleWithProfile img profile) registry;

  # ==========================================================================
  # Resource Aggregation
  # ==========================================================================

  # Calculate total resources needed for a set of services
  calculateResources = registry: services:
    let
      # Find minimum set of images needed
      relevantImages = filter (img:
        any (svc: elem svc img.provides) services
      ) (attrValues registry);

      # Aggregate resources
      parseSize = str:
        let
          num = toInt (head (match "([0-9]+)[GMK]?" str));
          unit = head (match "[0-9]+([GMK])?" str);
          multiplier = if unit == "G" then 1024 else if unit == "M" then 1 else if unit == "K" then 1 else 1024;
        in num * multiplier;

      totalMemory = foldl' (acc: img: acc + parseSize (img.resources.memory or "1G")) 0 relevantImages;
      totalCpus = foldl' (acc: img: acc + (img.resources.cpus or 1)) 0 relevantImages;
      totalDisk = foldl' (acc: img: acc + parseSize (img.resources.disk or "10G")) 0 relevantImages;
    in {
      memory = "${toString (totalMemory / 1024)}G";
      cpus = totalCpus;
      disk = "${toString (totalDisk / 1024)}G";
      imageCount = length relevantImages;
    };
}
