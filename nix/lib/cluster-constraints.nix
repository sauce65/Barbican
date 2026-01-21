# Barbican Cluster Constraints Library
#
# Defines isolation and sharing constraints for services based on FedRAMP
# security profiles. These constraints determine whether services can share
# VMs or must be isolated.
#
# Constraint Levels:
#   - required:    Service MUST have its own dedicated VM (hard constraint)
#   - recommended: Service SHOULD have its own VM, but can be overridden
#   - optional:    Service can freely share with others (no constraint)
#
# NIST 800-53 Control Mapping:
#   - SC-7: Boundary Protection (network isolation)
#   - SC-32: Information System Partitioning
#   - AC-4: Information Flow Enforcement
{ lib }:

with lib;

rec {
  # ==========================================================================
  # Isolation Levels
  # ==========================================================================

  isolationLevels = {
    required = {
      level = 3;
      canOverride = false;
      description = "Must be isolated - compliance requirement";
    };
    recommended = {
      level = 2;
      canOverride = true;
      description = "Should be isolated - security best practice";
    };
    optional = {
      level = 1;
      canOverride = true;
      description = "May be shared - no isolation requirement";
    };
  };

  # ==========================================================================
  # Profile-Specific Constraints
  # ==========================================================================

  # FedRAMP High - Maximum security, most services isolated
  # NIST 800-53 High baseline requires strong separation of concerns
  fedrampHighConstraints = {
    vault = {
      isolation = "required";
      reason = "SC-12, SC-17: Cryptographic key management requires dedicated boundary";
      controls = [ "SC-12" "SC-17" "SC-32" ];
    };
    postgres = {
      isolation = "required";
      reason = "SC-28: Data at rest requires isolated storage boundary";
      controls = [ "SC-28" "SC-32" ];
    };
    keycloak = {
      isolation = "required";
      reason = "IA-2, AC-2: Identity provider requires isolated trust boundary";
      controls = [ "IA-2" "AC-2" "SC-32" ];
    };
    redis = {
      isolation = "recommended";
      reason = "SC-8: Session data should be isolated from application";
      controls = [ "SC-8" ];
    };
    observability = {
      isolation = "recommended";
      reason = "AU-9: Audit data should be protected from application access";
      controls = [ "AU-9" "SI-4" ];
    };
    app-runtime = {
      isolation = "optional";
      reason = "Application can share with auxiliary services";
      controls = [];
    };
  };

  # FedRAMP Moderate - Standard government security
  # Balance between security and operational complexity
  fedrampModerateConstraints = {
    vault = {
      isolation = "recommended";
      reason = "SC-12: Key management benefits from isolation";
      controls = [ "SC-12" "SC-17" ];
    };
    postgres = {
      isolation = "recommended";
      reason = "SC-28: Database isolation is a best practice";
      controls = [ "SC-28" ];
    };
    keycloak = {
      isolation = "recommended";
      reason = "IA-2: Identity provider benefits from isolation";
      controls = [ "IA-2" "AC-2" ];
    };
    redis = {
      isolation = "optional";
      reason = "Can share with application for simplicity";
      controls = [];
    };
    observability = {
      isolation = "optional";
      reason = "Can share with application for simplicity";
      controls = [];
    };
    app-runtime = {
      isolation = "optional";
      reason = "Application can share with auxiliary services";
      controls = [];
    };
  };

  # FedRAMP Low - Basic security
  # Simplified deployment, most services can share
  fedrampLowConstraints = {
    vault = {
      isolation = "optional";
      reason = "Vault can be colocated for simpler deployments";
      controls = [];
    };
    postgres = {
      isolation = "optional";
      reason = "Database can be colocated for simpler deployments";
      controls = [];
    };
    keycloak = {
      isolation = "optional";
      reason = "Identity provider can be colocated";
      controls = [];
    };
    redis = {
      isolation = "optional";
      reason = "Redis can be colocated";
      controls = [];
    };
    observability = {
      isolation = "optional";
      reason = "Observability can be colocated";
      controls = [];
    };
    app-runtime = {
      isolation = "optional";
      reason = "All services can share";
      controls = [];
    };
  };

  # Development - No isolation requirements
  # Everything can run on a single VM for local development
  developmentConstraints = {
    vault = {
      isolation = "optional";
      reason = "Development mode allows all services on one VM";
      controls = [];
    };
    postgres = {
      isolation = "optional";
      reason = "Development mode allows all services on one VM";
      controls = [];
    };
    keycloak = {
      isolation = "optional";
      reason = "Development mode allows all services on one VM";
      controls = [];
    };
    redis = {
      isolation = "optional";
      reason = "Development mode allows all services on one VM";
      controls = [];
    };
    observability = {
      isolation = "optional";
      reason = "Development mode allows all services on one VM";
      controls = [];
    };
    app-runtime = {
      isolation = "optional";
      reason = "Development mode allows all services on one VM";
      controls = [];
    };
  };

  # ==========================================================================
  # Profile Selector
  # ==========================================================================

  forProfile = profile:
    if profile == "fedramp-high" then fedrampHighConstraints
    else if profile == "fedramp-moderate" then fedrampModerateConstraints
    else if profile == "fedramp-low" then fedrampLowConstraints
    else if profile == "development" then developmentConstraints
    else throw "Unknown profile: ${profile}. Valid profiles: development, fedramp-low, fedramp-moderate, fedramp-high";

  # ==========================================================================
  # Constraint Merging
  # ==========================================================================

  # Merge profile constraints with user overrides
  # User can only loosen constraints that are not "required"
  merge = { profileConstraints, userOverrides }:
    let
      # Process each service's constraints
      mergeService = serviceName: profileConstraint:
        let
          userOverride = userOverrides.overrides.${serviceName} or {};
          requestedIsolation = userOverride.isolation or null;

          # Check if override is valid
          canOverride = profileConstraint.isolation != "required";
          finalIsolation =
            if requestedIsolation == null then profileConstraint.isolation
            else if !canOverride && requestedIsolation != "required" then
              # Cannot loosen required constraints
              profileConstraint.isolation
            else
              requestedIsolation;

          overrideApplied = requestedIsolation != null &&
                           requestedIsolation != profileConstraint.isolation &&
                           canOverride;
        in
          profileConstraint // {
            isolation = finalIsolation;
            overridden = overrideApplied;
            originalIsolation = if overrideApplied then profileConstraint.isolation else null;
          };
    in
      mapAttrs mergeService profileConstraints // {
        # Include explicit sharing rules from user
        _allowSharing = userOverrides.allowSharing or [];
        _denySharing = userOverrides.denySharing or [];
      };

  # ==========================================================================
  # Constraint Queries
  # ==========================================================================

  # Check if two services can share a VM given constraints
  canShare = constraints: svc1: svc2:
    let
      c1 = constraints.${svc1} or { isolation = "optional"; };
      c2 = constraints.${svc2} or { isolation = "optional"; };

      # Check explicit deny rules
      explicitlyDenied = any (pair:
        (elem svc1 pair && elem svc2 pair)
      ) (constraints._denySharing or []);

      # Check explicit allow rules (overrides recommended but not required)
      explicitlyAllowed = any (pair:
        (elem svc1 pair && elem svc2 pair)
      ) (constraints._allowSharing or []);

      # Check isolation requirements
      requiresIsolation = level: level == "required";
      recommendsIsolation = level: level == "recommended";

      either1 = requiresIsolation c1.isolation;
      either2 = requiresIsolation c2.isolation;
    in
      if explicitlyDenied then false
      else if either1 || either2 then false
      else if explicitlyAllowed then true
      else
        # For recommended, allow sharing but resolver should prefer separation
        !(recommendsIsolation c1.isolation && recommendsIsolation c2.isolation);

  # Check if a service requires dedicated VM
  requiresDedicated = constraints: service:
    let
      c = constraints.${service} or { isolation = "optional"; };
    in
      c.isolation == "required";

  # Check if a service prefers dedicated VM (required or recommended)
  prefersDedicated = constraints: service:
    let
      c = constraints.${service} or { isolation = "optional"; };
    in
      c.isolation == "required" || c.isolation == "recommended";

  # Get all services that require dedicated VMs
  getRequiredDedicated = constraints:
    attrNames (filterAttrs (_: c: c.isolation or "" == "required") constraints);

  # Get all services that recommend dedicated VMs
  getRecommendedDedicated = constraints:
    attrNames (filterAttrs (_: c: c.isolation or "" == "recommended") constraints);

  # ==========================================================================
  # Validation
  # ==========================================================================

  # Validate that a proposed placement satisfies all constraints
  # Returns { valid: bool, errors: [string], warnings: [string] }
  validatePlacement = { constraints, placement }:
    let
      # placement is { vmName: [serviceName] }
      errors = concatLists (mapAttrsToList (vmName: services:
        let
          # Check for services that require isolation but are sharing
          isolationViolations = filter (svc:
            requiresDedicated constraints svc && length services > 1
          ) services;

          # Check for explicit deny violations
          denyViolations = filter (pair:
            let
              svc1 = elemAt pair 0;
              svc2 = elemAt pair 1;
            in
              elem svc1 services && elem svc2 services
          ) (constraints._denySharing or []);
        in
          (map (svc: "Service '${svc}' requires dedicated VM but is sharing ${vmName} with: ${concatStringsSep ", " (filter (s: s != svc) services)}") isolationViolations) ++
          (map (pair: "Services ${toString pair} cannot share a VM but are both on ${vmName}") denyViolations)
      ) placement);

      warnings = concatLists (mapAttrsToList (vmName: services:
        let
          # Check for services that recommend isolation but are sharing
          recommendationViolations = filter (svc:
            prefersDedicated constraints svc &&
            !requiresDedicated constraints svc &&
            length services > 1
          ) services;
        in
          map (svc: "Service '${svc}' recommends dedicated VM but is sharing ${vmName}") recommendationViolations
      ) placement);
    in {
      valid = length errors == 0;
      inherit errors warnings;
    };

  # ==========================================================================
  # Documentation Helpers
  # ==========================================================================

  # Generate human-readable constraint documentation for a profile
  documentProfile = profile:
    let
      constraints = forProfile profile;
    in
      concatStringsSep "\n" (mapAttrsToList (service: constraint:
        "- ${service}: ${constraint.isolation} (${constraint.reason})"
      ) constraints);

  # Generate compliance documentation showing control mappings
  documentControls = profile:
    let
      constraints = forProfile profile;
      allControls = unique (concatLists (mapAttrsToList (_: c: c.controls or []) constraints));
    in {
      profile = profile;
      controls = allControls;
      serviceMapping = mapAttrs (_: c: c.controls or []) constraints;
    };
}
