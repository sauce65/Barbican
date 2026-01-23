# Barbican Isolation Boundaries Library
#
# Defines granular isolation levels that can be composed into FedRAMP profiles.
# This library is deployment-target agnostic - it validates topology, not
# how that topology is provisioned (QEMU, EC2, Kubernetes, etc.).
#
# NIST 800-53 Control Mapping:
#   - SC-7:  Boundary Protection
#   - SC-32: Information System Partitioning
#   - SC-39: Process Isolation
#   - AC-4:  Information Flow Enforcement
#   - AC-6:  Least Privilege
{ lib }:

with lib;

rec {
  # ==========================================================================
  # Isolation Boundary Levels
  # ==========================================================================
  #
  # Each level represents a security boundary. Higher levels provide stronger
  # isolation guarantees. A constraint specifies the MINIMUM boundary required
  # between two services.

  boundaries = {
    physical = {
      level = 4;
      name = "physical";
      description = "Different physical hosts (EC2 instances, bare metal)";
      guarantees = [
        "Separate CPU/memory hardware"
        "No shared hypervisor"
        "Independent failure domain"
        "No side-channel attack surface"
      ];
      controls = [ "SC-7" "SC-32" "PE-18" ];
    };

    hypervisor = {
      level = 3;
      name = "hypervisor";
      description = "Different VMs on same host (KVM, QEMU, Xen)";
      guarantees = [
        "Separate virtual CPU/memory"
        "Hypervisor-enforced isolation"
        "Independent OS instances"
      ];
      limitations = [
        "Shared physical resources"
        "Potential side-channel exposure"
        "Common hypervisor vulnerabilities"
      ];
      controls = [ "SC-7" "SC-32" "SC-39" ];
    };

    container = {
      level = 2;
      name = "container";
      description = "Different containers/namespaces (Docker, systemd-nspawn)";
      guarantees = [
        "Namespace isolation (pid, net, mnt)"
        "cgroup resource limits"
        "Separate filesystem roots"
      ];
      limitations = [
        "Shared kernel"
        "Weaker isolation than VMs"
        "Container escape vulnerabilities"
      ];
      controls = [ "SC-39" "AC-6" ];
    };

    process = {
      level = 1;
      name = "process";
      description = "Different processes in same OS";
      guarantees = [
        "Separate process address space"
        "User/group permission separation"
      ];
      limitations = [
        "Shared kernel and libraries"
        "Shared filesystem (with permissions)"
        "IPC channels available"
      ];
      controls = [ "AC-6" ];
    };

    none = {
      level = 0;
      name = "none";
      description = "Can share process space";
      guarantees = [];
      limitations = [ "No isolation" ];
      controls = [];
    };
  };

  # ==========================================================================
  # Service Isolation Requirements
  # ==========================================================================
  #
  # Define what boundary a service requires from OTHER services.
  # This is an adjacency model: "vault requires PHYSICAL isolation from postgres"

  # Helper to create a service isolation spec
  mkServiceIsolation = {
    description,
    # Default boundary required from all other services
    defaultBoundary ? "none",
    # Specific boundaries required from named services
    fromServices ? {},
    # NIST controls this isolation satisfies
    controls ? [],
    # Whether this can be overridden by operator
    canOverride ? true,
  }: {
    inherit description defaultBoundary fromServices controls canOverride;
  };

  # ==========================================================================
  # Primitive Isolation Rules (composable building blocks)
  # ==========================================================================

  primitives = {
    # Key management isolation
    keyManagement = {
      vault = mkServiceIsolation {
        description = "Cryptographic key management";
        defaultBoundary = "hypervisor";
        fromServices = {
          # Vault should be isolated from everything that uses its keys
          postgres = "hypervisor";
          keycloak = "hypervisor";
          redis = "hypervisor";
          app-runtime = "hypervisor";
          observability = "hypervisor";
        };
        controls = [ "SC-12" "SC-17" ];
      };
    };

    # Data storage isolation
    dataStorage = {
      postgres = mkServiceIsolation {
        description = "Persistent data storage";
        defaultBoundary = "process";
        fromServices = {
          app-runtime = "process";
          redis = "none";
        };
        controls = [ "SC-28" ];
      };
    };

    # Identity provider isolation
    identityProvider = {
      keycloak = mkServiceIsolation {
        description = "Identity and authentication provider";
        defaultBoundary = "process";
        fromServices = {
          app-runtime = "process";
        };
        controls = [ "IA-2" "AC-2" ];
      };
    };

    # Session/cache isolation
    sessionStore = {
      redis = mkServiceIsolation {
        description = "Session and cache storage";
        defaultBoundary = "none";
        controls = [ "SC-8" ];
      };
    };

    # Audit/monitoring isolation
    auditSystem = {
      observability = mkServiceIsolation {
        description = "Logging, metrics, and audit collection";
        defaultBoundary = "process";
        fromServices = {
          app-runtime = "process";
        };
        controls = [ "AU-9" "SI-4" ];
      };
    };

    # Application runtime (no special isolation by default)
    applicationRuntime = {
      app-runtime = mkServiceIsolation {
        description = "Application workload";
        defaultBoundary = "none";
        controls = [];
      };
    };
  };

  # ==========================================================================
  # Profile Compositions
  # ==========================================================================
  #
  # Compose primitives with profile-specific boundary upgrades

  # Merge service isolation specs, taking the stricter boundary
  mergeIsolation = base: overlay:
    let
      mergeFromServices = baseFrom: overlayFrom:
        let
          allServices = unique (attrNames baseFrom ++ attrNames overlayFrom);
        in
          listToAttrs (map (svc:
            let
              baseBoundary = baseFrom.${svc} or "none";
              overlayBoundary = overlayFrom.${svc} or "none";
              # Take stricter (higher level)
              finalBoundary =
                if boundaries.${overlayBoundary}.level > boundaries.${baseBoundary}.level
                then overlayBoundary
                else baseBoundary;
            in
              nameValuePair svc finalBoundary
          ) allServices);
    in
      base // overlay // {
        fromServices = mergeFromServices (base.fromServices or {}) (overlay.fromServices or {});
        controls = unique ((base.controls or []) ++ (overlay.controls or []));
      };

  # Build complete service isolation map from primitives
  buildFromPrimitives = primitiveList:
    foldl' (acc: prim: acc // prim) {} primitiveList;

  # Base isolation (all primitives with default boundaries)
  baseIsolation = buildFromPrimitives (attrValues primitives);

  # FedRAMP High: Upgrade boundaries for maximum security
  fedrampHighOverrides = {
    vault = {
      fromServices = {
        postgres = "physical";
        keycloak = "physical";
        redis = "physical";
        app-runtime = "physical";
        observability = "physical";
      };
      canOverride = false;  # Cannot weaken at High
    };
    postgres = {
      fromServices = {
        app-runtime = "hypervisor";
        keycloak = "hypervisor";
        redis = "hypervisor";
        observability = "hypervisor";
      };
      canOverride = false;
    };
    keycloak = {
      fromServices = {
        app-runtime = "hypervisor";
        redis = "hypervisor";
        observability = "hypervisor";
      };
      canOverride = false;
    };
    observability = {
      fromServices = {
        app-runtime = "hypervisor";
      };
    };
  };

  # FedRAMP Moderate: Hypervisor isolation for sensitive services
  fedrampModerateOverrides = {
    vault = {
      fromServices = {
        postgres = "hypervisor";
        keycloak = "hypervisor";
        app-runtime = "hypervisor";
      };
      canOverride = true;  # Can adjust for operational needs
    };
    postgres = {
      fromServices = {
        app-runtime = "hypervisor";
      };
      canOverride = true;
    };
    keycloak = {
      fromServices = {
        app-runtime = "hypervisor";
      };
      canOverride = true;
    };
  };

  # FedRAMP Low: Process isolation is sufficient
  fedrampLowOverrides = {
    # Use base primitives (process-level isolation)
  };

  # Development: No isolation requirements
  developmentOverrides = {
    vault = { fromServices = {}; defaultBoundary = "none"; };
    postgres = { fromServices = {}; defaultBoundary = "none"; };
    keycloak = { fromServices = {}; defaultBoundary = "none"; };
    redis = { fromServices = {}; defaultBoundary = "none"; };
    observability = { fromServices = {}; defaultBoundary = "none"; };
    app-runtime = { fromServices = {}; defaultBoundary = "none"; };
  };

  # ==========================================================================
  # Profile Builder
  # ==========================================================================

  # Build a complete profile by applying overrides to base
  buildProfile = overrides:
    mapAttrs (svc: base:
      if hasAttr svc overrides
      then mergeIsolation base overrides.${svc}
      else base
    ) baseIsolation;

  profiles = {
    "fedramp-high" = buildProfile fedrampHighOverrides;
    "fedramp-moderate" = buildProfile fedrampModerateOverrides;
    "fedramp-low" = buildProfile fedrampLowOverrides;
    "development" = buildProfile developmentOverrides;
  };

  forProfile = profile:
    profiles.${profile} or (throw "Unknown profile: ${profile}. Valid: ${toString (attrNames profiles)}");

  # ==========================================================================
  # Query Functions
  # ==========================================================================

  # Get required boundary between two services
  requiredBoundary = profile: svc1: svc2:
    let
      isolation = forProfile profile;
      svc1Spec = isolation.${svc1} or { fromServices = {}; defaultBoundary = "none"; };
      svc2Spec = isolation.${svc2} or { fromServices = {}; defaultBoundary = "none"; };

      # Check both directions (isolation is symmetric for safety)
      svc1RequiresFromSvc2 = svc1Spec.fromServices.${svc2} or svc1Spec.defaultBoundary;
      svc2RequiresFromSvc1 = svc2Spec.fromServices.${svc1} or svc2Spec.defaultBoundary;

      # Take the stricter requirement
      level1 = boundaries.${svc1RequiresFromSvc2}.level;
      level2 = boundaries.${svc2RequiresFromSvc1}.level;
    in
      if level1 >= level2 then svc1RequiresFromSvc2 else svc2RequiresFromSvc1;

  # Check if a boundary satisfies a requirement
  satisfies = actualBoundary: requiredBoundary:
    boundaries.${actualBoundary}.level >= boundaries.${requiredBoundary}.level;

  # ==========================================================================
  # Documentation
  # ==========================================================================

  documentProfile = profile:
    let
      isolation = forProfile profile;
    in
      concatStringsSep "\n" (mapAttrsToList (svc: spec:
        let
          fromDesc = concatStringsSep ", " (mapAttrsToList (from: boundary:
            "${from}:${boundary}"
          ) (spec.fromServices or {}));
        in
          "${svc}: default=${spec.defaultBoundary or "none"}" +
          (if fromDesc != "" then " | ${fromDesc}" else "") +
          " [${concatStringsSep "," (spec.controls or [])}]"
      ) isolation);
}
