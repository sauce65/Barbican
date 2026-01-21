# Barbican Cluster Resolver Library
#
# The resolver is the core intelligence that maps declared services to VMs.
# It takes into account:
#   - Available VM images (what services they can provide)
#   - Security constraints (what services must be isolated)
#   - Developer preferences (placement hints, explicit overrides)
#   - Service dependencies (boot order)
#
# The resolver produces a topology: { vmName -> { image, services, config } }
#
# Algorithm Overview:
#   1. Collect all enabled services
#   2. Apply placement constraints (dedicated, colocate-with)
#   3. Group remaining services by available images
#   4. Validate against security constraints
#   5. Generate network topology
#   6. Output deployment plan
{ lib }:

with lib;

let
  constraints = import ./cluster-constraints.nix { inherit lib; };
  images = import ./cluster-images.nix { inherit lib; };
in rec {
  # ==========================================================================
  # Main Resolution Function
  # ==========================================================================

  resolve = {
    services,          # Declared services (from barbican.cluster.services)
    application,       # Application definition (from barbican.cluster.application)
    images,           # Available VM images (from barbican.cluster.images)
    constraints,      # Merged constraints (profile + overrides)
    network,          # Network configuration
  }:
    let
      # Step 1: Collect enabled services
      enabledServices = collectEnabledServices services application;

      # Step 2: Apply explicit placements
      explicitPlacements = resolveExplicitPlacements enabledServices constraints;

      # Step 3: Place remaining services
      remainingServices = filter (svc:
        !hasAttr svc.name explicitPlacements.dedicated &&
        !hasAttr svc.name explicitPlacements.colocated
      ) enabledServices;

      autoPlacement = resolveAutoPlacement {
        services = remainingServices;
        inherit images constraints;
        existingPlacements = explicitPlacements;
      };

      # Step 4: Merge all placements
      allPlacements = mergePlacements explicitPlacements autoPlacement;

      # Step 5: Validate
      validation = validateTopology allPlacements constraints;

      # Step 6: Generate topology
      topology = generateTopology {
        placements = allPlacements;
        inherit images network;
        enabledServices = enabledServices;
      };

    in topology // {
      _validation = validation;
      _enabledServices = map (s: s.name) enabledServices;
    };

  # ==========================================================================
  # Service Collection
  # ==========================================================================

  # Collect all enabled services into a normalized list
  collectEnabledServices = services: application:
    let
      # Extract enabled infrastructure services
      infraServices = mapAttrsToList (name: svc:
        if svc.enable or false then {
          inherit name;
          type = "infrastructure";
          placement = svc.placement or "auto";
          colocateWith = svc.colocateWith or null;
          priority = svc.priority or 100;
          dependsOn = svc.dependsOn or [];
          healthCheck = svc.healthCheck or null;
          ports = svc.ports or [];
          resources = svc.resources or {};
          config = svc.config or {};
        } else null
      ) services;

      # Add application if defined
      appService = if application != null then [{
        name = application.name;
        type = "application";
        placement = "auto";
        colocateWith = null;
        priority = 100;
        dependsOn = application.dependsOn or [];
        healthCheck = application.healthCheck or null;
        ports = application.ports or [];
        resources = {};
        config = { module = application.module; };
      }] else [];

    in filter (x: x != null) infraServices ++ appService;

  # ==========================================================================
  # Explicit Placement Resolution
  # ==========================================================================

  resolveExplicitPlacements = enabledServices: constraints:
    let
      # Services with placement = "dedicated"
      dedicatedServices = filter (svc: svc.placement == "dedicated") enabledServices;

      # Services with placement = "colocate-with"
      colocateWithServices = filter (svc: svc.placement == "colocate-with") enabledServices;

      # Services that MUST be dedicated due to constraints (regardless of user preference)
      constraintDedicated = filter (svc:
        constraints.requiresDedicated constraints svc.name
      ) enabledServices;

      # Build dedicated placements
      dedicatedPlacements = foldl' (acc: svc:
        acc // { ${svc.name} = { vm = "${svc.name}-0"; services = [ svc ]; }; }
      ) {} (dedicatedServices ++ constraintDedicated);

      # Build colocate-with mappings
      colocatedPlacements = foldl' (acc: svc:
        let
          target = svc.colocateWith;
          existing = acc.${target} or { vm = null; services = []; };
        in
          acc // { ${target} = existing // { services = existing.services ++ [ svc ]; }; }
      ) {} colocateWithServices;

    in {
      dedicated = dedicatedPlacements;
      colocated = colocatedPlacements;
    };

  # ==========================================================================
  # Automatic Placement Resolution
  # ==========================================================================

  resolveAutoPlacement = { services, images, constraints, existingPlacements }:
    let
      # Find images that can host each service
      serviceImageMapping = map (svc:
        let
          candidates = filterAttrs (_: img:
            elem svc.name img.provides || elem "app-runtime" img.provides && svc.type == "application"
          ) images;
        in {
          service = svc;
          candidateImages = attrNames candidates;
        }
      ) services;

      # Group services by their candidate images
      # Services with identical candidates can potentially share
      groupByImageSet = foldl' (acc: mapping:
        let
          key = concatStringsSep "," (sort lessThan mapping.candidateImages);
          existing = acc.${key} or [];
        in
          acc // { ${key} = existing ++ [ mapping.service ]; }
      ) {} serviceImageMapping;

      # For each group, determine if they can share based on constraints
      resolveGroup = imageKey: groupServices:
        let
          # Check all pairs for sharing compatibility
          canAllShare = all (svc1:
            all (svc2:
              svc1.name == svc2.name || constraints.canShare constraints svc1.name svc2.name
            ) groupServices
          ) groupServices;

          # Pick best image from candidates
          candidateImages = filter (x: x != "") (splitString "," imageKey);
          bestImage = head candidateImages; # TODO: smarter selection
        in
          if canAllShare && length groupServices > 0 then
            # All services share one VM
            [{
              vm = "${bestImage}-0";
              image = bestImage;
              services = groupServices;
            }]
          else
            # Each service gets its own VM
            imap0 (i: svc: {
              vm = "${svc.name}-${toString i}";
              image = bestImage;
              services = [ svc ];
            }) groupServices;

      # Flatten all resolved groups
      resolvedGroups = concatLists (mapAttrsToList resolveGroup groupByImageSet);

    in {
      auto = foldl' (acc: group:
        acc // { ${group.vm} = group; }
      ) {} resolvedGroups;
    };

  # ==========================================================================
  # Placement Merging
  # ==========================================================================

  mergePlacements = explicit: auto:
    let
      # Start with dedicated placements
      base = mapAttrs (name: placement: {
        vm = placement.vm;
        image = name; # Dedicated uses service name as image hint
        services = placement.services;
        dedicated = true;
      }) explicit.dedicated;

      # Add colocated services to their target VMs
      withColocated = foldl' (acc: targetName:
        let
          colocatedServices = explicit.colocated.${targetName}.services;
          targetVm = acc.${targetName} or auto.auto.${targetName} or { services = []; };
        in
          acc // {
            ${targetName} = targetVm // {
              services = targetVm.services ++ colocatedServices;
            };
          }
      ) base (attrNames explicit.colocated);

      # Add auto-placed services that aren't already placed
      alreadyPlaced = concatMap (p: map (s: s.name) p.services) (attrValues withColocated);
      remainingAuto = filterAttrs (vmName: vm:
        !all (svc: elem svc.name alreadyPlaced) vm.services
      ) auto.auto;

    in withColocated // remainingAuto;

  # ==========================================================================
  # Topology Validation
  # ==========================================================================

  validateTopology = placements: constraints:
    let
      # Convert placements to format expected by constraints.validatePlacement
      placementMap = mapAttrs (_: p: map (s: s.name) p.services) placements;
      validation = constraints.validatePlacement {
        inherit constraints;
        placement = placementMap;
      };
    in validation;

  # ==========================================================================
  # Topology Generation
  # ==========================================================================

  generateTopology = { placements, images, network, enabledServices }:
    let
      # Assign IPs to VMs
      vmList = attrNames placements;
      vmIps = imap0 (i: vmName: {
        name = vmName;
        ip = "10.100.0.${toString (10 + i)}";
      }) vmList;
      ipMap = listToAttrs (map (v: nameValuePair v.name v.ip) vmIps);

      # Build VM configurations
      vms = mapAttrs (vmName: placement:
        let
          vmIp = ipMap.${vmName};
          serviceNames = map (s: s.name) placement.services;

          # Collect ports from all services
          allPorts = concatMap (s: s.ports) placement.services;

          # Determine dependencies
          allDependsOn = unique (concatMap (s: s.dependsOn) placement.services);
          externalDeps = filter (dep: !elem dep serviceNames) allDependsOn;

          # Find VMs that provide dependencies
          depVms = filter (otherVm:
            any (dep: elem dep (map (s: s.name) placements.${otherVm}.services)) externalDeps
          ) (filter (v: v != vmName) vmList);
        in {
          inherit vmName;
          ip = vmIp;
          image = placement.image or "full";
          services = serviceNames;
          ports = allPorts;
          dependsOnVms = depVms;
          dedicated = placement.dedicated or false;
          config = foldl' (acc: svc: acc // { ${svc.name} = svc.config; }) {} placement.services;
        }
      ) placements;

      # Calculate boot order based on dependencies
      bootOrder = calculateBootOrder vms;

      # Generate network flows (who talks to whom)
      flows = generateNetworkFlows vms enabledServices;

    in {
      inherit vms bootOrder flows;
      network = network // { hosts = ipMap; };
    };

  # ==========================================================================
  # Boot Order Calculation
  # ==========================================================================

  calculateBootOrder = vms:
    let
      # Build dependency graph
      vmDeps = mapAttrs (_: vm: vm.dependsOnVms) vms;

      # Topological sort with stages
      sortVms = remaining: sorted:
        if remaining == [] then sorted
        else
          let
            # Find VMs with no remaining dependencies
            ready = filter (vm:
              all (dep: elem dep (concatLists sorted)) (vmDeps.${vm} or [])
            ) remaining;

            newRemaining = filter (vm: !elem vm ready) remaining;
          in
            if ready == [] then
              throw "Circular dependency in VM boot order: ${toString remaining}"
            else
              sortVms newRemaining (sorted ++ [ ready ]);

      stages = sortVms (attrNames vms) [];

    in imap0 (i: stage: {
      stage = i;
      name = if i == 0 then "infrastructure"
             else if i == 1 then "data"
             else if i == 2 then "application"
             else "stage-${toString i}";
      vms = stage;
    }) stages;

  # ==========================================================================
  # Network Flow Generation
  # ==========================================================================

  generateNetworkFlows = vms: enabledServices:
    let
      # For each service dependency, create a flow
      serviceDepFlows = concatLists (map (svc:
        map (dep:
          let
            sourceVm = findFirst (vmName:
              elem svc.name (vms.${vmName}.services or [])
            ) null (attrNames vms);

            targetVm = findFirst (vmName:
              elem dep (vms.${vmName}.services or [])
            ) null (attrNames vms);

            # Find port for the dependency
            targetService = findFirst (s: s.name == dep) null enabledServices;
            targetPort = head ((targetService.ports or [{ port = 0; }]));
          in
            if sourceVm != null && targetVm != null && sourceVm != targetVm then {
              from = sourceVm;
              to = targetVm;
              port = targetPort.port or 0;
              protocol = targetPort.protocol or "tcp";
              purpose = "${svc.name} -> ${dep}";
            } else null
        ) (svc.dependsOn or [])
      ) enabledServices);

    in filter (f: f != null) serviceDepFlows;

  # ==========================================================================
  # Utility Functions
  # ==========================================================================

  # Find first element matching predicate, or default
  findFirst = pred: default: list:
    let matches = filter pred list;
    in if matches == [] then default else head matches;
}
