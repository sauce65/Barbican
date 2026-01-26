# Barbican Topology Validator
#
# Validates a deployment topology against isolation boundary requirements.
# This is the interface between infrastructure provisioning (e.g., Terraform)
# and security compliance validation (Barbican).
#
# The validator is deployment-target agnostic. It takes a topology declaration
# and checks whether the placement satisfies FedRAMP isolation requirements.
#
# Usage from an infrastructure provisioner:
#   barbican.lib.topology.validate {
#     profile = "fedramp-moderate";
#     topology = { machines = { ... }; };
#   }
{ lib }:

with lib;

let
  boundariesLib = import ./isolation-boundaries.nix { inherit lib; };
in rec {
  # ==========================================================================
  # Topology Schema
  # ==========================================================================
  #
  # The topology describes the physical and logical structure of a deployment:
  #
  # topology = {
  #   machines = {
  #     "machine-name" = {
  #       # Optional: metadata about the machine
  #       provider = "aws";  # aws, gcp, azure, bare-metal, local
  #       instanceType = "t3.medium";
  #
  #       # VMs running on this machine (can be empty for bare-metal services)
  #       vms = {
  #         "vm-name" = {
  #           services = [ "vault" "postgres" ];  # Services in this VM
  #         };
  #       };
  #
  #       # Services running directly on machine (no VM layer)
  #       services = [ "service-name" ];
  #     };
  #   };
  # };

  # ==========================================================================
  # Topology Analysis
  # ==========================================================================

  # Extract all services and their placement from topology
  analyzeTopology = topology:
    let
      machines = topology.machines or {};

      # Process each machine
      analyzeMachine = machineName: machine:
        let
          vms = machine.vms or {};
          directServices = machine.services or [];

          # Services in VMs
          vmServices = concatLists (mapAttrsToList (vmName: vm:
            map (svc: {
              service = svc;
              inherit machineName vmName;
              boundary = "hypervisor";  # VM provides hypervisor isolation
            }) (vm.services or [])
          ) vms);

          # Services directly on machine (no VM)
          machineServices = map (svc: {
            service = svc;
            inherit machineName;
            vmName = null;
            boundary = "physical";  # Direct on machine
          }) directServices;

        in vmServices ++ machineServices;

      allPlacements = concatLists (mapAttrsToList analyzeMachine machines);

      # Build lookup: service -> { machine, vm, boundary }
      servicePlacement = listToAttrs (map (p:
        nameValuePair p.service {
          machine = p.machineName;
          vm = p.vmName;
          boundary = p.boundary;
        }
      ) allPlacements);

    in {
      placements = allPlacements;
      inherit servicePlacement;
      services = map (p: p.service) allPlacements;
      machines = attrNames machines;
    };

  # Determine the actual isolation boundary between two services
  actualBoundary = analysis: svc1: svc2:
    let
      p1 = analysis.servicePlacement.${svc1} or null;
      p2 = analysis.servicePlacement.${svc2} or null;
    in
      if p1 == null || p2 == null then
        # Service not in topology
        null
      else if p1.machine != p2.machine then
        # Different machines = physical isolation
        "physical"
      else if p1.vm != null && p2.vm != null && p1.vm != p2.vm then
        # Same machine, different VMs = hypervisor isolation
        "hypervisor"
      else if p1.vm != null && p2.vm == null then
        # One in VM, one direct on machine = hypervisor (VM is isolated from host)
        "hypervisor"
      else if p1.vm == null && p2.vm != null then
        "hypervisor"
      else if p1.vm == p2.vm && p1.vm != null then
        # Same VM = process isolation only
        "process"
      else
        # Same machine, no VMs, both direct = process isolation
        "process";

  # ==========================================================================
  # Validation
  # ==========================================================================

  # Main validation function
  # Returns { valid, errors, warnings, analysis }
  validate = { profile, topology, overrides ? {} }:
    let
      isolation = boundariesLib.forProfile profile;
      analysis = analyzeTopology topology;

      # Check each pair of services
      servicePairs =
        let svcs = analysis.services;
        in concatLists (imap0 (i: svc1:
          map (svc2: { inherit svc1 svc2; }) (drop (i + 1) svcs)
        ) svcs);

      # Validate each pair
      pairResults = map (pair:
        let
          required = boundariesLib.requiredBoundary profile pair.svc1 pair.svc2;
          actual = actualBoundary analysis pair.svc1 pair.svc2;
          satisfies = actual != null && boundariesLib.satisfies actual required;

          # Get isolation specs for error messages
          svc1Spec = isolation.${pair.svc1} or {};
          svc2Spec = isolation.${pair.svc2} or {};
          canOverride = (svc1Spec.canOverride or true) && (svc2Spec.canOverride or true);

          # Check if there's an override allowing this
          overrideKey = "${pair.svc1}:${pair.svc2}";
          reverseKey = "${pair.svc2}:${pair.svc1}";
          hasOverride = hasAttr overrideKey (overrides.allowPairs or {}) ||
                       hasAttr reverseKey (overrides.allowPairs or {});

        in {
          inherit (pair) svc1 svc2;
          inherit required actual satisfies canOverride hasOverride;

          # Placement info for error messages
          svc1Placement = analysis.servicePlacement.${pair.svc1} or null;
          svc2Placement = analysis.servicePlacement.${pair.svc2} or null;
        }
      ) servicePairs;

      # Separate errors and warnings
      violations = filter (r: !r.satisfies && !r.hasOverride) pairResults;

      errors = map (r:
        let
          requiredLevel = boundariesLib.boundaries.${r.required}.level;
          actualLevel = boundariesLib.boundaries.${r.actual or "none"}.level;
          canFix = r.canOverride;

          # Safely get placement info (handle null values explicitly)
          svc1Machine = if r.svc1Placement != null then r.svc1Placement.machine else "?";
          svc1Vm = if r.svc1Placement != null then
            (if r.svc1Placement.vm != null then r.svc1Placement.vm else "direct")
            else "?";
          svc2Machine = if r.svc2Placement != null then r.svc2Placement.machine else "?";
          svc2Vm = if r.svc2Placement != null then
            (if r.svc2Placement.vm != null then r.svc2Placement.vm else "direct")
            else "?";
        in {
          type = "isolation_violation";
          severity = if canFix then "warning" else "error";
          services = [ r.svc1 r.svc2 ];
          required = r.required;
          actual = r.actual or "unknown";
          message =
            "'${r.svc1}' and '${r.svc2}' require ${r.required} isolation " +
            "but have ${r.actual or "unknown"} " +
            "(${r.svc1} on ${svc1Machine}/${svc1Vm}, " +
            "${r.svc2} on ${svc2Machine}/${svc2Vm})";
          canOverride = canFix;
          controls = unique (
            (isolation.${r.svc1}.controls or []) ++
            (isolation.${r.svc2}.controls or [])
          );
        }
      ) violations;

      # Hard errors (canOverride = false)
      hardErrors = filter (e: e.severity == "error") errors;

      # Soft errors (can be overridden with justification)
      softErrors = filter (e: e.severity == "warning") errors;

    in {
      valid = length hardErrors == 0;
      validWithOverrides = length hardErrors == 0 && length softErrors == 0;
      errors = hardErrors;
      warnings = softErrors;
      inherit analysis;
      summary = {
        profile = profile;
        servicesChecked = length analysis.services;
        pairsChecked = length servicePairs;
        violations = length violations;
        hardViolations = length hardErrors;
        softViolations = length softErrors;
      };
    };

  # ==========================================================================
  # Assertion Generator
  # ==========================================================================
  #
  # Generate NixOS assertions from validation results

  mkAssertions = validationResult:
    let
      inherit (validationResult) errors warnings;
    in
      # Hard errors become assertions (fail the build)
      (map (e: {
        assertion = false;
        message = "[FEDRAMP] ${e.message}\n  Controls: ${toString e.controls}";
      }) errors) ++
      # Warnings become trace messages (logged but don't fail)
      (map (w: {
        assertion = true;  # Don't fail, just warn
        message = "[FEDRAMP WARNING] ${w.message}";
      }) warnings);

  # ==========================================================================
  # Topology Helpers
  # ==========================================================================

  # Create topology from external provisioner machine definitions
  fromProvisionerMachines = { machines, serviceMapping }:
    # serviceMapping = { "machine-name" = { vms = { ... }; services = [...]; }; }
    {
      machines = mapAttrs (name: machine:
        let
          mapping = serviceMapping.${name} or {};
        in {
          provider = "aws";
          instanceType = machine.terraform.instanceType or "unknown";
          vms = mapping.vms or {};
          services = mapping.services or [];
        }
      ) machines;
    };

  # Create topology from DPE cluster definition
  fromDpeCluster = clusterConfig:
    # Convert DPE's VM-centric model to topology
    let
      vms = clusterConfig.vms or {};
    in {
      machines = {
        # DPE assumes single-host QEMU, so one logical "machine"
        "localhost" = {
          provider = "local";
          vms = mapAttrs (vmName: vm: {
            services = vm.services or [];
          }) vms;
        };
      };
    };

  # ==========================================================================
  # Documentation
  # ==========================================================================

  # Generate human-readable validation report
  formatReport = result:
    let
      header = ''
        ═══════════════════════════════════════════════════════════════
        BARBICAN TOPOLOGY VALIDATION REPORT
        Profile: ${result.summary.profile}
        ═══════════════════════════════════════════════════════════════

        Services checked: ${toString result.summary.servicesChecked}
        Service pairs checked: ${toString result.summary.pairsChecked}
        Violations found: ${toString result.summary.violations}
          - Hard violations: ${toString result.summary.hardViolations}
          - Soft violations: ${toString result.summary.softViolations}

        Status: ${if result.valid then "✓ VALID" else "✗ INVALID"}
      '';

      errorSection = if result.errors == [] then "" else ''

        ───────────────────────────────────────────────────────────────
        ERRORS (must fix)
        ───────────────────────────────────────────────────────────────
        ${concatMapStringsSep "\n" (e: ''
          ✗ ${e.message}
            Required: ${e.required} | Actual: ${e.actual}
            Controls: ${toString e.controls}
        '') result.errors}
      '';

      warningSection = if result.warnings == [] then "" else ''

        ───────────────────────────────────────────────────────────────
        WARNINGS (can override with justification)
        ───────────────────────────────────────────────────────────────
        ${concatMapStringsSep "\n" (w: ''
          ⚠ ${w.message}
            Required: ${w.required} | Actual: ${w.actual}
            Controls: ${toString w.controls}
        '') result.warnings}
      '';

    in header + errorSection + warningSection;
}
