# Barbican Security Module: Cluster Orchestration
#
# Provides declarative multi-VM cluster deployment with intelligent service placement.
# Services are mapped to VMs based on available images, security constraints, and
# developer preferences.
#
# NIST 800-53 Controls:
# - SC-7: Boundary Protection (network isolation between VMs)
# - SC-32: Information System Partitioning (service separation)
# - AC-4: Information Flow Enforcement (controlled inter-VM communication)
# - CM-2: Baseline Configuration (reproducible VM configurations)
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.cluster;

  # Import cluster libraries
  constraints = import ../lib/cluster-constraints.nix { inherit lib; };
  images = import ../lib/cluster-images.nix { inherit lib; };
  resolver = import ../lib/cluster-resolver.nix { inherit lib; };

  # ==========================================================================
  # Type Definitions
  # ==========================================================================

  # Service placement mode
  placementType = types.enum [
    "auto"           # Let resolver decide based on constraints and available images
    "dedicated"      # Force this service onto its own VM
    "colocate"       # Prefer colocation with other services (hint, not guarantee)
    "colocate-with"  # Colocate with a specific named service
  ];

  # Health check type
  healthCheckType = types.submodule {
    options = {
      type = mkOption {
        type = types.enum [ "http" "https" "tcp" "exec" ];
        description = "Type of health check";
      };

      target = mkOption {
        type = types.str;
        description = "Health check target (URL for http/https, host:port for tcp, command for exec)";
        example = "/health";
      };

      interval = mkOption {
        type = types.int;
        default = 5;
        description = "Health check interval in seconds";
      };

      timeout = mkOption {
        type = types.int;
        default = 10;
        description = "Health check timeout in seconds";
      };

      retries = mkOption {
        type = types.int;
        default = 3;
        description = "Number of retries before marking unhealthy";
      };
    };
  };

  # Service definition submodule
  serviceType = types.submodule ({ name, ... }: {
    options = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable this service in the cluster";
      };

      placement = mkOption {
        type = placementType;
        default = "auto";
        description = ''
          Service placement strategy:
          - auto: Let the resolver decide based on constraints and available images
          - dedicated: Force this service onto its own dedicated VM
          - colocate: Prefer colocation with other services when possible
          - colocate-with: Colocate with a specific named service
        '';
      };

      colocateWith = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "When placement is 'colocate-with', specifies which service to colocate with";
        example = "app";
      };

      priority = mkOption {
        type = types.int;
        default = 100;
        description = ''
          Boot priority (lower = earlier). Services with dependencies automatically
          have their priority adjusted.

          Suggested ranges:
          - 0-49: Infrastructure (vault, PKI)
          - 50-99: Data layer (postgres, redis)
          - 100-149: Application layer
          - 150+: Auxiliary services (observability, monitoring)
        '';
      };

      dependsOn = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Services that must be healthy before this service starts";
        example = [ "vault" "postgres" ];
      };

      healthCheck = mkOption {
        type = types.nullOr healthCheckType;
        default = null;
        description = "Health check configuration for this service";
      };

      ports = mkOption {
        type = types.listOf (types.submodule {
          options = {
            port = mkOption {
              type = types.int;
              description = "Port number";
            };
            protocol = mkOption {
              type = types.enum [ "tcp" "udp" "http" "https" "grpc" ];
              default = "tcp";
              description = "Protocol";
            };
            public = mkOption {
              type = types.bool;
              default = false;
              description = "Whether this port should be exposed externally";
            };
          };
        });
        default = [];
        description = "Ports exposed by this service";
      };

      resources = mkOption {
        type = types.submodule {
          options = {
            memory = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Memory allocation (e.g., '512M', '2G')";
            };
            cpus = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = "CPU cores allocated";
            };
            disk = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "Disk allocation (e.g., '10G', '100G')";
            };
          };
        };
        default = {};
        description = "Resource requirements for this service";
      };

      config = mkOption {
        type = types.attrsOf types.anything;
        default = {};
        description = "Service-specific configuration passed to the VM module";
      };
    };
  });

  # Application definition submodule
  applicationType = types.submodule {
    options = {
      name = mkOption {
        type = types.str;
        description = "Application name";
        example = "dpe";
      };

      module = mkOption {
        type = types.path;
        description = "Path to the NixOS module for this application";
      };

      healthCheck = mkOption {
        type = types.nullOr healthCheckType;
        default = null;
        description = "Health check for the application";
      };

      dependsOn = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Services that must be healthy before the application starts";
        example = [ "postgres" "vault" ];
      };

      ports = mkOption {
        type = types.listOf (types.submodule {
          options = {
            port = mkOption { type = types.int; };
            protocol = mkOption {
              type = types.enum [ "tcp" "udp" "http" "https" "grpc" ];
              default = "https";
            };
            public = mkOption { type = types.bool; default = true; };
          };
        });
        default = [];
        description = "Ports exposed by the application";
      };
    };
  };

  # Network configuration submodule
  networkType = types.submodule {
    options = {
      subnet = mkOption {
        type = types.str;
        default = "10.100.0.0/24";
        description = "Subnet for cluster internal network";
      };

      gateway = mkOption {
        type = types.str;
        default = "10.100.0.1";
        description = "Gateway address";
      };

      dns = mkOption {
        type = types.listOf types.str;
        default = [ "10.100.0.1" ];
        description = "DNS servers for cluster VMs";
      };

      domain = mkOption {
        type = types.str;
        default = "cluster.local";
        description = "Internal domain for service discovery";
      };
    };
  };

in {
  options.barbican.cluster = {
    enable = mkEnableOption "Barbican cluster orchestration";

    # ========================================================================
    # Core Configuration
    # ========================================================================

    name = mkOption {
      type = types.str;
      default = "barbican-cluster";
      description = "Cluster name (used for resource naming and identification)";
    };

    profile = mkOption {
      type = types.enum [ "development" "fedramp-low" "fedramp-moderate" "fedramp-high" ];
      default = "fedramp-moderate";
      description = ''
        Security profile for the cluster. This determines:
        - Which services require isolation (dedicated VMs)
        - Network security policies
        - Audit and logging requirements
        - Encryption requirements
      '';
    };

    # ========================================================================
    # Service Declarations
    # ========================================================================

    services = mkOption {
      type = types.submodule {
        options = {
          vault = mkOption {
            type = serviceType;
            default = {};
            description = "HashiCorp Vault for PKI and secrets management";
          };

          postgres = mkOption {
            type = serviceType;
            default = {};
            description = "PostgreSQL database with Barbican security hardening";
          };

          observability = mkOption {
            type = serviceType;
            default = {};
            description = "Observability stack (Prometheus, Grafana, Loki)";
          };

          redis = mkOption {
            type = serviceType;
            default = {};
            description = "Redis for caching and session storage";
          };

          keycloak = mkOption {
            type = serviceType;
            default = {};
            description = "Keycloak for identity and access management";
          };
        };
      };
      default = {};
      description = "Infrastructure services to deploy";
    };

    # ========================================================================
    # Application
    # ========================================================================

    application = mkOption {
      type = types.nullOr applicationType;
      default = null;
      description = "The application to deploy on this cluster";
    };

    # ========================================================================
    # Network Configuration
    # ========================================================================

    network = mkOption {
      type = networkType;
      default = {};
      description = "Cluster network configuration";
    };

    # ========================================================================
    # VM Image Registry
    # ========================================================================

    images = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          provides = mkOption {
            type = types.listOf types.str;
            description = "Services this image can provide";
            example = [ "vault" "postgres" "observability" "app-runtime" ];
          };

          module = mkOption {
            type = types.path;
            description = "Path to NixOS module for this VM image";
          };

          resources = mkOption {
            type = types.submodule {
              options = {
                memory = mkOption { type = types.str; default = "2G"; };
                cpus = mkOption { type = types.int; default = 2; };
                disk = mkOption { type = types.str; default = "20G"; };
              };
            };
            default = {};
            description = "Default resource allocation for VMs using this image";
          };
        };
      });
      default = {};
      description = ''
        Registry of available VM images. The resolver uses this to map
        requested services to actual VMs. When images are coarse (one image
        provides many services), services are colocated. As images become
        granular, services can be separated.
      '';
    };

    # ========================================================================
    # Constraint Overrides
    # ========================================================================

    constraints = mkOption {
      type = types.submodule {
        options = {
          overrides = mkOption {
            type = types.attrsOf (types.submodule {
              options = {
                isolation = mkOption {
                  type = types.nullOr (types.enum [ "required" "recommended" "optional" ]);
                  default = null;
                  description = "Override isolation requirement for this service";
                };
              };
            });
            default = {};
            description = "Per-service constraint overrides";
          };

          allowSharing = mkOption {
            type = types.listOf (types.listOf types.str);
            default = [];
            description = ''
              Explicit sharing allowances. Each inner list contains services
              that may share a VM even if the profile would normally separate them.
            '';
            example = [ [ "postgres" "vault" ] ];
          };

          denySharing = mkOption {
            type = types.listOf (types.listOf types.str);
            default = [];
            description = ''
              Explicit sharing denials. Each inner list contains services
              that must NOT share a VM even if the profile would allow it.
            '';
            example = [ [ "app" "postgres" ] ];
          };
        };
      };
      default = {};
      description = "Constraint overrides for advanced deployment scenarios";
    };

    # ========================================================================
    # Output Configuration
    # ========================================================================

    output = mkOption {
      type = types.submodule {
        options = {
          directory = mkOption {
            type = types.path;
            default = ./cluster-output;
            description = "Directory for generated cluster configuration";
          };

          generateOrchestration = mkOption {
            type = types.bool;
            default = true;
            description = "Generate orchestration scripts (deploy.sh, teardown.sh, etc.)";
          };

          generateNetworkConfig = mkOption {
            type = types.bool;
            default = true;
            description = "Generate network topology configuration";
          };
        };
      };
      default = {};
      description = "Output configuration for generated artifacts";
    };
  };

  # ==========================================================================
  # Configuration Implementation
  # ==========================================================================

  config = mkIf cfg.enable {
    # Get profile-specific constraints
    # These are merged with any user overrides
    _module.args.clusterConstraints = constraints.forProfile cfg.profile;

    # Resolve services to VMs
    _module.args.clusterTopology = resolver.resolve {
      services = cfg.services;
      application = cfg.application;
      images = cfg.images;
      constraints = constraints.merge {
        profileConstraints = constraints.forProfile cfg.profile;
        userOverrides = cfg.constraints;
      };
      network = cfg.network;
    };

    # Assertions for constraint validation
    assertions = [
      # Profile constraints that cannot be overridden
      {
        assertion = cfg.profile != "fedramp-high" ||
          !cfg.services.vault.enable ||
          cfg.services.vault.placement == "dedicated" ||
          (cfg.constraints.overrides.vault.isolation or null) == "required";
        message = ''
          FedRAMP High profile requires Vault to run on a dedicated VM.
          Either set services.vault.placement = "dedicated" or don't use FedRAMP High.
          This constraint cannot be overridden for compliance reasons.
        '';
      }
      {
        assertion = cfg.profile != "fedramp-high" ||
          !cfg.services.postgres.enable ||
          cfg.services.postgres.placement == "dedicated" ||
          cfg.services.postgres.placement == "auto";
        message = ''
          FedRAMP High profile requires PostgreSQL isolation.
          Do not use placement = "colocate" for postgres with FedRAMP High.
        '';
      }
      # Validate colocate-with references
      {
        assertion = all (name: svc:
          svc.placement != "colocate-with" || svc.colocateWith != null
        ) (filterAttrs (_: svc: svc.enable) cfg.services);
        message = ''
          Services with placement = "colocate-with" must specify colocateWith.
        '';
      }
      # Validate colocate-with targets exist
      {
        assertion = all (name: svc:
          svc.placement != "colocate-with" ||
          (cfg.services.${svc.colocateWith}.enable or false) ||
          (cfg.application != null && cfg.application.name == svc.colocateWith)
        ) (filterAttrs (_: svc: svc.enable) cfg.services);
        message = ''
          colocateWith must reference an enabled service or the application.
        '';
      }
      # At least one image must be available
      {
        assertion = cfg.images != {};
        message = ''
          No VM images defined. Define at least one image in barbican.cluster.images.
          For a single-VM deployment, define a "full" image that provides all services.
        '';
      }
      # All enabled services must be providable by some image
      {
        assertion =
          let
            enabledServices = attrNames (filterAttrs (_: svc: svc.enable) cfg.services);
            allProvided = unique (concatMap (img: img.provides) (attrValues cfg.images));
            appProvided = if cfg.application != null then [ "app-runtime" ] else [];
          in
            all (svc: elem svc (allProvided ++ appProvided ++ [ "app-runtime" ])) enabledServices;
        message = ''
          Some enabled services cannot be provided by any available VM image.
          Check that your images provide all required services.
        '';
      }
    ];

    # Warnings for non-compliance recommendations
    warnings =
      let
        moderateVaultWarning =
          if cfg.profile == "fedramp-moderate" &&
             cfg.services.vault.enable &&
             cfg.services.vault.placement != "dedicated"
          then [ "FedRAMP Moderate recommends Vault on a dedicated VM. Consider setting services.vault.placement = \"dedicated\"." ]
          else [];
      in
        moderateVaultWarning;
  };
}
