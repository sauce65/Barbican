# Barbican Cluster Orchestration Generator
#
# Generates deployment artifacts from a resolved cluster topology:
#   - NixOS configurations for each VM
#   - Boot order manifest with health checks
#   - Network topology (IPs, firewall rules, DNS)
#   - Secrets bootstrap plan
#   - Orchestration scripts (deploy, status, teardown)
#
# The generator is pure Nix - it produces derivations and script content
# that can be built and executed.
{ lib, pkgs }:

with lib;

rec {
  # ==========================================================================
  # Main Generation Function
  # ==========================================================================

  generate = {
    topology,           # Resolved topology from cluster-resolver
    clusterName,        # Cluster name
    profile,            # Security profile
    outputDir,          # Output directory path
    vmModules ? {},     # Additional NixOS modules per VM
    secretsConfig ? {}, # Secrets configuration
  }:
    let
      bootOrder = generateBootOrder topology;
      networkConfig = generateNetworkConfig topology;
      secretsBootstrap = generateSecretsBootstrap topology secretsConfig;
      vmConfigs = generateVmConfigs topology profile vmModules;
      scripts = generateScripts {
        inherit topology clusterName profile bootOrder networkConfig secretsBootstrap;
      };
    in {
      inherit bootOrder networkConfig secretsBootstrap vmConfigs scripts;

      # Convenience: all artifacts as a single derivation
      all = pkgs.runCommand "cluster-${clusterName}" {} ''
        mkdir -p $out/{vms,orchestration,scripts}

        # Write boot order
        cat > $out/orchestration/boot-order.json << 'EOF'
        ${builtins.toJSON bootOrder}
        EOF

        # Write network config
        cat > $out/orchestration/network.json << 'EOF'
        ${builtins.toJSON networkConfig}
        EOF

        # Write secrets bootstrap
        cat > $out/orchestration/secrets-bootstrap.json << 'EOF'
        ${builtins.toJSON secretsBootstrap}
        EOF

        # Write VM configs (as JSON for inspection)
        cat > $out/vms/topology.json << 'EOF'
        ${builtins.toJSON vmConfigs}
        EOF

        # Write scripts
        cp ${scripts.deploy} $out/scripts/deploy.sh
        cp ${scripts.status} $out/scripts/status.sh
        cp ${scripts.teardown} $out/scripts/teardown.sh
        cp ${scripts.lib} $out/scripts/lib.sh

        chmod +x $out/scripts/*.sh
      '';
    };

  # ==========================================================================
  # Boot Order Generation
  # ==========================================================================

  generateBootOrder = topology:
    let
      stages = topology.bootOrder;
    in {
      version = "1.0";
      stages = map (stage: {
        inherit (stage) stage name;
        vms = map (vmName:
          let vm = topology.vms.${vmName};
          in {
            name = vmName;
            ip = vm.ip;
            image = vm.image;
            services = vm.services;
            healthCheck = mkHealthCheck vm;
          }
        ) stage.vms;
      }) stages;
    };

  mkHealthCheck = vm:
    let
      # Determine health check based on primary service
      primaryService = head (vm.services or [ "unknown" ]);
      defaultChecks = {
        vault = {
          type = "http";
          path = "/v1/sys/health";
          port = 8200;
          expectedStatus = [ 200 429 472 473 501 503 ];  # Vault health statuses
          timeout = 60;
          retries = 12;
          interval = 5;
        };
        postgres = {
          type = "tcp";
          port = 5432;
          timeout = 30;
          retries = 10;
          interval = 3;
        };
        redis = {
          type = "tcp";
          port = 6379;
          timeout = 15;
          retries = 5;
          interval = 2;
        };
        keycloak = {
          type = "http";
          path = "/health/ready";
          port = 8080;
          expectedStatus = [ 200 ];
          timeout = 120;
          retries = 24;
          interval = 5;
        };
        observability = {
          type = "http";
          path = "/-/healthy";
          port = 9090;  # Prometheus
          expectedStatus = [ 200 ];
          timeout = 30;
          retries = 6;
          interval = 5;
        };
        app-runtime = {
          type = "http";
          path = "/health";
          port = 8055;
          expectedStatus = [ 200 ];
          timeout = 60;
          retries = 12;
          interval = 5;
        };
      };
    in
      defaultChecks.${primaryService} or {
        type = "tcp";
        port = 22;  # Fallback to SSH
        timeout = 30;
        retries = 10;
        interval = 3;
      };

  # ==========================================================================
  # Network Configuration Generation
  # ==========================================================================

  generateNetworkConfig = topology:
    let
      network = topology.network;
      hosts = topology.network.hosts;
      flows = topology.flows;

      # Generate /etc/hosts entries
      hostsFile = concatStringsSep "\n" (mapAttrsToList (vmName: ip:
        "${ip} ${vmName} ${vmName}.${network.domain or "cluster.local"}"
      ) hosts);

      # Generate firewall rules per VM
      firewallRules = mapAttrs (vmName: vm:
        let
          # Inbound: from flows where this VM is the target
          inbound = filter (f: f.to == vmName) flows;
          # Outbound: from flows where this VM is the source
          outbound = filter (f: f.from == vmName) flows;
        in {
          inbound = map (f: {
            from = f.from;
            fromIp = hosts.${f.from};
            port = f.port;
            protocol = f.protocol;
            purpose = f.purpose;
          }) inbound;
          outbound = map (f: {
            to = f.to;
            toIp = hosts.${f.to};
            port = f.port;
            protocol = f.protocol;
            purpose = f.purpose;
          }) outbound;
        }
      ) topology.vms;

    in {
      version = "1.0";
      subnet = network.subnet or "10.100.0.0/24";
      gateway = network.gateway or "10.100.0.1";
      dns = network.dns or [ "10.100.0.1" ];
      domain = network.domain or "cluster.local";
      inherit hosts hostsFile firewallRules flows;
    };

  # ==========================================================================
  # Secrets Bootstrap Generation
  # ==========================================================================

  generateSecretsBootstrap = topology: secretsConfig:
    let
      vms = topology.vms;
      bootOrder = topology.bootOrder;

      # Vault is always first (if present)
      vaultVm = findFirst (vmName:
        elem "vault" (vms.${vmName}.services or [])
      ) null (attrNames vms);

      # Generate secrets plan per VM
      vmSecrets = mapAttrs (vmName: vm:
        let
          isVault = elem "vault" vm.services;
          needsVaultCreds = !isVault && vaultVm != null;
        in {
          # Pre-start secrets (must exist before VM boots)
          preStart =
            if isVault then [{
              action = "generate";
              type = "vault-init";
              description = "Initialize Vault and generate unseal keys";
              output = {
                unsealKeys = "/run/secrets/${vmName}/vault-unseal-keys.json";
                rootToken = "/run/secrets/${vmName}/vault-root-token";
              };
            }]
            else if needsVaultCreds then [{
              action = "inject";
              type = "vault-approle";
              description = "Inject Vault AppRole credentials";
              source = {
                vm = vaultVm;
                roleId = "/run/secrets/${vaultVm}/approle-${vmName}-role-id";
                secretId = "/run/secrets/${vaultVm}/approle-${vmName}-secret-id";
              };
              target = {
                roleId = "/run/secrets/${vmName}/vault-role-id";
                secretId = "/run/secrets/${vmName}/vault-secret-id";
              };
            }]
            else [];

          # Post-start actions (after VM is healthy)
          postStart =
            if isVault then
              # Create AppRoles for other VMs
              map (otherVm: {
                action = "create";
                type = "vault-approle";
                description = "Create AppRole for ${otherVm}";
                role = otherVm;
                policies = getVaultPolicies vms.${otherVm}.services;
                output = {
                  roleId = "/run/secrets/${vmName}/approle-${otherVm}-role-id";
                  secretId = "/run/secrets/${vmName}/approle-${otherVm}-secret-id";
                };
              }) (filter (v: v != vmName && !elem "vault" (vms.${v}.services or [])) (attrNames vms))
            else [];

          # Certificates to fetch (for services that need TLS)
          certificates = getCertificateRequirements vm.services vmName;
        }
      ) vms;

    in {
      version = "1.0";
      vaultVm = vaultVm;
      vms = vmSecrets;
      # Execution order follows boot order
      executionOrder = concatMap (stage: stage.vms) bootOrder;
    };

  # Helper: determine Vault policies based on services
  getVaultPolicies = services:
    let
      policyMap = {
        postgres = [ "pki-issue-postgres" "database-creds" ];
        redis = [ "pki-issue-redis" ];
        keycloak = [ "pki-issue-keycloak" "database-creds" ];
        observability = [ "pki-issue-observability" ];
        app-runtime = [ "pki-issue-app" "database-creds-readonly" ];
      };
    in
      unique (concatMap (svc: policyMap.${svc} or []) services);

  # Helper: determine certificate requirements
  getCertificateRequirements = services: vmName:
    let
      certMap = {
        postgres = [{
          name = "postgres-server";
          role = "postgres";
          commonName = vmName;
          altNames = [ "localhost" "postgres" "${vmName}.cluster.local" ];
          ipSans = [ "127.0.0.1" ];
          outputDir = "/var/lib/postgresql/certs";
          owner = "postgres";
          group = "postgres";
        }];
        redis = [{
          name = "redis-server";
          role = "redis";
          commonName = vmName;
          outputDir = "/var/lib/redis/certs";
          owner = "redis";
          group = "redis";
        }];
        keycloak = [{
          name = "keycloak-server";
          role = "keycloak";
          commonName = vmName;
          altNames = [ "localhost" "keycloak" ];
          outputDir = "/var/lib/keycloak/certs";
          owner = "keycloak";
          group = "keycloak";
        }];
        app-runtime = [{
          name = "app-server";
          role = "app";
          commonName = vmName;
          altNames = [ "localhost" "app" ];
          outputDir = "/var/lib/app/certs";
          owner = "app";
          group = "app";
        }];
      };
    in
      concatMap (svc: certMap.${svc} or []) services;

  # ==========================================================================
  # VM Configuration Generation
  # ==========================================================================

  generateVmConfigs = topology: profile: vmModules:
    mapAttrs (vmName: vm: {
      inherit vmName;
      inherit (vm) ip image services dedicated;

      # NixOS module configuration
      nixosConfig = {
        networking = {
          hostName = vmName;
          domain = topology.network.domain or "cluster.local";
          interfaces.eth0.ipv4.addresses = [{
            address = vm.ip;
            prefixLength = 24;
          }];
          defaultGateway = topology.network.gateway or "10.100.0.1";
          nameservers = topology.network.dns or [ "10.100.0.1" ];

          # Firewall based on flows
          firewall = {
            enable = true;
            allowedTCPPorts = unique (
              map (p: p.port) (filter (p: p.protocol != "udp") (vm.ports or []))
            );
            allowedUDPPorts = unique (
              map (p: p.port) (filter (p: p.protocol == "udp") (vm.ports or []))
            );
          };

          # /etc/hosts for cluster DNS
          extraHosts = concatStringsSep "\n" (mapAttrsToList (name: ip:
            "${ip} ${name} ${name}.${topology.network.domain or "cluster.local"}"
          ) topology.network.hosts);
        };

        # Profile-specific Barbican configuration
        imports = [
          # The actual import would be: barbican.nixosModules.${profileToModule profile}
        ];

        # Service-specific configuration
        barbican = mkBarbicanConfig vm.services profile;
      };

      # Additional modules if provided
      extraModules = vmModules.${vmName} or [];
    }) topology.vms;

  # Helper: map profile to module name
  profileToModule = profile: {
    "development" = "development";
    "fedramp-low" = "fedrampLow";
    "fedramp-moderate" = "fedrampModerate";
    "fedramp-high" = "fedrampHigh";
  }.${profile};

  # Helper: generate Barbican config for services
  mkBarbicanConfig = services: profile:
    let
      hasVault = elem "vault" services;
      hasPostgres = elem "postgres" services;
      hasObservability = elem "observability" services;
    in {
      vault = mkIf hasVault {
        enable = true;
        mode = if profile == "development" then "dev" else "production";
        audit.enable = profile != "development";
      };
      securePostgres = mkIf hasPostgres {
        enable = true;
        enableSSL = true;
        enablePgaudit = profile != "development";
        enableProcessIsolation = profile != "development";
      };
      observability = mkIf hasObservability {
        enable = true;
      };
    };

  # ==========================================================================
  # Script Generation
  # ==========================================================================

  generateScripts = { topology, clusterName, profile, bootOrder, networkConfig, secretsBootstrap }:
    {
      lib = generateLibScript { inherit topology networkConfig; };
      deploy = generateDeployScript { inherit topology clusterName profile bootOrder secretsBootstrap; };
      status = generateStatusScript { inherit topology clusterName; };
      teardown = generateTeardownScript { inherit topology clusterName bootOrder; };
    };

  # --------------------------------------------------------------------------
  # Library Script (shared functions)
  # --------------------------------------------------------------------------

  generateLibScript = { topology, networkConfig }:
    pkgs.writeScript "lib.sh" ''
      #!/usr/bin/env bash
      # Barbican Cluster Orchestration Library
      # Generated for cluster topology
      set -euo pipefail

      # =======================================================================
      # Configuration
      # =======================================================================

      CLUSTER_SUBNET="${networkConfig.subnet}"
      CLUSTER_GATEWAY="${networkConfig.gateway}"
      CLUSTER_DOMAIN="${networkConfig.domain}"

      declare -A VM_IPS=(
        ${concatStringsSep "\n  " (mapAttrsToList (name: ip: "[\"${name}\"]=\"${ip}\"") networkConfig.hosts)}
      )

      declare -A VM_IMAGES=(
        ${concatStringsSep "\n  " (mapAttrsToList (name: vm: "[\"${name}\"]=\"${vm.image}\"") topology.vms)}
      )

      # =======================================================================
      # Logging
      # =======================================================================

      log() {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
      }

      log_info() {
        log "INFO: $*"
      }

      log_warn() {
        log "WARN: $*" >&2
      }

      log_error() {
        log "ERROR: $*" >&2
      }

      log_success() {
        log "SUCCESS: $*"
      }

      # =======================================================================
      # VM Management
      # =======================================================================

      vm_exists() {
        local vm_name="$1"
        # Check if VM process exists (implementation depends on VM backend)
        pgrep -f "qemu.*${vm_name}" > /dev/null 2>&1
      }

      vm_start() {
        local vm_name="$1"
        local vm_image="''${VM_IMAGES[$vm_name]}"
        local vm_ip="''${VM_IPS[$vm_name]}"

        log_info "Starting VM: $vm_name (image: $vm_image, ip: $vm_ip)"

        # Build the VM if needed
        if [[ ! -f "''${CLUSTER_DIR}/images/''${vm_name}.qcow2" ]]; then
          log_info "Building VM image for $vm_name..."
          nix build ".#vm-''${vm_name}" -o "''${CLUSTER_DIR}/images/''${vm_name}"
        fi

        # Start the VM
        "''${CLUSTER_DIR}/images/''${vm_name}/bin/run-''${vm_name}-vm" &
        echo $! > "''${CLUSTER_DIR}/pids/''${vm_name}.pid"

        log_info "VM $vm_name started with PID $(cat "''${CLUSTER_DIR}/pids/''${vm_name}.pid")"
      }

      vm_stop() {
        local vm_name="$1"
        local pid_file="''${CLUSTER_DIR}/pids/''${vm_name}.pid"

        if [[ -f "$pid_file" ]]; then
          local pid=$(cat "$pid_file")
          if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping VM: $vm_name (PID: $pid)"
            kill "$pid"
            rm -f "$pid_file"
          else
            log_warn "VM $vm_name not running (stale PID file)"
            rm -f "$pid_file"
          fi
        else
          log_warn "VM $vm_name has no PID file"
        fi
      }

      vm_status() {
        local vm_name="$1"
        local pid_file="''${CLUSTER_DIR}/pids/''${vm_name}.pid"

        if [[ -f "$pid_file" ]]; then
          local pid=$(cat "$pid_file")
          if kill -0 "$pid" 2>/dev/null; then
            echo "running"
            return 0
          fi
        fi
        echo "stopped"
        return 1
      }

      # =======================================================================
      # Health Checks
      # =======================================================================

      wait_healthy() {
        local vm_name="$1"
        local check_type="$2"
        local target="$3"
        local timeout="''${4:-60}"
        local interval="''${5:-5}"

        local vm_ip="''${VM_IPS[$vm_name]}"
        local elapsed=0

        log_info "Waiting for $vm_name to be healthy (type: $check_type, timeout: ''${timeout}s)"

        while [[ $elapsed -lt $timeout ]]; do
          if check_health "$check_type" "$vm_ip" "$target"; then
            log_success "$vm_name is healthy"
            return 0
          fi
          sleep "$interval"
          elapsed=$((elapsed + interval))
        done

        log_error "$vm_name failed health check after ''${timeout}s"
        return 1
      }

      check_health() {
        local check_type="$1"
        local ip="$2"
        local target="$3"

        case "$check_type" in
          http)
            local port="''${target%%/*}"
            local path="/''${target#*/}"
            curl -sf "http://''${ip}:''${port}''${path}" > /dev/null 2>&1
            ;;
          https)
            local port="''${target%%/*}"
            local path="/''${target#*/}"
            curl -sfk "https://''${ip}:''${port}''${path}" > /dev/null 2>&1
            ;;
          tcp)
            nc -z "$ip" "$target" > /dev/null 2>&1
            ;;
          exec)
            ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "root@$ip" "$target" > /dev/null 2>&1
            ;;
          *)
            log_error "Unknown health check type: $check_type"
            return 1
            ;;
        esac
      }

      # =======================================================================
      # Secrets Management
      # =======================================================================

      ensure_secrets_dir() {
        local vm_name="$1"
        mkdir -p "''${CLUSTER_DIR}/secrets/''${vm_name}"
        chmod 700 "''${CLUSTER_DIR}/secrets/''${vm_name}"
      }

      inject_secret() {
        local source_vm="$1"
        local source_path="$2"
        local target_vm="$3"
        local target_path="$4"

        local source_file="''${CLUSTER_DIR}/secrets/''${source_vm}/$(basename "$source_path")"
        local target_dir="''${CLUSTER_DIR}/secrets/''${target_vm}"

        if [[ -f "$source_file" ]]; then
          cp "$source_file" "''${target_dir}/$(basename "$target_path")"
          log_info "Injected secret from $source_vm to $target_vm"
        else
          log_error "Source secret not found: $source_file"
          return 1
        fi
      }

      # =======================================================================
      # Vault Operations
      # =======================================================================

      vault_init() {
        local vault_vm="$1"
        local vault_ip="''${VM_IPS[$vault_vm]}"

        log_info "Initializing Vault on $vault_vm"

        # Wait for Vault to be reachable
        wait_healthy "$vault_vm" "http" "8200/v1/sys/health" 120 5

        # Initialize Vault
        local init_output
        init_output=$(curl -sf "http://''${vault_ip}:8200/v1/sys/init" \
          -X PUT \
          -d '{"secret_shares": 5, "secret_threshold": 3}')

        # Save unseal keys and root token
        ensure_secrets_dir "$vault_vm"
        echo "$init_output" > "''${CLUSTER_DIR}/secrets/''${vault_vm}/vault-init.json"
        echo "$init_output" | jq -r '.root_token' > "''${CLUSTER_DIR}/secrets/''${vault_vm}/vault-root-token"

        log_success "Vault initialized on $vault_vm"
      }

      vault_unseal() {
        local vault_vm="$1"
        local vault_ip="''${VM_IPS[$vault_vm]}"
        local init_file="''${CLUSTER_DIR}/secrets/''${vault_vm}/vault-init.json"

        if [[ ! -f "$init_file" ]]; then
          log_error "Vault init file not found: $init_file"
          return 1
        fi

        log_info "Unsealing Vault on $vault_vm"

        # Get unseal keys
        local keys
        keys=$(jq -r '.keys_base64[]' "$init_file" | head -3)

        # Unseal with threshold keys
        for key in $keys; do
          curl -sf "http://''${vault_ip}:8200/v1/sys/unseal" \
            -X PUT \
            -d "{\"key\": \"$key\"}" > /dev/null
        done

        log_success "Vault unsealed on $vault_vm"
      }

      vault_create_approle() {
        local vault_vm="$1"
        local role_name="$2"
        local policies="$3"

        local vault_ip="''${VM_IPS[$vault_vm]}"
        local token=$(cat "''${CLUSTER_DIR}/secrets/''${vault_vm}/vault-root-token")

        log_info "Creating AppRole '$role_name' on $vault_vm"

        # Enable approle if not already
        curl -sf "http://''${vault_ip}:8200/v1/sys/auth/approle" \
          -X POST \
          -H "X-Vault-Token: $token" \
          -d '{"type": "approle"}' 2>/dev/null || true

        # Create role
        curl -sf "http://''${vault_ip}:8200/v1/auth/approle/role/''${role_name}" \
          -X POST \
          -H "X-Vault-Token: $token" \
          -d "{\"policies\": $policies, \"token_ttl\": \"1h\", \"token_max_ttl\": \"4h\"}"

        # Get role ID
        local role_id
        role_id=$(curl -sf "http://''${vault_ip}:8200/v1/auth/approle/role/''${role_name}/role-id" \
          -H "X-Vault-Token: $token" | jq -r '.data.role_id')

        # Generate secret ID
        local secret_id
        secret_id=$(curl -sf "http://''${vault_ip}:8200/v1/auth/approle/role/''${role_name}/secret-id" \
          -X POST \
          -H "X-Vault-Token: $token" | jq -r '.data.secret_id')

        # Save credentials
        echo "$role_id" > "''${CLUSTER_DIR}/secrets/''${vault_vm}/approle-''${role_name}-role-id"
        echo "$secret_id" > "''${CLUSTER_DIR}/secrets/''${vault_vm}/approle-''${role_name}-secret-id"

        log_success "AppRole '$role_name' created"
      }

      # =======================================================================
      # Utility Functions
      # =======================================================================

      print_cluster_info() {
        echo ""
        echo "========================================"
        echo "Cluster Information"
        echo "========================================"
        echo "Subnet: $CLUSTER_SUBNET"
        echo "Gateway: $CLUSTER_GATEWAY"
        echo "Domain: $CLUSTER_DOMAIN"
        echo ""
        echo "VMs:"
        for vm in "''${!VM_IPS[@]}"; do
          local status=$(vm_status "$vm" || echo "unknown")
          printf "  %-20s %-15s %s\n" "$vm" "''${VM_IPS[$vm]}" "$status"
        done
        echo ""
      }
    '';

  # --------------------------------------------------------------------------
  # Deploy Script
  # --------------------------------------------------------------------------

  generateDeployScript = { topology, clusterName, profile, bootOrder, secretsBootstrap }:
    pkgs.writeScript "deploy.sh" ''
      #!/usr/bin/env bash
      # Barbican Cluster Deployment Script
      # Cluster: ${clusterName}
      # Profile: ${profile}
      set -euo pipefail

      SCRIPT_DIR="$(cd "$(dirname "''${BASH_SOURCE[0]}")" && pwd)"
      CLUSTER_DIR="$(dirname "$SCRIPT_DIR")"

      source "''${SCRIPT_DIR}/lib.sh"

      # =======================================================================
      # Pre-flight Checks
      # =======================================================================

      preflight_checks() {
        log_info "Running pre-flight checks..."

        # Check required tools
        for cmd in nix curl jq nc ssh; do
          if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
          fi
        done

        # Create directories
        mkdir -p "''${CLUSTER_DIR}"/{images,pids,secrets,logs}

        log_success "Pre-flight checks passed"
      }

      # =======================================================================
      # Stage Deployment
      # =======================================================================

      deploy_stage() {
        local stage_num="$1"
        local stage_name="$2"
        shift 2
        local vms=("$@")

        log_info "========================================"
        log_info "Stage $stage_num: $stage_name"
        log_info "========================================"

        for vm in "''${vms[@]}"; do
          # Run pre-start secrets setup
          run_pre_start_secrets "$vm"

          # Start VM
          vm_start "$vm"
        done

        # Wait for all VMs in stage to be healthy
        for vm in "''${vms[@]}"; do
          wait_for_vm_healthy "$vm"
        done

        # Run post-start actions
        for vm in "''${vms[@]}"; do
          run_post_start_actions "$vm"
        done

        log_success "Stage $stage_num complete"
      }

      wait_for_vm_healthy() {
        local vm="$1"
        local services=(${concatStringsSep " " (map (vm: "\"${concatStringsSep "\" \"" vm.services}\"") (attrValues topology.vms))})

        # Determine health check based on primary service
        case "''${services[0]}" in
          vault)
            wait_healthy "$vm" "http" "8200/v1/sys/health" 120 5
            ;;
          postgres)
            wait_healthy "$vm" "tcp" "5432" 60 3
            ;;
          redis)
            wait_healthy "$vm" "tcp" "6379" 30 2
            ;;
          keycloak)
            wait_healthy "$vm" "http" "8080/health/ready" 180 5
            ;;
          observability)
            wait_healthy "$vm" "http" "9090/-/healthy" 60 5
            ;;
          *)
            wait_healthy "$vm" "tcp" "22" 60 5
            ;;
        esac
      }

      run_pre_start_secrets() {
        local vm="$1"
        ensure_secrets_dir "$vm"

        # VM-specific pre-start secrets logic would go here
        # This is generated based on secretsBootstrap
        log_info "Running pre-start secrets for $vm"
      }

      run_post_start_actions() {
        local vm="$1"

        ${if secretsBootstrap.vaultVm != null then ''
        # If this is the Vault VM, initialize and create AppRoles
        if [[ "$vm" == "${secretsBootstrap.vaultVm}" ]]; then
          # Check if already initialized
          local vault_ip="''${VM_IPS[$vm]}"
          local init_status=$(curl -sf "http://''${vault_ip}:8200/v1/sys/init" | jq -r '.initialized')

          if [[ "$init_status" != "true" ]]; then
            vault_init "$vm"
            vault_unseal "$vm"
          fi

          # Create AppRoles for other VMs
          ${concatStringsSep "\n          " (map (vmName:
            if vmName != secretsBootstrap.vaultVm then
              "vault_create_approle \"$vm\" \"${vmName}\" '[\"default\"]'"
            else ""
          ) (attrNames topology.vms))}
        fi
        '' else ""}

        log_info "Post-start actions complete for $vm"
      }

      # =======================================================================
      # Main
      # =======================================================================

      main() {
        log_info "Deploying cluster: ${clusterName}"
        log_info "Profile: ${profile}"

        preflight_checks

        # Deploy each stage
        ${concatStringsSep "\n\n        " (map (stage: ''
        deploy_stage ${toString stage.stage} "${stage.name}" ${concatStringsSep " " (map (vm: "\"${vm}\"") stage.vms)}
        '') bootOrder.stages)}

        log_success "Cluster deployment complete!"
        print_cluster_info
      }

      main "$@"
    '';

  # --------------------------------------------------------------------------
  # Status Script
  # --------------------------------------------------------------------------

  generateStatusScript = { topology, clusterName }:
    pkgs.writeScript "status.sh" ''
      #!/usr/bin/env bash
      # Barbican Cluster Status Script
      # Cluster: ${clusterName}
      set -euo pipefail

      SCRIPT_DIR="$(cd "$(dirname "''${BASH_SOURCE[0]}")" && pwd)"
      CLUSTER_DIR="$(dirname "$SCRIPT_DIR")"

      source "''${SCRIPT_DIR}/lib.sh"

      # =======================================================================
      # Status Display
      # =======================================================================

      show_status() {
        echo ""
        echo "========================================"
        echo "Cluster Status: ${clusterName}"
        echo "========================================"
        echo ""

        printf "%-20s %-15s %-10s %-30s\n" "VM" "IP" "STATUS" "SERVICES"
        printf "%-20s %-15s %-10s %-30s\n" "----" "----" "------" "--------"

        ${concatStringsSep "\n        " (mapAttrsToList (vmName: vm: ''
        status=$(vm_status "${vmName}" 2>/dev/null || echo "stopped")
        printf "%-20s %-15s %-10s %-30s\n" "${vmName}" "${vm.ip}" "$status" "${concatStringsSep ", " vm.services}"
        '') topology.vms)}

        echo ""
      }

      show_health() {
        echo "Health Checks:"
        echo ""

        ${concatStringsSep "\n        " (mapAttrsToList (vmName: vm: ''
        if vm_status "${vmName}" > /dev/null 2>&1; then
          # Check primary service health
          ${if elem "vault" vm.services then ''
          if check_health "http" "${vm.ip}" "8200/v1/sys/health"; then
            echo "  ${vmName}: vault [OK]"
          else
            echo "  ${vmName}: vault [UNHEALTHY]"
          fi
          '' else if elem "postgres" vm.services then ''
          if check_health "tcp" "${vm.ip}" "5432"; then
            echo "  ${vmName}: postgres [OK]"
          else
            echo "  ${vmName}: postgres [UNHEALTHY]"
          fi
          '' else ''
          echo "  ${vmName}: [running]"
          ''}
        else
          echo "  ${vmName}: [stopped]"
        fi
        '') topology.vms)}

        echo ""
      }

      # =======================================================================
      # Main
      # =======================================================================

      main() {
        show_status
        show_health
      }

      main "$@"
    '';

  # --------------------------------------------------------------------------
  # Teardown Script
  # --------------------------------------------------------------------------

  generateTeardownScript = { topology, clusterName, bootOrder }:
    let
      # Reverse boot order for teardown
      reverseOrder = reverseList (concatMap (s: s.vms) bootOrder.stages);
    in
    pkgs.writeScript "teardown.sh" ''
      #!/usr/bin/env bash
      # Barbican Cluster Teardown Script
      # Cluster: ${clusterName}
      set -euo pipefail

      SCRIPT_DIR="$(cd "$(dirname "''${BASH_SOURCE[0]}")" && pwd)"
      CLUSTER_DIR="$(dirname "$SCRIPT_DIR")"

      source "''${SCRIPT_DIR}/lib.sh"

      # =======================================================================
      # Options
      # =======================================================================

      FORCE=false
      CLEAN_SECRETS=false
      CLEAN_IMAGES=false

      usage() {
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --force          Don't prompt for confirmation"
        echo "  --clean-secrets  Remove secrets directory"
        echo "  --clean-images   Remove built VM images"
        echo "  --clean-all      Remove everything (secrets, images, logs)"
        echo "  -h, --help       Show this help message"
      }

      parse_args() {
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --force)
              FORCE=true
              shift
              ;;
            --clean-secrets)
              CLEAN_SECRETS=true
              shift
              ;;
            --clean-images)
              CLEAN_IMAGES=true
              shift
              ;;
            --clean-all)
              CLEAN_SECRETS=true
              CLEAN_IMAGES=true
              shift
              ;;
            -h|--help)
              usage
              exit 0
              ;;
            *)
              log_error "Unknown option: $1"
              usage
              exit 1
              ;;
          esac
        done
      }

      # =======================================================================
      # Teardown
      # =======================================================================

      teardown_cluster() {
        log_info "Tearing down cluster: ${clusterName}"

        # Stop VMs in reverse order
        ${concatStringsSep "\n        " (map (vmName: ''
        log_info "Stopping ${vmName}..."
        vm_stop "${vmName}" || true
        '') reverseOrder)}

        # Clean up if requested
        if [[ "$CLEAN_SECRETS" == "true" ]]; then
          log_info "Removing secrets..."
          rm -rf "''${CLUSTER_DIR}/secrets"
        fi

        if [[ "$CLEAN_IMAGES" == "true" ]]; then
          log_info "Removing VM images..."
          rm -rf "''${CLUSTER_DIR}/images"
        fi

        # Always clean PIDs
        rm -rf "''${CLUSTER_DIR}/pids"

        log_success "Cluster teardown complete"
      }

      # =======================================================================
      # Main
      # =======================================================================

      main() {
        parse_args "$@"

        if [[ "$FORCE" != "true" ]]; then
          read -p "Are you sure you want to tear down cluster '${clusterName}'? [y/N] " confirm
          if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            log_info "Cancelled"
            exit 0
          fi
        fi

        teardown_cluster
      }

      main "$@"
    '';

  # ==========================================================================
  # Helper: Find first match
  # ==========================================================================

  findFirst = pred: default: list:
    let matches = filter pred list;
    in if matches == [] then default else head matches;
}
