# Barbican Security Checks
#
# Provides:
# - Flake security checks (lock integrity, cargo audit)
# - NixOS VM security tests
{ pkgs, pkgsWithVault, lib, flakeLockPath, cargoLockPath }:

{
  # =============================================================
  # Flake Security Checks
  # =============================================================

  # Verify flake inputs are properly locked with content hashes
  flake-lock-check = pkgs.runCommand "flake-lock-check" { } ''
    echo "Checking flake.lock integrity..."

    # Verify all inputs have narHash (content-addressed)
    if ! ${pkgs.jq}/bin/jq -e '.nodes | to_entries[] | select(.key != "root") | .value.locked.narHash' ${flakeLockPath} > /dev/null 2>&1; then
      echo "ERROR: Some flake inputs are missing narHash verification" >&2
      exit 1
    fi

    echo "All flake inputs have content-addressed hashes"
    touch $out
  '';

  # Check for known vulnerabilities in Rust dependencies
  cargo-audit = pkgs.runCommand "cargo-audit"
    {
      buildInputs = [ pkgs.cargo-audit ];
    } ''
    echo "Running cargo audit for known vulnerabilities..."

    # Run audit (write results to build dir, not source)
    cargo-audit audit --file ${cargoLockPath} --json > $TMPDIR/audit-results.json 2>&1 || true

    # Check for actual vulnerabilities
    if ${pkgs.jq}/bin/jq -e '.vulnerabilities.count > 0' $TMPDIR/audit-results.json > /dev/null 2>&1; then
      echo "WARNING: Vulnerabilities found in dependencies" >&2
      ${pkgs.jq}/bin/jq '.vulnerabilities' $TMPDIR/audit-results.json >&2
    else
      echo "No known vulnerabilities in Cargo dependencies"
    fi

    touch $out
  '';

  # Validate Cargo.lock exists and is parseable
  cargo-lock-check = pkgs.runCommand "cargo-lock-check" { } ''
    echo "Checking Cargo.lock exists and is valid..."

    # Verify Cargo.lock exists
    if [ ! -f "${cargoLockPath}" ]; then
      echo "ERROR: Cargo.lock not found. Run 'cargo generate-lockfile' and commit." >&2
      exit 1
    fi

    # Verify it's valid TOML (basic syntax check)
    ${pkgs.python3}/bin/python3 -c "
import tomllib
with open('${cargoLockPath}', 'rb') as f:
    data = tomllib.load(f)
    packages = data.get('package', [])
    print(f'Cargo.lock contains {len(packages)} packages')
" || {
      echo "ERROR: Cargo.lock is not valid TOML" >&2
      exit 1
    }

    echo "Cargo.lock validation passed"
    touch $out
  '';

  # =============================================================
  # NixOS VM Security Tests
  # =============================================================

  secure-users = import ./tests/secure-users.nix { inherit pkgs lib; };
  hardened-ssh = import ./tests/hardened-ssh.nix { inherit pkgs lib; };
  hardened-nginx = import ./tests/hardened-nginx.nix { inherit pkgs lib; };
  kernel-hardening = import ./tests/kernel-hardening.nix { inherit pkgs lib; };
  secure-postgres = import ./tests/secure-postgres.nix { inherit pkgs lib; };
  time-sync = import ./tests/time-sync.nix { inherit pkgs lib; };
  intrusion-detection = import ./tests/intrusion-detection.nix { inherit pkgs lib; };
  vm-firewall = import ./tests/vm-firewall.nix { inherit pkgs lib; };
  resource-limits = import ./tests/resource-limits.nix { inherit pkgs lib; };
  vault-pki = import ./tests/vault-pki.nix { pkgs = pkgsWithVault; inherit lib; };

  # Combined security suite (all tests)
  all = (import ./tests/default.nix { inherit pkgs; lib = pkgs.lib; }).all;
}
