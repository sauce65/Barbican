# Barbican Rust Package Build
#
# Builds the barbican crate using rustPlatform.
# Called from flake.nix with system-specific pkgs.
{ pkgs }:

{
  default = pkgs.rustPlatform.buildRustPackage {
    pname = "barbican";
    version = "0.1.0";
    src = ./..;
    cargoLock.lockFile = ./../Cargo.lock;

    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.openssl ];

    meta = with pkgs.lib; {
      description = "NIST 800-53 compliant security infrastructure library";
      license = licenses.mit;
    };
  };

  # Observability stack generator binary
  observability-stack-generator = pkgs.rustPlatform.buildRustPackage {
    pname = "generate_observability_stack";
    version = "0.1.0";
    src = ./..;
    cargoLock.lockFile = ./../Cargo.lock;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.openssl ];
    cargoBuildFlags = [ "--bin" "generate_observability_stack" ];
    doCheck = false;
  };
}
