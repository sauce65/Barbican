# Barbican Development Shell
#
# Provides development environment with:
# - Rust toolchain with extensions
# - PostgreSQL and sqlx-cli
# - Vault PKI tools
{ pkgs, rustToolchain }:

let
  # Vault PKI scripts
  vaultPkiLib = import ./lib/vault-pki.nix { lib = pkgs.lib; inherit pkgs; };
  pkiScripts = vaultPkiLib.mkPkiScripts { outputDir = "./certs"; };
in
pkgs.mkShell {
  buildInputs = [
    rustToolchain
    pkgs.pkg-config
    pkgs.openssl
    pkgs.postgresql_16
    pkgs.sqlx-cli
    # Vault PKI tools
    pkgs.vault
    pkgs.jq
    pkiScripts.issueServer
    pkiScripts.issueClient
    pkiScripts.issuePostgres
    pkiScripts.showCerts
    pkiScripts.getCaChain
  ];

  RUST_BACKTRACE = 1;

  shellHook = ''
    echo ""
    echo "Barbican Development Shell"
    echo "=========================="
    echo ""
    echo "Vault PKI commands available:"
    echo "  nix run .#vault-dev        - Start Vault with PKI (dev mode)"
    echo "  barbican-cert-server       - Issue server certificate"
    echo "  barbican-cert-client       - Issue mTLS client certificate"
    echo "  barbican-cert-postgres     - Issue PostgreSQL certificate"
    echo "  barbican-ca-chain          - Export CA chain"
    echo "  barbican-cert-show         - Show certificate details"
    echo ""
    echo "After starting vault-dev, set:"
    echo "  export VAULT_ADDR=http://127.0.0.1:8200"
    echo "  export VAULT_TOKEN=barbican-dev"
    echo ""
  '';
}
