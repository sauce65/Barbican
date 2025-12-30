# Agenix secrets configuration
# See: https://github.com/ryantm/agenix
#
# To use:
# 1. Generate an age key: age-keygen -o ~/.config/agenix/keys.txt
# 2. Add your public key below
# 3. Create secrets: agenix -e secrets/db-password.age
# 4. Deploy with the flake

let
  # Add your public keys here (from age-keygen or SSH keys)
  # Example: admin = "age1...";
  # Example: server = "ssh-ed25519 AAAA...";

  # For development/testing only - replace with real keys
  devKey = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";
in
{
  # Database password for PostgreSQL
  "db-password.age".publicKeys = [ devKey ];

  # Application environment variables (DATABASE_URL, etc.)
  "app-env.age".publicKeys = [ devKey ];
}
