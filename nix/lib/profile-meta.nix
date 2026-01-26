# Profile metadata module
#
# Provides read-only metadata about the active Barbican security profile.
# Imported by each profile to declare its name and included modules.
{ lib, ... }:

{
  options.barbican.profile = {
    name = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      description = "Name of the active Barbican security profile";
    };

    includedModules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = "List of Barbican modules enabled by this profile";
    };
  };
}
