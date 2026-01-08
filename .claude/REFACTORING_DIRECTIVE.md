# Code Refactoring & Enhancement Directive

## Core Philosophy

You are modifying an existing codebase. Your goal is to make the code **more elegant, not more verbose**. Treat every line you add as a cost and every line you remove (while preserving correctness) as a benefit.

Code should become simpler, clearer, and more maintainable after your changes—never more convoluted.

---

## Before Writing Any Code

### 1. Analyze Current State

- What does this code do now?
- What is its structure and intent?
- Identify existing patterns, abstractions, and organization.
- Note any technical debt, redundancy, or unclear sections.

### 2. Define Desired End State

- What should this code do after the change?
- What structure and intent should it have?
- How does this fit into the broader system architecture?

### 3. Map the Delta

Explicitly categorize each required change:

| Category | Description |
|----------|-------------|
| **Modification** | Changing existing code to behave differently |
| **Removal** | Eliminating dead, redundant, or superseded code |
| **Addition** | Genuinely new functionality with no existing analog |

### 4. Challenge Additions

For each item categorized as "Addition," ask: *Can this be achieved by modifying or extending something that already exists?*

Only add new constructs when they provide clear organizational or semantic value.

---

## Execution Principles

- **Refactor, don't append**: When behavior needs to change, change the existing code. Don't wrap it, shadow it, or add parallel paths.
- **Deduplicate aggressively**: If your change introduces logic similar to existing code, unify them.
- **Preserve locality**: Keep related logic together. Don't scatter implementation across files without good reason.
- **Reduce surface area**: Fewer public interfaces, fewer parameters, fewer special cases.
- **Delete with confidence**: Dead code, redundant checks, and vestigial abstractions should be removed, not commented out.
- **Simplify control flow**: Prefer early returns, flat structure, and obvious paths over nested conditionals.

---

## Documentation Standard

Every function and module must have a comment header (max 5 sentences) stating:

1. **What** it does (purpose)
2. **Why** it exists (context in the system)
3. **How** it connects (key dependencies or callers)

Update existing comments when behavior changes. Remove comments for deleted code. Never write comments that merely restate what the code obviously does.

---

## Output Format

When presenting changes, first provide a brief summary:

- What is being **modified** and why
- What is being **removed** and why
- What is being **added** and why (with justification)

Then present the code changes.

---

## Anti-Patterns to Avoid

- Adding wrapper functions instead of modifying the original
- Creating new modules for small additions that belong in existing modules
- Introducing abstractions that serve only one use case
- Adding feature flags or conditionals when the old behavior is no longer needed
- Preserving backward compatibility that wasn't requested
- Verbose error handling that obscures the happy path
- Comments that restate what the code obviously does
- Catching and re-wrapping errors without adding information
- Generic type parameters where concrete types suffice

---

## Detecting Shortcut Code

"Shortcut code" refers to implementations that notionally support configurable or branching behavior but contain shortcuts that bypass the intended configuration. These shortcuts often silently undermine security, compliance, or design requirements.

### Why Shortcut Code Is Dangerous

- **Silent failures**: The code runs without errors but doesn't behave as configured
- **False confidence**: Tests pass because they test the shortcut, not the intended behavior
- **Security risks**: Development defaults may silently apply in production
- **Debugging difficulty**: No errors or warnings indicate the misconfiguration

### Common Patterns

| Pattern | Example | Problem |
|---------|---------|---------|
| **Dual constructors** | `from_env()` alongside `from_defaults()` | The simpler method gets used, bypassing configuration |
| **Silent fallbacks** | `.unwrap_or("development")` | Missing config silently degrades to insecure defaults |
| **Duplicated env checks** | Same `if env == "production"` in 4 places | Copy-paste leads to inconsistency; one gets missed |
| **Development helpers** | `Config::development()` | Convenient method becomes a crutch in production paths |

### Detection Strategies

**1. Dual API Analysis**

Search for types with multiple construction methods:
```bash
grep -n "fn from_env\|fn from_config\|fn from_default\|fn new(" src/
```

If a type has both `from_env()` and a simpler alternative, verify the simpler one isn't used where configuration should apply.

**2. Call Graph Verification**

For any `from_env()` method, search for its usage:
```bash
grep -rn "TypeName::from_env\|TypeName::new\|TypeName::default" src/
```

If `from_env()` exists but `new()` or `default()` is called in production paths, that's a shortcut.

**3. Silent Fallback Audit**

Search for fallbacks that default to development/insecure values:
```bash
grep -n "unwrap_or.*development\|unwrap_or_else.*development" src/
grep -n "unwrap_or_default\|unwrap_or.*false\|unwrap_or.*true" src/
```

Each fallback should be evaluated: Is silent degradation acceptable, or should it fail/warn?

**4. Deprecation Markers**

When you find a shortcut method, don't just fix the call site—deprecate the method:
```rust
#[deprecated(since = "0.2.0", note = "Use from_env() instead")]
pub fn from_deployment_environment(...) -> Self {
    tracing::warn!("Using deprecated method that ignores configuration");
    // ...
}
```

**5. Audit Logging**

Add logging to configuration loading so shortcuts become visible:
```rust
pub fn from_env() -> Self {
    let config = /* load from env */;
    tracing::info!(
        profile = ?config.profile,
        timeout_secs = config.timeout,
        "Configuration loaded from environment"
    );
    config
}
```

**6. Runtime Verification**

After making changes, deploy and verify logs show expected values:
```bash
DPE_COMPLIANCE_PROFILE=fedramp-high nix run .#full
grep "Configuration loaded" logs/dpe-api.log
```

### Example: The Bug We Found

```rust
// BEFORE: Shortcut that ignored DPE_COMPLIANCE_PROFILE
let security = DpeSecurityConfig::from_deployment_environment(&env);

// AFTER: Respects environment variable configuration
let security = DpeSecurityConfig::from_env();
```

The `from_deployment_environment()` method hardcoded `Production → FedRampModerate`, ignoring any explicit `DPE_COMPLIANCE_PROFILE=fedramp-high` setting. The fix was to:

1. Change call sites to use `from_env()`
2. Deprecate `from_deployment_environment()` with a warning
3. Add audit logging to `from_env()` showing the selected profile

### Checklist for Configuration Code

- [ ] Is there only ONE way to construct this config, or are there shortcuts?
- [ ] Do all fallback values fail safely (or at least warn)?
- [ ] Is the selected configuration logged at startup?
- [ ] Are deprecated methods marked `#[deprecated]` with warnings?
- [ ] Have you deployed and verified the logs show correct values?

---

## Language-Specific Idioms

The principles above apply universally. The following sections provide language-specific guidance for writing idiomatic, clean code.

---

### Rust

#### Type System

- Use the type system to make invalid states unrepresentable. Prefer enums with variants over boolean flags or stringly-typed data.
- Use newtypes to distinguish semantically different values of the same underlying type (e.g., `UserId(i64)` vs `PostId(i64)`).
- Prefer `Option` and `Result` over sentinel values or panics. Reserve `unwrap()` and `expect()` for cases where invariants are truly guaranteed.

#### Error Handling

- Define domain-specific error types. Use `thiserror` for library errors, `anyhow` sparingly for application-level errors where you don't need to match on variants.
- Propagate errors with `?`. Don't catch and re-wrap unless you're adding meaningful context.
- Error messages should state what failed and why, not just that something failed.

#### Ownership & Borrowing

- Prefer borrowing over cloning. Clone only when ownership transfer is genuinely required.
- Use `Cow<'_, T>` when a function might or might not need to allocate.
- Avoid `Arc<Mutex<T>>` as a default—reach for it only when shared mutable state is unavoidable.

#### Structure

- Keep modules focused. A module should represent a single concept or capability.
- Prefer free functions over methods when the function doesn't need `self`.
- Use `impl Trait` in argument position for flexibility, in return position for simplicity. Be explicit with generics when bounds become complex.

#### Iteration & Collections

- Prefer iterator chains over manual loops when the chain is readable.
- Use `collect()` judiciously—be aware of what you're collecting into.
- Prefer slices (`&[T]`) over `&Vec<T>` in function parameters.

#### Concurrency

- Prefer message passing (`mpsc`, `crossbeam`) over shared state when feasible.
- Use `tokio::spawn` for concurrent tasks, but be mindful of task granularity.
- Avoid `async` in traits unless necessary; the complexity cost is real.

#### Style

- Follow `rustfmt` defaults. Don't fight the formatter.
- Use `clippy` and address its warnings. If you disagree with a lint, disable it explicitly with a comment explaining why.
- Prefer `snake_case` for functions and variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.

---

### Nix

#### Expression Structure

- Nix is a pure functional language. Embrace immutability—transform data, don't mutate it.
- Keep expressions small and composable. Extract reusable logic into functions.
- Use `let ... in` for local bindings. Avoid deeply nested expressions by breaking them into named intermediate values.

#### Function Design

- Prefer attribute set arguments with defaults over positional arguments:
  ```nix
  { pkgs, lib, enableFeature ? false }: ...
  ```
- Use `lib.mkOption` with clear types and descriptions for module options.
- Document function arguments with comments when their purpose isn't obvious from the name.

#### Module System

- One concept per module. A module should configure a single service, package set, or system aspect.
- Use `lib.mkEnableOption` for feature flags, `lib.mkIf` for conditional configuration.
- Prefer `lib.mkDefault` over hard-coded values when setting defaults that users might override.
- Avoid `with pkgs;` in favor of explicit attribute access or selective `inherit`.

#### Derivations & Packaging

- Pin inputs explicitly. Avoid `fetchurl` without a hash.
- Use `stdenv.mkDerivation` for building, `writeShellApplication` for scripts.
- Prefer `buildInputs` for runtime dependencies, `nativeBuildInputs` for build-time tools.

#### Flakes

- Keep `flake.nix` minimal—delegate to separate files for complex configurations.
- Use `inputs.nixpkgs.follows` to avoid duplicate nixpkgs instances.
- Define outputs clearly: `packages`, `devShells`, `nixosConfigurations`, etc.

#### Style

- Use `nixfmt` or `alejandra` consistently. Pick one and stick with it.
- Align attribute sets for readability when it aids scanning.
- Prefer `lib` functions over reimplementing logic (e.g., `lib.optionalString`, `lib.concatMapStringsSep`).

---

### Python

#### Structure

- Follow PEP 8. Use a formatter (`black`, `ruff format`) and linter (`ruff`, `flake8`).
- Prefer functions over classes unless you need state. Prefer dataclasses or named tuples over raw dicts for structured data.
- Use type hints consistently. They serve as documentation and enable static analysis.

#### Error Handling

- Catch specific exceptions, not bare `except:`.
- Prefer returning `None` or raising meaningful exceptions over returning sentinel values.
- Use context managers (`with`) for resource management.

#### Iteration

- Prefer list comprehensions and generator expressions over manual loops when readable.
- Use `itertools` for complex iteration patterns.
- Avoid mutating a list while iterating over it.

#### Imports

- Group imports: standard library, third-party, local. Separate groups with blank lines.
- Avoid `from module import *`.
- Prefer absolute imports over relative imports.

---

### SQL (PostgreSQL)

#### Schema Design

- Use the most specific type available. `timestamptz` over `timestamp`, `uuid` over `varchar` for IDs.
- Name constraints explicitly for clearer error messages and easier migrations.
- Prefer `NOT NULL` with defaults over nullable columns when semantically appropriate.

#### Queries

- Use CTEs (`WITH` clauses) to break complex queries into readable steps.
- Prefer `EXISTS` over `IN` for subqueries, and `JOIN` over correlated subqueries.
- Use parameterized queries. Never interpolate user input into SQL strings.

#### Migrations

- One logical change per migration. Migrations should be reversible when possible.
- Name migrations descriptively: `add_user_email_index`, not `migration_003`.

---

### Shell (Bash)

#### Safety

- Start scripts with:
  ```bash
  set -euo pipefail
  ```
- Quote all variable expansions: `"$var"`, not `$var`.
- Use `[[ ]]` over `[ ]` for conditionals.

#### Structure

- Define functions for reusable logic. Keep the main script flow at the bottom.
- Use `readonly` for constants.
- Prefer `$(command)` over backticks.

#### Portability

- Target POSIX sh if portability matters; otherwise, use bashisms explicitly and require bash in the shebang.
- Avoid relying on GNU-specific flags without checking availability.

---

### TypeScript / JavaScript

#### Type Safety

- Enable `strict` mode in TypeScript. Don't use `any` as an escape hatch.
- Prefer `unknown` over `any` when the type is genuinely uncertain, then narrow with type guards.
- Use discriminated unions over optional properties when a value is conditionally present.

#### Structure

- Prefer named exports over default exports for better refactoring support.
- Keep modules focused—one primary export per file is a reasonable default.
- Avoid classes unless you need inheritance or complex state. Prefer plain objects and functions.

#### Async

- Use `async/await` over raw promises for readability.
- Handle errors with try/catch at appropriate boundaries, not around every await.
- Prefer `Promise.all` for concurrent independent operations.

#### Style

- Use `const` by default, `let` when rebinding is needed, never `var`.
- Prefer template literals over string concatenation.
- Use optional chaining (`?.`) and nullish coalescing (`??`) instead of manual checks.

---

## Final Checklist

Before submitting changes, verify:

- [ ] Did I modify existing code rather than add parallel implementations?
- [ ] Did I remove any code that is now dead or redundant?
- [ ] Is every addition justified—could it have been a modification instead?
- [ ] Are all functions and modules documented according to the standard?
- [ ] Does the code follow the language-specific idioms above?
- [ ] Is the code simpler and more readable than before?
- [ ] Would another developer understand the structure and intent quickly?
