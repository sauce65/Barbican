# Documentation Update Directive

## Core Principle

**Documentation must reflect reality. Reality is determined by reading code, not by reading documentation.**

Existing comments, docstrings, README files, function names, and prior documentation are **claims**, not facts. Every assertion must be verified against the actual code or architectural reality before being included in updated documentation.

Assume all existing documentation is potentially stale, incomplete, or wrong until proven otherwise.

---

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  1. SURVEY          Catalog existing documentation structure    │
├─────────────────────────────────────────────────────────────────┤
│  2. INVESTIGATE     Empirically assess actual codebase state    │
├─────────────────────────────────────────────────────────────────┤
│  3. COMPARE         Identify discrepancies and gaps             │
├─────────────────────────────────────────────────────────────────┤
│  4. PLAN            Design documentation refactoring strategy   │
├─────────────────────────────────────────────────────────────────┤
│  5. EXECUTE         Implement changes with verification         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Survey Existing Documentation

Catalog all existing documentation without assuming accuracy:

### Inventory

- List all documentation files (READMEs, guides, ADRs, wikis, etc.)
- Identify inline documentation (module-level comments, docstrings)
- Note structural organization (directories, naming conventions, cross-references)
- Record the apparent scope and purpose of each document

### Structural Assessment

For each document, note:

| Aspect | Questions |
|--------|-----------|
| **Scope** | What does this document claim to cover? |
| **Audience** | Who is the intended reader? |
| **Dependencies** | What other docs does it reference or assume? |
| **Freshness signals** | Dates, version numbers, references to features/APIs |
| **Overlap** | Does it duplicate content from other documents? |

### Output

Produce a documentation map: a structured overview of what exists, where it lives, and what it claims to describe. **Do not yet assess accuracy.**

---

## Phase 2: Empirical Codebase Investigation

Independently determine the true state of the system by reading actual code.

### Ground Rules

- **Do not trust comments.** Comments are claims. Read the code they describe.
- **Do not trust function names.** A function named `validate_input` might not validate anything. Read the implementation.
- **Do not trust existing documentation.** That's what you're here to fix.
- **Do trust**: actual code paths, type signatures, database schemas, configuration files, dependency manifests, test assertions.

### Investigation Targets

Depending on documentation scope, examine:

| Target | What to verify |
|--------|----------------|
| **Architecture** | Actual module boundaries, dependency graph, data flow |
| **APIs** | Real endpoints, parameters, response shapes, error conditions |
| **Data models** | Actual schema, constraints, relationships, migrations |
| **Configuration** | Real options, defaults, environment variables, feature flags |
| **Build/Deploy** | Actual build steps, dependencies, required tooling |
| **Business logic** | Real rules, edge cases, validation, state transitions |

### Verification Methods

- Read function/method implementations, not just signatures
- Trace call graphs for critical paths
- Examine test cases for behavioral expectations
- Check configuration defaults and environment bindings
- Review database migrations for schema truth
- Run the code mentally or actually to confirm behavior

### Output

Produce a ground truth summary: what the system actually does, how it's actually structured, what it actually requires. This is independent of any documentation.

---

## Phase 3: Comparative Analysis

Systematically compare existing documentation against verified reality.

### Discrepancy Categories

| Category | Description | Action |
|----------|-------------|--------|
| **Accurate** | Documentation matches reality | Retain (possibly edit for clarity) |
| **Outdated** | Documentation describes old behavior | Update to reflect current state |
| **Incorrect** | Documentation contradicts reality | Correct or remove |
| **Missing** | Real functionality has no documentation | Create if warranted |
| **Orphaned** | Documentation describes removed features | Delete |
| **Redundant** | Multiple docs cover the same ground | Consolidate |
| **Misplaced** | Correct content in wrong location | Relocate |
| **Fragmented** | Related content scattered across docs | Unify |
| **Bloated** | Excessive detail obscuring key information | Reduce |

### Gap Analysis

- What critical functionality lacks documentation?
- What common tasks have no guidance?
- What questions would a new developer have that docs don't answer?

### Overlap Analysis

- Which documents repeat the same information?
- Are there conflicting statements across documents?
- Can multiple documents be merged without loss?

### Output

Produce a discrepancy report: a detailed accounting of what's wrong, what's missing, and what's redundant in existing documentation.

---

## Phase 4: Documentation Refactoring Plan

Design a strategy to bring documentation into alignment with reality while improving structure.

### Guiding Principles

- **Reductive by default**: Remove, consolidate, and simplify before adding.
- **Single source of truth**: Each concept documented in exactly one place.
- **Proximity**: Documentation near what it documents (inline > separate file > wiki).
- **Audience-appropriate**: Match depth and terminology to the reader.
- **Maintainable**: Docs that are hard to update become stale. Prefer stable truths.

### Structural Decisions

For each piece of existing documentation, decide:

| Action | When to apply |
|--------|---------------|
| **Retain** | Accurate, well-placed, appropriately scoped |
| **Edit** | Accurate but unclear, verbose, or poorly organized |
| **Delete** | Orphaned, redundant after consolidation, or irrecoverably wrong |
| **Merge** | Multiple docs covering same topic with no structural reason for separation |
| **Split** | Single doc covering unrelated topics or serving multiple audiences |
| **Relocate** | Correct content in wrong location |
| **Create** | Verified gap that warrants new documentation |

### Consolidation Strategy

When merging documents:

- Identify the canonical location
- Extract unique, accurate content from each source
- Verify extracted content against code (again)
- Delete redundant sources after merge
- Update all references to point to canonical location

### Creation Criteria

Only create new documentation when:

- A verified gap exists (real functionality, no docs)
- The information is stable enough to maintain
- The audience genuinely needs it
- No existing document can reasonably be extended to cover it

### Output

Produce a refactoring plan: specific actions for each document, proposed new structure, and rationale for each decision.

---

## Phase 5: Execution

Implement the documentation changes with ongoing verification.

### Execution Standards

- **Verify while writing**: Every factual claim you write, verify against code in that moment.
- **Cite your sources**: When documenting behavior, know which file/function/line proves it.
- **Atomic changes**: Each document change should be independently correct.
- **Update references**: When moving or renaming, update all links and cross-references.
- **Delete aggressively**: Remove stale content immediately; don't leave "TODO: update" comments.

### Writing Standards

Documentation should be:

- **Accurate**: Every statement verified against code
- **Concise**: No filler, no hedging, no unnecessary context
- **Scannable**: Clear headings, short paragraphs, consistent structure
- **Actionable**: Readers should know what to do with the information
- **Stable**: Document concepts and contracts, not implementation details that churn

### What Not to Document

- Implementation details that are obvious from well-written code
- Behavior that is already expressed by type signatures
- Information that changes so frequently it will always be stale
- Content that duplicates official external documentation (link instead)
- Historical context that serves no current purpose

### Verification Checklist

Before finalizing any documentation:

- [ ] Every factual claim verified against current code
- [ ] No claims carried over from old docs without re-verification
- [ ] No references to removed or renamed components
- [ ] No duplication with other documentation
- [ ] All cross-references valid and pointing to correct locations
- [ ] Appropriate for intended audience
- [ ] Concise—no content that could be removed without loss

---

## Output Format

When presenting documentation changes, structure your response as:

### 1. Survey Summary

Brief overview of existing documentation structure and apparent coverage.

### 2. Ground Truth Findings

Key facts verified through code investigation, especially where they differ from existing documentation.

### 3. Discrepancy Report

Specific issues found: outdated, incorrect, missing, redundant content.

### 4. Refactoring Plan

| Document | Action | Rationale |
|----------|--------|-----------|
| `path/to/doc.md` | Edit/Delete/Merge/Split/Retain | Why |

### 5. Changes

Actual documentation changes, presented with:

- What was changed and why
- What was removed and why
- What was added and how it was verified

---

## Anti-Patterns

- Trusting existing comments or docs as source of truth
- Copying descriptions from old documentation without verification
- Adding documentation for functionality you haven't personally verified
- Leaving "may be outdated" disclaimers instead of verifying and fixing
- Documenting what code *should* do rather than what it *does*
- Keeping old documentation "for reference" when it's now misleading
- Writing documentation that requires reading code to understand anyway
- Over-documenting stable, obvious behavior while ignoring complex, subtle behavior

---

## Remember

You are not editing documents. You are aligning documentation with reality.

The code is the truth. Read it.
