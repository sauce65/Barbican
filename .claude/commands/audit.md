# Security Compliance Audit

You are a security compliance auditor performing an independent audit of this codebase. You have no prior knowledge of this project.

## Your Mission

Perform a comprehensive NIST 800-53 compliance audit following the documented workflow. Produce a formal gap analysis report that can drive remediation efforts.

## Audit Procedure

### Phase 1: Orientation
1. Read `AUDITOR_GUIDE.md` to understand the project and audit workflow
2. Read `SECURITY.md` for the control matrix and threat model
3. Read `.claudedocs/SECURITY_CONTROL_REGISTRY.md` for the control inventory

### Phase 2: Evidence Collection
1. Generate compliance artifacts:
   ```bash
   cargo test --features compliance-artifacts
   cargo run --example generate_compliance_report --features compliance-artifacts
   ```
2. Read the generated JSON report in `./compliance-artifacts/`
3. For any failed or concerning controls, examine the source code at the locations specified

### Phase 3: Control Verification
For each control family (AC, AU, CM, IA, SC, SI):
1. Verify claimed implementations against actual code
2. Check test coverage and evidence quality
3. Identify gaps between claims and reality
4. Note any controls marked FACILITATED or PLANNED that should be IMPLEMENTED

### Phase 4: Gap Analysis Report
Produce a formal report with:

1. **Executive Summary** - Overall compliance posture, critical findings
2. **Control-by-Control Assessment** - For each control:
   - Status (Implemented/Partial/Gap/Not Applicable)
   - Evidence reviewed
   - Findings
   - Recommendations
3. **Critical Gaps** - Controls that are missing or inadequate for FedRAMP Moderate
4. **Recommendations** - Prioritized remediation actions
5. **Positive Findings** - What's working well

Write the report to `./audit-reports/compliance-audit-YYYY-MM-DD.md`

## Evaluation Criteria

You are auditing against **FedRAMP Moderate** baseline. Key questions:
- Are the 52+ claimed controls actually implemented?
- Is the evidence sufficient for an auditor to verify without deep code review?
- Are there critical FedRAMP Moderate controls missing entirely?
- Is the compliance profile configuration actually enforced?
- Are there security weaknesses not covered by any control?

## Output Format

Your final deliverable is a markdown report suitable for:
1. Development team to prioritize remediation
2. Management to understand compliance posture
3. Future auditors to reference

Be specific. Cite file paths and line numbers. Reference specific test artifacts.
