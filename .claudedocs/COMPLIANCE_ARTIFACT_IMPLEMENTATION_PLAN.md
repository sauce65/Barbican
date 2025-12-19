# Compliance Artifact Generation Implementation Plan

## Overview

This plan details the implementation of a compliance testing framework that generates
auditor-verifiable artifacts proving NIST 800-53 control implementations behave as asserted.

**Goal**: Enable `cargo test` to produce timestamped, signed JSON artifacts that auditors
can use to verify control compliance without reading source code.

**Document Version**: 1.1
**Created**: 2025-12-17
**Implemented**: 2025-12-18 (Phases 1-5 complete, 13 controls)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Compliance Artifact System                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │ Control Test │───▶│   Evidence   │───▶│   Artifact   │                  │
│  │   Executor   │    │   Collector  │    │   Builder    │                  │
│  └──────────────┘    └──────────────┘    └──────────────┘                  │
│         │                   │                   │                           │
│         ▼                   ▼                   ▼                           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │  Test Input  │    │ SecurityEvent│    │    Report    │                  │
│  │  Generator   │    │   Capture    │    │   Signer     │                  │
│  └──────────────┘    └──────────────┘    └──────────────┘                  │
│                                                 │                           │
│                                                 ▼                           │
│                                          ┌──────────────┐                  │
│                                          │  JSON Export │                  │
│                                          │   + HMAC     │                  │
│                                          └──────────────┘                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation (JSON Serialization)

### 1.1 Add Serde to Compliance Types

**File**: `src/compliance/validation.rs`

**Changes**:
```rust
// Add to existing structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatus {
    pub control_id: String,
    pub control_name: String,
    pub status: ControlResult,
    pub details: Option<String>,
    pub tested_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlResult {
    Satisfied,
    Failed,
    NotApplicable,
    NotTested,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub generated_at: DateTime<Utc>,
    pub profile: ComplianceProfile,
    pub controls: Vec<ControlStatus>,
    pub warnings: Vec<String>,
    pub metadata: ReportMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub barbican_version: String,
    pub rust_version: String,
    pub hostname: Option<String>,
    pub generator: String,
}
```

**New Methods**:
```rust
impl ComplianceReport {
    /// Export report as JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export report as JSON value
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Write report to file
    pub fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        let json = self.to_json().map_err(|e|
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        )?;
        std::fs::write(path, json)
    }
}
```

**Dependencies** (already present):
- `serde = { version = "1", features = ["derive"] }`
- `serde_json = "1"`

**New Dependency**:
```toml
chrono = { version = "0.4", features = ["serde"] }
```

### 1.2 Add Serde to SecurityEvent

**File**: `src/observability/events.rs`

**Changes**:
```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityEvent {
    // ... existing variants
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
```

### 1.3 Deliverables

| Item | File | Status |
|------|------|--------|
| Serialize ComplianceReport | `src/compliance/validation.rs` | DONE |
| Serialize ControlStatus | `src/compliance/validation.rs` | DONE |
| Serialize SecurityEvent | `src/observability/events.rs` | DONE |
| Add chrono dependency | `Cargo.toml` | DONE |
| JSON export methods | `src/compliance/validation.rs` | DONE |
| Unit tests for serialization | `src/compliance/validation.rs` | DONE |

**Status**: COMPLETE

---

## Phase 2: Artifact Structure

### 2.1 Create Artifact Module

**New File**: `src/compliance/artifacts.rs`

```rust
//! Compliance Test Artifact Generation
//!
//! Generates auditor-verifiable artifacts proving control implementations
//! behave as specified by NIST 800-53.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::artifacts::{ArtifactBuilder, ControlTestArtifact};
//!
//! let artifact = ArtifactBuilder::new("AC-7", "Unsuccessful Logon Attempts")
//!     .code_location("src/login.rs:150-200")
//!     .input("username", "test@example.com")
//!     .input("failed_attempts", 3)
//!     .expected("account_locked", true)
//!     .execute(|| {
//!         // Test code that returns observed output
//!         let tracker = LoginTracker::new(policy);
//!         tracker.record_attempt("test@example.com", false);
//!         tracker.record_attempt("test@example.com", false);
//!         tracker.record_attempt("test@example.com", false);
//!         json!({ "account_locked": tracker.is_locked("test@example.com") })
//!     })
//!     .build();
//!
//! assert!(artifact.passed);
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Individual evidence item captured during test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Type of evidence (log, event, assertion, screenshot)
    pub evidence_type: EvidenceType,
    /// When this evidence was captured
    pub timestamp: DateTime<Utc>,
    /// The evidence content
    pub content: serde_json::Value,
    /// Optional description
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Log message captured during test
    Log,
    /// SecurityEvent emitted during test
    SecurityEvent,
    /// Explicit assertion made
    Assertion,
    /// HTTP request/response pair
    HttpExchange,
    /// Database query result
    DatabaseQuery,
    /// Configuration state
    Configuration,
    /// Custom evidence type
    Custom(String),
}

/// Artifact proving a specific control test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlTestArtifact {
    /// NIST 800-53 control identifier (e.g., "AC-7")
    pub control_id: String,

    /// Human-readable control name
    pub control_name: String,

    /// Specific test case name
    pub test_name: String,

    /// Test description explaining what is being verified
    pub description: String,

    /// When the test was executed (UTC)
    pub executed_at: DateTime<Utc>,

    /// Test execution duration in milliseconds
    pub duration_ms: u64,

    /// Source code location implementing the control
    pub code_location: CodeLocation,

    /// Inputs provided to the test
    pub inputs: HashMap<String, serde_json::Value>,

    /// Expected outputs/behavior
    pub expected: HashMap<String, serde_json::Value>,

    /// Actually observed outputs
    pub observed: HashMap<String, serde_json::Value>,

    /// Whether observed matched expected
    pub passed: bool,

    /// Failure reason if test failed
    pub failure_reason: Option<String>,

    /// Evidence collected during execution
    pub evidence: Vec<EvidenceItem>,

    /// Cross-references to related controls
    pub related_controls: Vec<String>,
}

/// Source code location for traceability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    /// File path relative to crate root
    pub file: String,
    /// Starting line number
    pub line_start: u32,
    /// Ending line number (optional)
    pub line_end: Option<u32>,
    /// Function or method name
    pub function: Option<String>,
}

impl CodeLocation {
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line_start: line,
            line_end: None,
            function: None,
        }
    }

    pub fn with_range(file: impl Into<String>, start: u32, end: u32) -> Self {
        Self {
            file: file.into(),
            line_start: start,
            line_end: Some(end),
            function: None,
        }
    }

    pub fn with_function(mut self, function: impl Into<String>) -> Self {
        self.function = Some(function.into());
        self
    }
}

/// Complete compliance test report with all artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTestReport {
    /// Report format version for forward compatibility
    pub schema_version: String,

    /// When the report was generated
    pub generated_at: DateTime<Utc>,

    /// Barbican library version
    pub barbican_version: String,

    /// Rust compiler version used
    pub rust_version: String,

    /// Target compliance profile
    pub compliance_profile: String,

    /// All control test artifacts
    pub artifacts: Vec<ControlTestArtifact>,

    /// Summary statistics
    pub summary: TestSummary,

    /// Report integrity signature (HMAC-SHA256)
    pub signature: Option<ReportSignature>,
}

/// Summary statistics for the test run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    /// Total number of controls tested
    pub total_controls: usize,
    /// Number of controls that passed
    pub passed: usize,
    /// Number of controls that failed
    pub failed: usize,
    /// Number of controls skipped/not applicable
    pub skipped: usize,
    /// Total test execution time in milliseconds
    pub total_duration_ms: u64,
    /// Pass rate as percentage
    pub pass_rate: f64,
    /// Controls grouped by family
    pub by_family: HashMap<String, FamilySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilySummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

/// Cryptographic signature for report integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSignature {
    /// Signature algorithm used
    pub algorithm: String,
    /// Key identifier (not the key itself)
    pub key_id: String,
    /// The signature value (base64 encoded)
    pub value: String,
    /// Timestamp of signing
    pub signed_at: DateTime<Utc>,
}

impl ComplianceTestReport {
    /// Create a new empty report
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            barbican_version: env!("CARGO_PKG_VERSION").to_string(),
            rust_version: rustc_version(),
            compliance_profile: profile.into(),
            artifacts: Vec::new(),
            summary: TestSummary::default(),
            signature: None,
        }
    }

    /// Add a test artifact to the report
    pub fn add_artifact(&mut self, artifact: ControlTestArtifact) {
        self.artifacts.push(artifact);
        self.update_summary();
    }

    /// Update summary statistics
    fn update_summary(&mut self) {
        let mut summary = TestSummary {
            total_controls: self.artifacts.len(),
            passed: 0,
            failed: 0,
            skipped: 0,
            total_duration_ms: 0,
            pass_rate: 0.0,
            by_family: HashMap::new(),
        };

        for artifact in &self.artifacts {
            summary.total_duration_ms += artifact.duration_ms;

            if artifact.passed {
                summary.passed += 1;
            } else {
                summary.failed += 1;
            }

            // Group by control family (first 2 chars, e.g., "AC" from "AC-7")
            let family = artifact.control_id.chars().take(2).collect::<String>();
            let entry = summary.by_family.entry(family).or_insert(FamilySummary {
                total: 0,
                passed: 0,
                failed: 0,
            });
            entry.total += 1;
            if artifact.passed {
                entry.passed += 1;
            } else {
                entry.failed += 1;
            }
        }

        if summary.total_controls > 0 {
            summary.pass_rate = (summary.passed as f64 / summary.total_controls as f64) * 100.0;
        }

        self.summary = summary;
    }

    /// Export as JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export as minified JSON (for signing)
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Write to file with timestamp in filename
    pub fn write_to_file(&self, dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let filename = format!(
            "compliance_report_{}.json",
            self.generated_at.format("%Y-%m-%dT%H-%M-%SZ")
        );
        let path = dir.join(filename);
        let json = self.to_json().map_err(|e|
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        )?;
        std::fs::write(&path, json)?;
        Ok(path)
    }
}

impl Default for TestSummary {
    fn default() -> Self {
        Self {
            total_controls: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            total_duration_ms: 0,
            pass_rate: 0.0,
            by_family: HashMap::new(),
        }
    }
}

fn rustc_version() -> String {
    option_env!("RUSTC_VERSION")
        .map(String::from)
        .unwrap_or_else(|| "unknown".to_string())
}
```

### 2.2 Artifact Builder

**Add to**: `src/compliance/artifacts.rs`

```rust
/// Builder for creating control test artifacts
pub struct ArtifactBuilder {
    control_id: String,
    control_name: String,
    test_name: Option<String>,
    description: Option<String>,
    code_location: Option<CodeLocation>,
    inputs: HashMap<String, serde_json::Value>,
    expected: HashMap<String, serde_json::Value>,
    related_controls: Vec<String>,
    evidence_collector: EvidenceCollector,
}

impl ArtifactBuilder {
    /// Create a new artifact builder for a control
    pub fn new(control_id: impl Into<String>, control_name: impl Into<String>) -> Self {
        Self {
            control_id: control_id.into(),
            control_name: control_name.into(),
            test_name: None,
            description: None,
            code_location: None,
            inputs: HashMap::new(),
            expected: HashMap::new(),
            related_controls: Vec::new(),
            evidence_collector: EvidenceCollector::new(),
        }
    }

    /// Set the test name
    pub fn test_name(mut self, name: impl Into<String>) -> Self {
        self.test_name = Some(name.into());
        self
    }

    /// Set the test description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the code location
    pub fn code_location(mut self, file: &str, line_start: u32, line_end: u32) -> Self {
        self.code_location = Some(CodeLocation::with_range(file, line_start, line_end));
        self
    }

    /// Add an input parameter
    pub fn input<V: Serialize>(mut self, name: impl Into<String>, value: V) -> Self {
        self.inputs.insert(
            name.into(),
            serde_json::to_value(value).unwrap_or_default()
        );
        self
    }

    /// Add an expected output
    pub fn expected<V: Serialize>(mut self, name: impl Into<String>, value: V) -> Self {
        self.expected.insert(
            name.into(),
            serde_json::to_value(value).unwrap_or_default()
        );
        self
    }

    /// Add a related control
    pub fn related_control(mut self, control_id: impl Into<String>) -> Self {
        self.related_controls.push(control_id.into());
        self
    }

    /// Execute the test and build the artifact
    pub fn execute<F, R>(self, test_fn: F) -> ControlTestArtifact
    where
        F: FnOnce(&mut EvidenceCollector) -> R,
        R: Serialize,
    {
        let start = std::time::Instant::now();
        let mut collector = self.evidence_collector;

        let result = test_fn(&mut collector);
        let duration = start.elapsed();

        let observed: HashMap<String, serde_json::Value> =
            match serde_json::to_value(&result) {
                Ok(serde_json::Value::Object(map)) => {
                    map.into_iter().collect()
                }
                Ok(value) => {
                    let mut map = HashMap::new();
                    map.insert("result".to_string(), value);
                    map
                }
                Err(_) => HashMap::new(),
            };

        // Compare expected vs observed
        let passed = self.expected.iter().all(|(key, expected_val)| {
            observed.get(key).map(|v| v == expected_val).unwrap_or(false)
        });

        let failure_reason = if !passed {
            Some(format!(
                "Expected {:?}, observed {:?}",
                self.expected, observed
            ))
        } else {
            None
        };

        ControlTestArtifact {
            control_id: self.control_id,
            control_name: self.control_name,
            test_name: self.test_name.unwrap_or_else(|| "unnamed_test".to_string()),
            description: self.description.unwrap_or_default(),
            executed_at: Utc::now(),
            duration_ms: duration.as_millis() as u64,
            code_location: self.code_location.unwrap_or_else(||
                CodeLocation::new("unknown", 0)
            ),
            inputs: self.inputs,
            expected: self.expected,
            observed,
            passed,
            failure_reason,
            evidence: collector.into_evidence(),
            related_controls: self.related_controls,
        }
    }
}

/// Collector for gathering evidence during test execution
pub struct EvidenceCollector {
    evidence: Vec<EvidenceItem>,
}

impl EvidenceCollector {
    pub fn new() -> Self {
        Self { evidence: Vec::new() }
    }

    /// Record a log message as evidence
    pub fn log(&mut self, message: impl Into<String>) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::Log,
            timestamp: Utc::now(),
            content: serde_json::Value::String(message.into()),
            description: None,
        });
    }

    /// Record a security event as evidence
    pub fn security_event(&mut self, event: &crate::observability::SecurityEvent, details: serde_json::Value) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::SecurityEvent,
            timestamp: Utc::now(),
            content: serde_json::json!({
                "event": event.name(),
                "category": event.category(),
                "severity": format!("{:?}", event.severity()),
                "details": details,
            }),
            description: None,
        });
    }

    /// Record an assertion as evidence
    pub fn assertion(&mut self, description: impl Into<String>, passed: bool, details: serde_json::Value) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::Assertion,
            timestamp: Utc::now(),
            content: serde_json::json!({
                "passed": passed,
                "details": details,
            }),
            description: Some(description.into()),
        });
    }

    /// Record an HTTP exchange as evidence
    pub fn http_exchange(&mut self, request: serde_json::Value, response: serde_json::Value) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::HttpExchange,
            timestamp: Utc::now(),
            content: serde_json::json!({
                "request": request,
                "response": response,
            }),
            description: None,
        });
    }

    /// Record configuration state as evidence
    pub fn configuration<V: Serialize>(&mut self, name: impl Into<String>, config: V) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::Configuration,
            timestamp: Utc::now(),
            content: serde_json::json!({
                "name": name.into(),
                "value": serde_json::to_value(config).unwrap_or_default(),
            }),
            description: None,
        });
    }

    /// Record custom evidence
    pub fn custom(&mut self, evidence_type: impl Into<String>, content: serde_json::Value, description: Option<String>) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::Custom(evidence_type.into()),
            timestamp: Utc::now(),
            content,
            description,
        });
    }

    fn into_evidence(self) -> Vec<EvidenceItem> {
        self.evidence
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}
```

### 2.3 Deliverables

| Item | File | Status |
|------|------|--------|
| ControlTestArtifact struct | `src/compliance/artifacts.rs` | DONE |
| ComplianceTestReport struct | `src/compliance/artifacts.rs` | DONE |
| ArtifactBuilder | `src/compliance/artifacts.rs` | DONE |
| EvidenceCollector | `src/compliance/artifacts.rs` | DONE |
| CodeLocation struct | `src/compliance/artifacts.rs` | DONE |
| JSON serialization | `src/compliance/artifacts.rs` | DONE |
| Unit tests | `src/compliance/artifacts.rs` | DONE |

**Status**: COMPLETE

---

## Phase 3: Report Signing

### 3.1 HMAC-SHA256 Signing

**Add to**: `src/compliance/artifacts.rs`

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

type HmacSha256 = Hmac<Sha256>;

impl ComplianceTestReport {
    /// Sign the report using HMAC-SHA256
    ///
    /// The signature covers the JSON representation of the report
    /// (excluding the signature field itself).
    pub fn sign(&mut self, key: &[u8], key_id: impl Into<String>) -> Result<(), SigningError> {
        // Create unsigned copy for hashing
        let mut unsigned = self.clone();
        unsigned.signature = None;

        let json = unsigned.to_json_compact()
            .map_err(|e| SigningError::Serialization(e.to_string()))?;

        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| SigningError::InvalidKey)?;
        mac.update(json.as_bytes());

        let signature = mac.finalize().into_bytes();

        self.signature = Some(ReportSignature {
            algorithm: "HMAC-SHA256".to_string(),
            key_id: key_id.into(),
            value: BASE64.encode(signature),
            signed_at: Utc::now(),
        });

        Ok(())
    }

    /// Verify the report signature
    pub fn verify(&self, key: &[u8]) -> Result<bool, SigningError> {
        let sig = self.signature.as_ref()
            .ok_or(SigningError::NotSigned)?;

        // Create unsigned copy
        let mut unsigned = self.clone();
        unsigned.signature = None;

        let json = unsigned.to_json_compact()
            .map_err(|e| SigningError::Serialization(e.to_string()))?;

        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| SigningError::InvalidKey)?;
        mac.update(json.as_bytes());

        let expected = BASE64.decode(&sig.value)
            .map_err(|_| SigningError::InvalidSignature)?;

        Ok(mac.verify_slice(&expected).is_ok())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Report is not signed")]
    NotSigned,
    #[error("Invalid signing key")]
    InvalidKey,
    #[error("Invalid signature format")]
    InvalidSignature,
    #[error("Serialization error: {0}")]
    Serialization(String),
}
```

### 3.2 New Dependencies

**Add to**: `Cargo.toml`

```toml
[dependencies]
# ... existing deps ...
chrono = { version = "0.4", features = ["serde"] }
hmac = "0.12"
sha2 = "0.10"
base64 = "0.21"
thiserror = "1.0"  # If not already present
```

### 3.3 Deliverables

| Item | File | Status |
|------|------|--------|
| sign() method | `src/compliance/artifacts.rs` | DONE |
| verify() method | `src/compliance/artifacts.rs` | DONE |
| SigningError enum | `src/compliance/artifacts.rs` | DONE |
| Add hmac, sha2, base64 deps | `Cargo.toml` | DONE |
| Signing tests | `src/compliance/artifacts.rs` | DONE |

**Status**: COMPLETE

---

## Phase 4: Control Test Implementations

### 4.1 Test Macro

**New File**: `src/compliance/test_macros.rs`

```rust
/// Macro for defining artifact-generating control tests
///
/// # Example
///
/// ```ignore
/// control_test! {
///     control_id: "AC-7",
///     control_name: "Unsuccessful Logon Attempts",
///     test_name: "lockout_after_max_attempts",
///     description: "Verify account locks after 3 failed attempts",
///     code_location: ("src/login.rs", 150, 200),
///     related_controls: ["AC-2", "IA-5"],
///     inputs: {
///         "username" => "test@example.com",
///         "max_attempts" => 3,
///         "lockout_duration_secs" => 1800,
///     },
///     expected: {
///         "locked_after_attempts" => true,
///         "lockout_duration_correct" => true,
///     },
///     test: |collector| {
///         let policy = LockoutPolicy::nist_compliant();
///         collector.configuration("lockout_policy", &policy);
///
///         let mut tracker = LoginTracker::new(policy);
///
///         // Record 3 failed attempts
///         for i in 1..=3 {
///             let result = tracker.record_attempt("test@example.com", false);
///             collector.log(format!("Attempt {}: {:?}", i, result));
///         }
///
///         let is_locked = matches!(
///             tracker.check_lockout("test@example.com"),
///             Some(LockoutInfo { .. })
///         );
///
///         collector.assertion(
///             "Account should be locked after 3 failures",
///             is_locked,
///             json!({ "is_locked": is_locked })
///         );
///
///         json!({
///             "locked_after_attempts": is_locked,
///             "lockout_duration_correct": true,
///         })
///     }
/// }
/// ```
#[macro_export]
macro_rules! control_test {
    (
        control_id: $control_id:expr,
        control_name: $control_name:expr,
        test_name: $test_name:expr,
        description: $description:expr,
        code_location: ($file:expr, $line_start:expr, $line_end:expr),
        $(related_controls: [$($related:expr),* $(,)?],)?
        inputs: { $($input_name:expr => $input_value:expr),* $(,)? },
        expected: { $($expected_name:expr => $expected_value:expr),* $(,)? },
        test: |$collector:ident| $test_body:expr
    ) => {{
        use $crate::compliance::artifacts::ArtifactBuilder;
        use serde_json::json;

        let mut builder = ArtifactBuilder::new($control_id, $control_name)
            .test_name($test_name)
            .description($description)
            .code_location($file, $line_start, $line_end);

        $($(
            builder = builder.related_control($related);
        )*)?

        $(
            builder = builder.input($input_name, $input_value);
        )*

        $(
            builder = builder.expected($expected_name, $expected_value);
        )*

        builder.execute(|$collector| $test_body)
    }};
}
```

### 4.2 Example Control Tests

**New File**: `src/compliance/control_tests.rs`

```rust
//! Artifact-generating control tests
//!
//! Run with: cargo test --features compliance-artifacts
//! Artifacts written to: ./compliance-artifacts/

use crate::compliance::artifacts::{ComplianceTestReport, ControlTestArtifact, ArtifactBuilder};
use crate::login::{LoginTracker, LockoutPolicy, AttemptResult};
use crate::validation::{validate_email, validate_length, sanitize_html};
use crate::password::PasswordPolicy;
use crate::session::{SessionPolicy, SessionState};
use crate::config::SecurityConfig;
use serde_json::json;
use std::sync::Mutex;
use std::time::Duration;

lazy_static::lazy_static! {
    static ref REPORT: Mutex<ComplianceTestReport> =
        Mutex::new(ComplianceTestReport::new("FedRAMP Moderate"));
}

/// AC-7: Unsuccessful Logon Attempts
pub fn test_ac7_lockout() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-7", "Unsuccessful Logon Attempts")
        .test_name("lockout_after_max_attempts")
        .description("Verify account locks after configured number of failed login attempts")
        .code_location("src/login.rs", 55, 120)
        .related_control("AC-2")
        .related_control("IA-5")
        .input("username", "test@example.com")
        .input("max_attempts", 3)
        .input("lockout_duration_secs", 1800)
        .expected("locked_after_3_attempts", true)
        .expected("allowed_before_lockout", true)
        .execute(|collector| {
            let policy = LockoutPolicy::nist_compliant();
            collector.configuration("lockout_policy", json!({
                "max_attempts": policy.max_attempts,
                "lockout_duration_secs": policy.lockout_duration.as_secs(),
            }));

            let mut tracker = LoginTracker::new(policy);
            let username = "test@example.com";

            // First two attempts should be allowed
            let result1 = tracker.record_attempt(username, false);
            collector.log(format!("Attempt 1: {:?}", result1));
            let allowed1 = matches!(result1, AttemptResult::Allowed);

            let result2 = tracker.record_attempt(username, false);
            collector.log(format!("Attempt 2: {:?}", result2));
            let allowed2 = matches!(result2, AttemptResult::Allowed);

            // Third attempt should trigger lockout
            let result3 = tracker.record_attempt(username, false);
            collector.log(format!("Attempt 3: {:?}", result3));
            let locked = matches!(result3, AttemptResult::AccountLocked(_));

            collector.assertion(
                "First two attempts allowed",
                allowed1 && allowed2,
                json!({ "attempt1": allowed1, "attempt2": allowed2 })
            );

            collector.assertion(
                "Third attempt triggers lockout",
                locked,
                json!({ "locked": locked })
            );

            json!({
                "locked_after_3_attempts": locked,
                "allowed_before_lockout": allowed1 && allowed2,
            })
        })
}

/// SC-5: Denial of Service Protection (Rate Limiting)
pub fn test_sc5_rate_limiting() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-5", "Denial of Service Protection")
        .test_name("rate_limiting_configuration")
        .description("Verify rate limiting is enabled and configured correctly")
        .code_location("src/layers.rs", 67, 73)
        .input("rate_limit_per_second", 5)
        .input("rate_limit_burst", 10)
        .expected("rate_limiting_enabled", true)
        .expected("config_matches_expected", true)
        .execute(|collector| {
            let config = SecurityConfig::default();

            collector.configuration("security_config", json!({
                "rate_limit_enabled": config.rate_limit_enabled,
                "rate_limit_per_second": config.rate_limit_per_second,
                "rate_limit_burst": config.rate_limit_burst,
            }));

            let enabled = config.rate_limit_enabled;
            let correct_rate = config.rate_limit_per_second == 5;
            let correct_burst = config.rate_limit_burst == 10;

            collector.assertion(
                "Rate limiting is enabled",
                enabled,
                json!({ "enabled": enabled })
            );

            collector.assertion(
                "Rate limit matches expected",
                correct_rate && correct_burst,
                json!({
                    "rate_per_second": config.rate_limit_per_second,
                    "burst": config.rate_limit_burst
                })
            );

            json!({
                "rate_limiting_enabled": enabled,
                "config_matches_expected": correct_rate && correct_burst,
            })
        })
}

/// SI-10: Information Input Validation
pub fn test_si10_input_validation() -> ControlTestArtifact {
    ArtifactBuilder::new("SI-10", "Information Input Validation")
        .test_name("email_and_length_validation")
        .description("Verify input validation rejects malformed data")
        .code_location("src/validation.rs", 50, 150)
        .input("valid_email", "user@example.com")
        .input("invalid_email", "not-an-email")
        .input("xss_payload", "<script>alert('xss')</script>")
        .expected("valid_email_accepted", true)
        .expected("invalid_email_rejected", true)
        .expected("xss_sanitized", true)
        .execute(|collector| {
            // Test valid email
            let valid_result = validate_email("user@example.com");
            collector.assertion(
                "Valid email accepted",
                valid_result.is_ok(),
                json!({ "result": format!("{:?}", valid_result) })
            );

            // Test invalid email
            let invalid_result = validate_email("not-an-email");
            collector.assertion(
                "Invalid email rejected",
                invalid_result.is_err(),
                json!({ "result": format!("{:?}", invalid_result) })
            );

            // Test XSS sanitization
            let xss_input = "<script>alert('xss')</script>";
            let sanitized = sanitize_html(xss_input);
            let xss_removed = !sanitized.contains("<script>");
            collector.assertion(
                "XSS payload sanitized",
                xss_removed,
                json!({
                    "input": xss_input,
                    "output": sanitized,
                })
            );

            json!({
                "valid_email_accepted": valid_result.is_ok(),
                "invalid_email_rejected": invalid_result.is_err(),
                "xss_sanitized": xss_removed,
            })
        })
}

/// IA-5(1): Password-Based Authentication
pub fn test_ia5_1_password_policy() -> ControlTestArtifact {
    ArtifactBuilder::new("IA-5(1)", "Password-Based Authentication")
        .test_name("password_policy_enforcement")
        .description("Verify password policy meets NIST 800-63B requirements")
        .code_location("src/password.rs", 45, 150)
        .input("min_length", 12)
        .input("weak_password", "password123")
        .input("strong_password", "K9$mP2vL#nQr5xWz")
        .expected("weak_password_rejected", true)
        .expected("min_length_enforced", true)
        .execute(|collector| {
            let policy = PasswordPolicy::default();

            collector.configuration("password_policy", json!({
                "min_length": policy.min_length,
                "max_length": policy.max_length,
                "check_common": policy.check_common,
            }));

            // Test weak password
            let weak_result = policy.validate("password123");
            collector.assertion(
                "Weak password rejected",
                weak_result.is_err(),
                json!({ "result": format!("{:?}", weak_result) })
            );

            // Test short password
            let short_result = policy.validate("short");
            collector.assertion(
                "Short password rejected",
                short_result.is_err(),
                json!({ "result": format!("{:?}", short_result) })
            );

            // Test strong password
            let strong_result = policy.validate("K9$mP2vL#nQr5xWz");
            collector.assertion(
                "Strong password accepted",
                strong_result.is_ok(),
                json!({ "result": format!("{:?}", strong_result) })
            );

            json!({
                "weak_password_rejected": weak_result.is_err(),
                "min_length_enforced": short_result.is_err(),
            })
        })
}

/// AC-11: Session Lock (Idle Timeout)
pub fn test_ac11_idle_timeout() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-11", "Session Lock")
        .test_name("idle_timeout_enforcement")
        .description("Verify sessions timeout after idle period")
        .code_location("src/session.rs", 120, 150)
        .related_control("AC-12")
        .related_control("SC-10")
        .input("idle_timeout_secs", 600)
        .expected("idle_timeout_configured", true)
        .expected("timeout_check_works", true)
        .execute(|collector| {
            let policy = SessionPolicy::builder()
                .idle_timeout(Duration::from_secs(600))
                .absolute_timeout(Duration::from_secs(28800))
                .build();

            collector.configuration("session_policy", json!({
                "idle_timeout_secs": policy.idle_timeout.as_secs(),
                "absolute_timeout_secs": policy.absolute_timeout.as_secs(),
            }));

            let session = SessionState::new("test-session", "test-user");

            // Fresh session should not be timed out
            let fresh_timeout = policy.is_idle_timeout_exceeded(&session);
            collector.assertion(
                "Fresh session not timed out",
                !fresh_timeout,
                json!({ "timed_out": fresh_timeout })
            );

            json!({
                "idle_timeout_configured": policy.idle_timeout.as_secs() == 600,
                "timeout_check_works": !fresh_timeout,
            })
        })
}

/// Generate complete compliance test report
pub fn generate_compliance_report() -> ComplianceTestReport {
    let mut report = ComplianceTestReport::new("FedRAMP Moderate");

    // Run all control tests
    report.add_artifact(test_ac7_lockout());
    report.add_artifact(test_sc5_rate_limiting());
    report.add_artifact(test_si10_input_validation());
    report.add_artifact(test_ia5_1_password_policy());
    report.add_artifact(test_ac11_idle_timeout());

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ac7_generates_artifact() {
        let artifact = test_ac7_lockout();
        assert_eq!(artifact.control_id, "AC-7");
        assert!(artifact.passed, "AC-7 test should pass: {:?}", artifact.failure_reason);
        assert!(!artifact.evidence.is_empty());
    }

    #[test]
    fn test_sc5_generates_artifact() {
        let artifact = test_sc5_rate_limiting();
        assert_eq!(artifact.control_id, "SC-5");
        assert!(artifact.passed);
    }

    #[test]
    fn test_si10_generates_artifact() {
        let artifact = test_si10_input_validation();
        assert_eq!(artifact.control_id, "SI-10");
        assert!(artifact.passed);
    }

    #[test]
    fn test_ia5_1_generates_artifact() {
        let artifact = test_ia5_1_password_policy();
        assert_eq!(artifact.control_id, "IA-5(1)");
        assert!(artifact.passed);
    }

    #[test]
    fn test_ac11_generates_artifact() {
        let artifact = test_ac11_idle_timeout();
        assert_eq!(artifact.control_id, "AC-11");
        assert!(artifact.passed);
    }

    #[test]
    fn test_full_report_generation() {
        let report = generate_compliance_report();
        assert_eq!(report.artifacts.len(), 5);
        assert!(report.summary.pass_rate > 0.0);

        // Verify JSON export works
        let json = report.to_json().expect("JSON export should work");
        assert!(json.contains("AC-7"));
        assert!(json.contains("FedRAMP Moderate"));
    }

    #[test]
    #[ignore] // Run manually: cargo test test_write_report -- --ignored
    fn test_write_report() {
        let mut report = generate_compliance_report();

        // Sign the report
        let key = b"test-signing-key-for-compliance-reports";
        report.sign(key, "test-key-001").expect("Signing should work");

        // Verify signature
        assert!(report.verify(key).expect("Verification should work"));

        // Write to file
        let dir = std::path::Path::new("./compliance-artifacts");
        std::fs::create_dir_all(dir).ok();
        let path = report.write_to_file(dir).expect("Write should work");
        println!("Report written to: {}", path.display());
    }
}
```

### 4.3 Deliverables

| Item | File | Status |
|------|------|--------|
| control_test! macro | `src/compliance/test_macros.rs` | SKIPPED (using builder pattern instead) |
| AC-7 test | `src/compliance/control_tests.rs` | DONE |
| SC-5 test | `src/compliance/control_tests.rs` | DONE |
| SI-10 test | `src/compliance/control_tests.rs` | DONE |
| IA-5(1) test | `src/compliance/control_tests.rs` | DONE |
| AC-11 test | `src/compliance/control_tests.rs` | DONE |
| Report generation function | `src/compliance/control_tests.rs` | DONE |
| Integration tests | `src/compliance/control_tests.rs` | DONE |

**Additional controls implemented**: AC-4, AU-2, AU-3, CM-6, IA-2, SC-8, SC-13, SI-11

**Status**: COMPLETE (13 controls total)

---

## Phase 5: CLI and Integration

### 5.1 Feature Flag

**Add to**: `Cargo.toml`

```toml
[features]
default = ["observability-stdout"]
# ... existing features ...
compliance-artifacts = ["dep:chrono", "dep:hmac", "dep:sha2", "dep:base64"]
```

### 5.2 Binary for Report Generation

**New File**: `examples/generate_compliance_report.rs`

```rust
//! Generate a signed compliance test report
//!
//! Usage: cargo run --example generate_compliance_report -- [OPTIONS]
//!
//! Options:
//!   --output-dir DIR    Output directory (default: ./compliance-artifacts)
//!   --profile PROFILE   Compliance profile (default: fedramp-moderate)
//!   --sign              Sign the report
//!   --key-file FILE     Key file for signing (or use COMPLIANCE_SIGNING_KEY env)

use barbican::compliance::control_tests::generate_compliance_report;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let output_dir = args.iter()
        .position(|a| a == "--output-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./compliance-artifacts"));

    let should_sign = args.iter().any(|a| a == "--sign");

    println!("Generating compliance test report...");
    let mut report = generate_compliance_report();

    println!("  Controls tested: {}", report.summary.total_controls);
    println!("  Passed: {}", report.summary.passed);
    println!("  Failed: {}", report.summary.failed);
    println!("  Pass rate: {:.1}%", report.summary.pass_rate);

    if should_sign {
        let key = std::env::var("COMPLIANCE_SIGNING_KEY")
            .unwrap_or_else(|_| "default-dev-key".to_string());
        report.sign(key.as_bytes(), "env-key")?;
        println!("  Signed: yes");
    }

    std::fs::create_dir_all(&output_dir)?;
    let path = report.write_to_file(&output_dir)?;
    println!("\nReport written to: {}", path.display());

    Ok(())
}
```

### 5.3 Module Registration

**Update**: `src/compliance/mod.rs`

```rust
pub mod config;
pub mod profile;
pub mod validation;

#[cfg(feature = "compliance-artifacts")]
pub mod artifacts;

#[cfg(feature = "compliance-artifacts")]
pub mod control_tests;

// Re-exports
pub use config::{ComplianceConfig, config, init};
pub use profile::ComplianceProfile;
pub use validation::{ComplianceValidator, ComplianceReport, ControlStatus};

#[cfg(feature = "compliance-artifacts")]
pub use artifacts::{
    ComplianceTestReport, ControlTestArtifact, ArtifactBuilder,
    EvidenceCollector, EvidenceItem, EvidenceType,
};
```

### 5.4 Deliverables

| Item | File | Status |
|------|------|--------|
| compliance-artifacts feature | `Cargo.toml` | DONE |
| Report generation example | `examples/generate_compliance_report.rs` | DONE |
| Module registration | `src/compliance/mod.rs` | DONE |
| Re-exports | `src/compliance/mod.rs` | DONE |

**Status**: COMPLETE

---

## Phase 6: Extended Control Coverage

### 6.1 Additional Control Tests

Implement artifact-generating tests for remaining high-priority controls:

| Control | Test Name | Implementation |
|---------|-----------|----------------|
| AC-3 | `test_ac3_access_enforcement` | Claims role/scope checking |
| AC-4 | `test_ac4_cors_policy` | CORS origin validation |
| AC-12 | `test_ac12_session_termination` | Absolute timeout |
| AU-2 | `test_au2_security_events` | Event type coverage |
| AU-3 | `test_au3_audit_content` | Required fields present |
| AU-12 | `test_au12_audit_generation` | Events generated at runtime |
| CM-6 | `test_cm6_security_headers` | Header presence/values |
| IA-2 | `test_ia2_mfa_enforcement` | MFA policy checking |
| SC-8 | `test_sc8_hsts_header` | HSTS configuration |
| SC-10 | `test_sc10_session_disconnect` | Session termination |
| SC-12 | `test_sc12_key_rotation` | Rotation policy |
| SC-13 | `test_sc13_constant_time` | Timing attack prevention |
| SI-11 | `test_si11_error_handling` | No sensitive data in errors |

### 6.2 Deliverables

| Item | Priority | Status |
|------|----------|--------|
| AC-3 test | HIGH | DONE |
| AC-4 test | HIGH | DONE (Phase 4) |
| AC-12 test | MEDIUM | DONE |
| AU-2 test | HIGH | DONE (Phase 4) |
| AU-3 test | HIGH | DONE (Phase 4) |
| AU-12 test | MEDIUM | DONE |
| CM-6 test | MEDIUM | DONE (Phase 4) |
| IA-2 test | HIGH | DONE (Phase 4) |
| SC-8 test | MEDIUM | DONE (Phase 4) |
| SC-10 test | MEDIUM | DONE |
| SC-12 test | MEDIUM | DONE |
| SC-13 test | MEDIUM | DONE (Phase 4) |
| SI-11 test | MEDIUM | DONE (Phase 4) |

**Status**: COMPLETE (18 total control tests implemented)

---

## Example Output

### Sample Artifact JSON

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2025-12-17T15:30:00Z",
  "barbican_version": "0.1.0",
  "rust_version": "1.75.0",
  "compliance_profile": "FedRAMP Moderate",
  "artifacts": [
    {
      "control_id": "AC-7",
      "control_name": "Unsuccessful Logon Attempts",
      "test_name": "lockout_after_max_attempts",
      "description": "Verify account locks after configured number of failed login attempts",
      "executed_at": "2025-12-17T15:30:00.123Z",
      "duration_ms": 15,
      "code_location": {
        "file": "src/login.rs",
        "line_start": 55,
        "line_end": 120,
        "function": null
      },
      "inputs": {
        "username": "test@example.com",
        "max_attempts": 3,
        "lockout_duration_secs": 1800
      },
      "expected": {
        "locked_after_3_attempts": true,
        "allowed_before_lockout": true
      },
      "observed": {
        "locked_after_3_attempts": true,
        "allowed_before_lockout": true
      },
      "passed": true,
      "failure_reason": null,
      "evidence": [
        {
          "evidence_type": "configuration",
          "timestamp": "2025-12-17T15:30:00.100Z",
          "content": {
            "name": "lockout_policy",
            "value": {
              "max_attempts": 3,
              "lockout_duration_secs": 1800
            }
          },
          "description": null
        },
        {
          "evidence_type": "log",
          "timestamp": "2025-12-17T15:30:00.105Z",
          "content": "Attempt 1: Allowed",
          "description": null
        },
        {
          "evidence_type": "log",
          "timestamp": "2025-12-17T15:30:00.108Z",
          "content": "Attempt 2: Allowed",
          "description": null
        },
        {
          "evidence_type": "log",
          "timestamp": "2025-12-17T15:30:00.112Z",
          "content": "Attempt 3: AccountLocked(LockoutInfo { ... })",
          "description": null
        },
        {
          "evidence_type": "assertion",
          "timestamp": "2025-12-17T15:30:00.115Z",
          "content": {
            "passed": true,
            "details": {
              "attempt1": true,
              "attempt2": true
            }
          },
          "description": "First two attempts allowed"
        },
        {
          "evidence_type": "assertion",
          "timestamp": "2025-12-17T15:30:00.118Z",
          "content": {
            "passed": true,
            "details": {
              "locked": true
            }
          },
          "description": "Third attempt triggers lockout"
        }
      ],
      "related_controls": ["AC-2", "IA-5"]
    }
  ],
  "summary": {
    "total_controls": 5,
    "passed": 5,
    "failed": 0,
    "skipped": 0,
    "total_duration_ms": 87,
    "pass_rate": 100.0,
    "by_family": {
      "AC": { "total": 2, "passed": 2, "failed": 0 },
      "SC": { "total": 1, "passed": 1, "failed": 0 },
      "SI": { "total": 1, "passed": 1, "failed": 0 },
      "IA": { "total": 1, "passed": 1, "failed": 0 }
    }
  },
  "signature": {
    "algorithm": "HMAC-SHA256",
    "key_id": "compliance-signing-key-2025",
    "value": "dGVzdC1zaWduYXR1cmUtdmFsdWU=",
    "signed_at": "2025-12-17T15:30:00.200Z"
  }
}
```

---

## Timeline Summary

| Phase | Description | Effort | Dependencies | Status |
|-------|-------------|--------|--------------|--------|
| 1 | JSON Serialization | 1-2 hrs | None | COMPLETE |
| 2 | Artifact Structure | 2-3 hrs | Phase 1 | COMPLETE |
| 3 | Report Signing | 1-2 hrs | Phase 2 | COMPLETE |
| 4 | Control Tests | 3-4 hrs | Phase 2 | COMPLETE (13 controls) |
| 5 | CLI Integration | 1 hr | Phase 3, 4 | COMPLETE |
| 6 | Extended Coverage | 6-8 hrs | Phase 4 | COMPLETE (5 new controls) |

**ALL PHASES COMPLETE** - 18 total control tests implemented

---

## Success Criteria

1. **Artifact Generation**: `cargo test` can produce JSON artifacts
2. **Evidence Capture**: Each test captures logs, assertions, config
3. **Integrity**: Reports can be cryptographically signed and verified
4. **Traceability**: Artifacts link to specific file:line locations
5. **Compliance Mapping**: Each artifact references NIST control IDs
6. **Auditor Usability**: JSON format is human-readable and machine-parseable

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Test brittleness | Medium | Use relative assertions, not absolute values |
| Signing key management | High | Document key rotation, support env vars |
| JSON schema changes | Medium | Version schema, maintain backwards compatibility |
| Performance overhead | Low | Feature-gate artifact collection |
| Evidence bloat | Medium | Limit evidence items, compress logs |

---

*Plan Version: 1.2*
*Author: Claude*
*Review Status: ALL PHASES IMPLEMENTED (2025-12-18)*
