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
//!     .test_name("lockout_after_max_attempts")
//!     .description("Verify account locks after 3 failed attempts")
//!     .code_location("src/login.rs", 150, 200)
//!     .input("username", "test@example.com")
//!     .input("failed_attempts", 3)
//!     .expected("account_locked", true)
//!     .execute(|collector| {
//!         // Test code that returns observed output
//!         serde_json::json!({ "account_locked": true })
//!     });
//!
//! assert!(artifact.passed);
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Individual evidence item captured during test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Type of evidence (log, event, assertion, etc.)
    pub evidence_type: EvidenceType,
    /// When this evidence was captured
    pub timestamp: DateTime<Utc>,
    /// The evidence content
    pub content: serde_json::Value,
    /// Optional description
    pub description: Option<String>,
}

/// Types of evidence that can be collected during test execution
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
    /// Create a new code location with a single line reference
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line_start: line,
            line_end: None,
            function: None,
        }
    }

    /// Create a code location with a line range
    pub fn with_range(file: impl Into<String>, start: u32, end: u32) -> Self {
        Self {
            file: file.into(),
            line_start: start,
            line_end: Some(end),
            function: None,
        }
    }

    /// Add function name to the location
    pub fn with_function(mut self, function: impl Into<String>) -> Self {
        self.function = Some(function.into());
        self
    }
}

impl std::fmt::Display for CodeLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(end) = self.line_end {
            write!(f, "{}:{}-{}", self.file, self.line_start, end)
        } else {
            write!(f, "{}:{}", self.file, self.line_start)
        }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ReportSignature>,
}

/// Summary statistics for the test run
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

/// Summary for a control family (e.g., AC, SC, IA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilySummary {
    /// Total controls in this family
    pub total: usize,
    /// Passed controls
    pub passed: usize,
    /// Failed controls
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

/// Errors that can occur during report signing or verification
#[derive(Debug, Error)]
pub enum SigningError {
    /// Report has not been signed
    #[error("Report is not signed")]
    NotSigned,

    /// The signing key is invalid (wrong length, etc.)
    #[error("Invalid signing key")]
    InvalidKey,

    /// The signature format is invalid (not valid base64, etc.)
    #[error("Invalid signature format")]
    InvalidSignature,

    /// JSON serialization failed during signing
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Signature verification failed (signature doesn't match)
    #[error("Signature verification failed")]
    VerificationFailed,
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

    /// Update summary statistics based on current artifacts
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

    /// Export as pretty-printed JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export as minified JSON (for signing)
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Export as JSON value
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Write to file with timestamp in filename
    pub fn write_to_file(&self, dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let filename = format!(
            "compliance_report_{}.json",
            self.generated_at.format("%Y-%m-%dT%H-%M-%SZ")
        );
        let path = dir.join(filename);
        let json = self
            .to_json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Get artifacts by control family
    pub fn artifacts_by_family(&self, family: &str) -> Vec<&ControlTestArtifact> {
        self.artifacts
            .iter()
            .filter(|a| a.control_id.starts_with(family))
            .collect()
    }

    /// Get all failed artifacts
    pub fn failed_artifacts(&self) -> Vec<&ControlTestArtifact> {
        self.artifacts.iter().filter(|a| !a.passed).collect()
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.summary.failed == 0 && self.summary.total_controls > 0
    }

    /// Sign the report using HMAC-SHA256
    ///
    /// The signature covers the JSON representation of the report
    /// (excluding the signature field itself). This allows verification
    /// that the report hasn't been tampered with.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key for signing (should be at least 32 bytes)
    /// * `key_id` - An identifier for the key (not the key itself), stored in the signature
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut report = ComplianceTestReport::new("FedRAMP Moderate");
    /// // ... add artifacts ...
    /// report.sign(b"my-secret-signing-key", "prod-key-2025")?;
    /// ```
    pub fn sign(&mut self, key: &[u8], key_id: impl Into<String>) -> Result<(), SigningError> {
        // Create an unsigned copy for hashing (signature field must be None)
        let mut unsigned = self.clone();
        unsigned.signature = None;

        // Serialize to compact JSON for consistent hashing
        let json = unsigned
            .to_json_compact()
            .map_err(|e| SigningError::Serialization(e.to_string()))?;

        // Create HMAC-SHA256 instance with the key
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|_| SigningError::InvalidKey)?;

        // Feed the JSON data into the HMAC
        mac.update(json.as_bytes());

        // Finalize and get the authentication tag
        let signature = mac.finalize().into_bytes();

        // Store the signature in the report
        self.signature = Some(ReportSignature {
            algorithm: "HMAC-SHA256".to_string(),
            key_id: key_id.into(),
            value: BASE64.encode(signature),
            signed_at: Utc::now(),
        });

        Ok(())
    }

    /// Verify the report's HMAC-SHA256 signature
    ///
    /// Recomputes the HMAC over the report (excluding signature) and compares
    /// it to the stored signature using constant-time comparison.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key that was used for signing
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Signature is valid
    /// * `Ok(false)` - Signature is invalid (report may have been tampered with)
    /// * `Err(SigningError::NotSigned)` - Report has no signature
    /// * `Err(SigningError::InvalidSignature)` - Signature format is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// let key = b"my-secret-signing-key";
    /// if report.verify(key)? {
    ///     println!("Report is authentic and unmodified");
    /// } else {
    ///     println!("WARNING: Report may have been tampered with!");
    /// }
    /// ```
    pub fn verify(&self, key: &[u8]) -> Result<bool, SigningError> {
        // Get the stored signature
        let sig = self.signature.as_ref().ok_or(SigningError::NotSigned)?;

        // Create an unsigned copy (same as during signing)
        let mut unsigned = self.clone();
        unsigned.signature = None;

        // Serialize to compact JSON (must match signing format exactly)
        let json = unsigned
            .to_json_compact()
            .map_err(|e| SigningError::Serialization(e.to_string()))?;

        // Create HMAC-SHA256 with the verification key
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|_| SigningError::InvalidKey)?;
        mac.update(json.as_bytes());

        // Decode the stored signature from base64
        let expected = BASE64
            .decode(&sig.value)
            .map_err(|_| SigningError::InvalidSignature)?;

        // Verify using constant-time comparison (prevents timing attacks)
        Ok(mac.verify_slice(&expected).is_ok())
    }

    /// Check if the report has been signed
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Get the key ID used for signing, if signed
    pub fn signing_key_id(&self) -> Option<&str> {
        self.signature.as_ref().map(|s| s.key_id.as_str())
    }
}

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

    /// Set the code location with function name
    pub fn code_location_with_fn(
        mut self,
        file: &str,
        line_start: u32,
        line_end: u32,
        function: &str,
    ) -> Self {
        self.code_location = Some(
            CodeLocation::with_range(file, line_start, line_end).with_function(function),
        );
        self
    }

    /// Add an input parameter
    pub fn input<V: Serialize>(mut self, name: impl Into<String>, value: V) -> Self {
        self.inputs
            .insert(name.into(), serde_json::to_value(value).unwrap_or_default());
        self
    }

    /// Add an expected output
    pub fn expected<V: Serialize>(mut self, name: impl Into<String>, value: V) -> Self {
        self.expected
            .insert(name.into(), serde_json::to_value(value).unwrap_or_default());
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
        let mut collector = EvidenceCollector::new();

        let result = test_fn(&mut collector);
        let duration = start.elapsed();

        let observed: HashMap<String, serde_json::Value> = match serde_json::to_value(&result) {
            Ok(serde_json::Value::Object(map)) => map.into_iter().collect(),
            Ok(value) => {
                let mut map = HashMap::new();
                map.insert("result".to_string(), value);
                map
            }
            Err(_) => HashMap::new(),
        };

        // Compare expected vs observed
        let passed = self.expected.iter().all(|(key, expected_val)| {
            observed
                .get(key)
                .map(|v| v == expected_val)
                .unwrap_or(false)
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
            code_location: self
                .code_location
                .unwrap_or_else(|| CodeLocation::new("unknown", 0)),
            inputs: self.inputs,
            expected: self.expected,
            observed,
            passed,
            failure_reason,
            evidence: collector.into_evidence(),
            related_controls: self.related_controls,
        }
    }

    /// Execute the test without an evidence collector (simpler API)
    pub fn execute_simple<F, R>(self, test_fn: F) -> ControlTestArtifact
    where
        F: FnOnce() -> R,
        R: Serialize,
    {
        self.execute(|_| test_fn())
    }
}

/// Collector for gathering evidence during test execution
pub struct EvidenceCollector {
    evidence: Vec<EvidenceItem>,
}

impl EvidenceCollector {
    /// Create a new evidence collector
    pub fn new() -> Self {
        Self {
            evidence: Vec::new(),
        }
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
    pub fn security_event(
        &mut self,
        event: &crate::observability::SecurityEvent,
        details: serde_json::Value,
    ) {
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
    pub fn assertion(
        &mut self,
        description: impl Into<String>,
        passed: bool,
        details: serde_json::Value,
    ) {
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

    /// Record a database query result as evidence
    pub fn database_query(&mut self, query: impl Into<String>, result: serde_json::Value) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::DatabaseQuery,
            timestamp: Utc::now(),
            content: serde_json::json!({
                "query": query.into(),
                "result": result,
            }),
            description: None,
        });
    }

    /// Record custom evidence
    pub fn custom(
        &mut self,
        evidence_type: impl Into<String>,
        content: serde_json::Value,
        description: Option<String>,
    ) {
        self.evidence.push(EvidenceItem {
            evidence_type: EvidenceType::Custom(evidence_type.into()),
            timestamp: Utc::now(),
            content,
            description,
        });
    }

    /// Get the number of evidence items collected
    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    /// Check if any evidence has been collected
    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }

    /// Consume the collector and return collected evidence
    pub(crate) fn into_evidence(self) -> Vec<EvidenceItem> {
        self.evidence
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the Rust compiler version
fn rustc_version() -> String {
    option_env!("RUSTC_VERSION")
        .map(String::from)
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_location_display() {
        let loc = CodeLocation::new("src/test.rs", 42);
        assert_eq!(loc.to_string(), "src/test.rs:42");

        let loc_range = CodeLocation::with_range("src/test.rs", 42, 100);
        assert_eq!(loc_range.to_string(), "src/test.rs:42-100");
    }

    #[test]
    fn test_code_location_with_function() {
        let loc = CodeLocation::new("src/test.rs", 42).with_function("test_fn");
        assert_eq!(loc.function, Some("test_fn".to_string()));
    }

    #[test]
    fn test_evidence_collector_log() {
        let mut collector = EvidenceCollector::new();
        collector.log("Test message");
        assert_eq!(collector.len(), 1);
        assert!(!collector.is_empty());
    }

    #[test]
    fn test_evidence_collector_assertion() {
        let mut collector = EvidenceCollector::new();
        collector.assertion("Test passed", true, serde_json::json!({"value": 42}));
        let evidence = collector.into_evidence();
        assert_eq!(evidence.len(), 1);
        assert!(matches!(evidence[0].evidence_type, EvidenceType::Assertion));
    }

    #[test]
    fn test_evidence_collector_configuration() {
        let mut collector = EvidenceCollector::new();
        collector.configuration("test_config", serde_json::json!({"enabled": true}));
        let evidence = collector.into_evidence();
        assert_eq!(evidence.len(), 1);
        assert!(matches!(
            evidence[0].evidence_type,
            EvidenceType::Configuration
        ));
    }

    #[test]
    fn test_artifact_builder_simple() {
        let artifact = ArtifactBuilder::new("AC-7", "Unsuccessful Logon Attempts")
            .test_name("test_lockout")
            .description("Test account lockout")
            .code_location("src/login.rs", 50, 100)
            .input("username", "test@example.com")
            .expected("locked", true)
            .execute_simple(|| serde_json::json!({"locked": true}));

        assert_eq!(artifact.control_id, "AC-7");
        assert_eq!(artifact.test_name, "test_lockout");
        assert!(artifact.passed);
        assert!(artifact.failure_reason.is_none());
    }

    #[test]
    fn test_artifact_builder_with_evidence() {
        let artifact = ArtifactBuilder::new("SI-10", "Input Validation")
            .test_name("test_validation")
            .expected("valid", true)
            .execute(|collector| {
                collector.log("Starting validation");
                collector.assertion("Input validated", true, serde_json::json!({}));
                serde_json::json!({"valid": true})
            });

        assert!(artifact.passed);
        assert_eq!(artifact.evidence.len(), 2);
    }

    #[test]
    fn test_artifact_builder_failure() {
        let artifact = ArtifactBuilder::new("AC-7", "Test Control")
            .expected("value", 100)
            .execute_simple(|| serde_json::json!({"value": 50}));

        assert!(!artifact.passed);
        assert!(artifact.failure_reason.is_some());
    }

    #[test]
    fn test_artifact_builder_related_controls() {
        let artifact = ArtifactBuilder::new("AC-7", "Test")
            .related_control("AC-2")
            .related_control("IA-5")
            .expected("done", true)
            .execute_simple(|| serde_json::json!({"done": true}));

        assert_eq!(artifact.related_controls, vec!["AC-2", "IA-5"]);
    }

    #[test]
    fn test_compliance_test_report_new() {
        let report = ComplianceTestReport::new("FedRAMP Moderate");
        assert_eq!(report.schema_version, "1.0.0");
        assert_eq!(report.compliance_profile, "FedRAMP Moderate");
        assert!(report.artifacts.is_empty());
        assert_eq!(report.summary.total_controls, 0);
    }

    #[test]
    fn test_compliance_test_report_add_artifact() {
        let mut report = ComplianceTestReport::new("FedRAMP Moderate");

        let artifact1 = ArtifactBuilder::new("AC-7", "Test 1")
            .expected("ok", true)
            .execute_simple(|| serde_json::json!({"ok": true}));

        let artifact2 = ArtifactBuilder::new("SC-5", "Test 2")
            .expected("ok", true)
            .execute_simple(|| serde_json::json!({"ok": false}));

        report.add_artifact(artifact1);
        report.add_artifact(artifact2);

        assert_eq!(report.summary.total_controls, 2);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.summary.pass_rate, 50.0);
    }

    #[test]
    fn test_compliance_test_report_by_family() {
        let mut report = ComplianceTestReport::new("Test");

        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );
        report.add_artifact(
            ArtifactBuilder::new("AC-11", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );
        report.add_artifact(
            ArtifactBuilder::new("SC-5", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        assert_eq!(report.summary.by_family.get("AC").unwrap().total, 2);
        assert_eq!(report.summary.by_family.get("SC").unwrap().total, 1);
    }

    #[test]
    fn test_compliance_test_report_artifacts_by_family() {
        let mut report = ComplianceTestReport::new("Test");

        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );
        report.add_artifact(
            ArtifactBuilder::new("SC-5", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        let ac_artifacts = report.artifacts_by_family("AC");
        assert_eq!(ac_artifacts.len(), 1);
        assert_eq!(ac_artifacts[0].control_id, "AC-7");
    }

    #[test]
    fn test_compliance_test_report_failed_artifacts() {
        let mut report = ComplianceTestReport::new("Test");

        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Passing")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );
        report.add_artifact(
            ArtifactBuilder::new("SC-5", "Failing")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": false})),
        );

        let failed = report.failed_artifacts();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].control_id, "SC-5");
    }

    #[test]
    fn test_compliance_test_report_all_passed() {
        let mut report = ComplianceTestReport::new("Test");
        assert!(!report.all_passed()); // Empty report

        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );
        assert!(report.all_passed());

        report.add_artifact(
            ArtifactBuilder::new("SC-5", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": false})),
        );
        assert!(!report.all_passed());
    }

    #[test]
    fn test_compliance_test_report_json_serialization() {
        let mut report = ComplianceTestReport::new("Test Profile");
        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test Control")
                .test_name("test_example")
                .expected("result", true)
                .execute_simple(|| serde_json::json!({"result": true})),
        );

        let json = report.to_json().expect("JSON serialization");
        assert!(json.contains("AC-7"));
        assert!(json.contains("Test Profile"));
        assert!(json.contains("test_example"));

        // Roundtrip
        let deserialized: ComplianceTestReport =
            serde_json::from_str(&json).expect("JSON deserialization");
        assert_eq!(deserialized.compliance_profile, "Test Profile");
        assert_eq!(deserialized.artifacts.len(), 1);
    }

    #[test]
    fn test_evidence_type_serialization() {
        let log_type = EvidenceType::Log;
        let json = serde_json::to_string(&log_type).unwrap();
        assert_eq!(json, "\"log\"");

        let custom_type = EvidenceType::Custom("my_type".to_string());
        let json = serde_json::to_string(&custom_type).unwrap();
        assert!(json.contains("custom"));
        assert!(json.contains("my_type"));
    }

    // HMAC-SHA256 signing tests

    #[test]
    fn test_sign_and_verify_success() {
        let mut report = ComplianceTestReport::new("Test");
        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        let key = b"test-signing-key-at-least-32-bytes-long";

        // Sign the report
        report.sign(key, "test-key-001").expect("signing should succeed");

        // Verify the signature
        assert!(report.is_signed());
        assert_eq!(report.signing_key_id(), Some("test-key-001"));
        assert!(report.verify(key).expect("verification should succeed"));
    }

    #[test]
    fn test_verify_with_wrong_key_fails() {
        let mut report = ComplianceTestReport::new("Test");
        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        let signing_key = b"correct-signing-key-32-bytes-xx";
        let wrong_key = b"wrong-key-for-verification-xxxx";

        report.sign(signing_key, "key-1").expect("signing should succeed");

        // Verification with wrong key should return false
        assert!(!report.verify(wrong_key).expect("verification should not error"));
    }

    #[test]
    fn test_verify_unsigned_report_fails() {
        let report = ComplianceTestReport::new("Test");

        let key = b"some-key";
        let result = report.verify(key);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SigningError::NotSigned));
    }

    #[test]
    fn test_verify_tampered_report_fails() {
        let mut report = ComplianceTestReport::new("Test");
        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        let key = b"test-signing-key-at-least-32-bytes-long";
        report.sign(key, "key-1").expect("signing should succeed");

        // Tamper with the report after signing
        report.compliance_profile = "TAMPERED".to_string();

        // Verification should fail
        assert!(!report.verify(key).expect("verification should not error"));
    }

    #[test]
    fn test_signature_in_json_output() {
        let mut report = ComplianceTestReport::new("Test");
        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        let key = b"test-signing-key-at-least-32-bytes-long";
        report.sign(key, "prod-key-2025").expect("signing should succeed");

        let json = report.to_json().expect("JSON serialization");

        // Signature should be in the output
        assert!(json.contains("signature"));
        assert!(json.contains("HMAC-SHA256"));
        assert!(json.contains("prod-key-2025"));
        assert!(json.contains("signed_at"));
    }

    #[test]
    fn test_signature_excluded_when_not_signed() {
        let mut report = ComplianceTestReport::new("Test");
        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        let json = report.to_json().expect("JSON serialization");

        // Signature field should not appear in output
        assert!(!json.contains("\"signature\""));
    }

    #[test]
    fn test_signed_report_roundtrip() {
        let mut report = ComplianceTestReport::new("FedRAMP Moderate");
        report.add_artifact(
            ArtifactBuilder::new("AC-7", "Test")
                .expected("ok", true)
                .execute_simple(|| serde_json::json!({"ok": true})),
        );

        let key = b"test-signing-key-at-least-32-bytes-long";
        report.sign(key, "key-1").expect("signing should succeed");

        // Serialize and deserialize
        let json = report.to_json().expect("JSON serialization");
        let restored: ComplianceTestReport =
            serde_json::from_str(&json).expect("JSON deserialization");

        // Signature should survive roundtrip and still verify
        assert!(restored.is_signed());
        assert!(restored.verify(key).expect("verification should succeed"));
    }

    #[test]
    fn test_signing_error_display() {
        let err = SigningError::NotSigned;
        assert_eq!(err.to_string(), "Report is not signed");

        let err = SigningError::InvalidKey;
        assert_eq!(err.to_string(), "Invalid signing key");

        let err = SigningError::VerificationFailed;
        assert_eq!(err.to_string(), "Signature verification failed");

        let err = SigningError::Serialization("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_is_signed_helper() {
        let mut report = ComplianceTestReport::new("Test");
        assert!(!report.is_signed());

        let key = b"test-key-32-bytes-long-xxxxxxxx";
        report.sign(key, "key").unwrap();
        assert!(report.is_signed());
    }
}
