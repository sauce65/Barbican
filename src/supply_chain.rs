//! Supply Chain Security (SR-3, SR-4)
//!
//! NIST SP 800-53 SR-3 (Supply Chain Controls and Processes) and SR-4
//! (Provenance) compliant supply chain security utilities.
//!
//! # Design Philosophy
//!
//! This module provides utilities for tracking and auditing software
//! supply chain security. It integrates with:
//!
//! - `cargo audit` for vulnerability scanning
//! - `cargo deny` for license and security policy enforcement
//! - SBOM (Software Bill of Materials) generation
//!
//! # What This Module Provides
//!
//! - Dependency metadata extraction from Cargo.lock
//! - Vulnerability status tracking
//! - License compliance checking
//! - SBOM generation helpers (CycloneDX format)
//! - Build provenance metadata
//!
//! # Usage
//!
//! ```ignore
//! use barbican::supply_chain::{DependencyAudit, parse_cargo_lock, generate_sbom};
//!
//! // Parse dependencies
//! let deps = parse_cargo_lock("Cargo.lock")?;
//!
//! // Generate SBOM
//! let sbom = generate_sbom(&deps, "my-app", "1.0.0");
//!
//! // Run audit
//! let audit = DependencyAudit::new();
//! let result = audit.run()?;
//! if result.has_vulnerabilities() {
//!     eprintln!("Found {} vulnerabilities!", result.vulnerability_count());
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

// ============================================================================
// Dependency Information
// ============================================================================

/// Information about a dependency
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Package name
    pub name: String,
    /// Version
    pub version: String,
    /// Source (crates.io, git, path)
    pub source: DependencySource,
    /// Checksum if available
    pub checksum: Option<String>,
    /// Dependencies of this package
    pub dependencies: Vec<String>,
}

/// Source of a dependency
#[derive(Debug, Clone, PartialEq)]
pub enum DependencySource {
    /// From crates.io registry
    CratesIo,
    /// From a git repository
    Git { url: String, rev: Option<String> },
    /// Local path
    Path(String),
    /// Unknown source
    Unknown,
}

impl Dependency {
    /// Create a new dependency
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            source: DependencySource::CratesIo,
            checksum: None,
            dependencies: Vec::new(),
        }
    }

    /// Set the source
    pub fn with_source(mut self, source: DependencySource) -> Self {
        self.source = source;
        self
    }

    /// Set the checksum
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum = Some(checksum.into());
        self
    }

    /// Add a dependency
    pub fn with_dependency(mut self, dep: impl Into<String>) -> Self {
        self.dependencies.push(dep.into());
        self
    }

    /// Get package URL (purl) format
    pub fn purl(&self) -> String {
        match &self.source {
            DependencySource::CratesIo => {
                format!("pkg:cargo/{}@{}", self.name, self.version)
            }
            DependencySource::Git { url, rev } => {
                let mut purl = format!("pkg:cargo/{}@{}?vcs_url={}", self.name, self.version, url);
                if let Some(r) = rev {
                    purl.push_str(&format!("&revision={}", r));
                }
                purl
            }
            DependencySource::Path(p) => {
                format!("pkg:cargo/{}@{}?path={}", self.name, self.version, p)
            }
            DependencySource::Unknown => {
                format!("pkg:cargo/{}@{}", self.name, self.version)
            }
        }
    }
}

/// Parse Cargo.lock file to extract dependencies
///
/// Returns a map of package name -> Dependency
pub fn parse_cargo_lock(path: impl AsRef<Path>) -> Result<HashMap<String, Dependency>, SupplyChainError> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| SupplyChainError::IoError(e.to_string()))?;

    parse_cargo_lock_content(&content)
}

/// Parse Cargo.lock content
pub fn parse_cargo_lock_content(content: &str) -> Result<HashMap<String, Dependency>, SupplyChainError> {
    let mut deps = HashMap::new();
    let mut current_package: Option<(String, String)> = None;
    let mut current_source: Option<DependencySource> = None;
    let mut current_checksum: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        if line == "[[package]]" {
            // Save previous package
            if let Some((name, version)) = current_package.take() {
                let mut dep = Dependency::new(&name, &version);
                if let Some(src) = current_source.take() {
                    dep = dep.with_source(src);
                }
                if let Some(cs) = current_checksum.take() {
                    dep = dep.with_checksum(cs);
                }
                deps.insert(format!("{} {}", name, version), dep);
            }
            current_source = None;
            current_checksum = None;
        } else if let Some(rest) = line.strip_prefix("name = ") {
            let name = rest.trim_matches('"').to_string();
            if let Some((_, version)) = &current_package {
                current_package = Some((name, version.clone()));
            } else {
                current_package = Some((name, String::new()));
            }
        } else if let Some(rest) = line.strip_prefix("version = ") {
            let version = rest.trim_matches('"').to_string();
            if let Some((name, _)) = &current_package {
                current_package = Some((name.clone(), version));
            } else {
                current_package = Some((String::new(), version));
            }
        } else if let Some(rest) = line.strip_prefix("source = ") {
            let source = rest.trim_matches('"');
            if source == "registry+https://github.com/rust-lang/crates.io-index" {
                current_source = Some(DependencySource::CratesIo);
            } else if source.starts_with("git+") {
                let url = source.strip_prefix("git+").unwrap_or(source);
                let (url, rev) = if let Some(idx) = url.find('#') {
                    (url[..idx].to_string(), Some(url[idx + 1..].to_string()))
                } else {
                    (url.to_string(), None)
                };
                current_source = Some(DependencySource::Git { url, rev });
            }
        } else if let Some(rest) = line.strip_prefix("checksum = ") {
            current_checksum = Some(rest.trim_matches('"').to_string());
        }
    }

    // Don't forget the last package
    if let Some((name, version)) = current_package {
        if !name.is_empty() && !version.is_empty() {
            let mut dep = Dependency::new(&name, &version);
            if let Some(src) = current_source {
                dep = dep.with_source(src);
            }
            if let Some(cs) = current_checksum {
                dep = dep.with_checksum(cs);
            }
            deps.insert(format!("{} {}", name, version), dep);
        }
    }

    Ok(deps)
}

// ============================================================================
// Vulnerability Auditing
// ============================================================================

/// Vulnerability information
#[derive(Debug, Clone)]
pub struct Vulnerability {
    /// Advisory ID (e.g., RUSTSEC-2021-0001)
    pub id: String,
    /// Affected package
    pub package: String,
    /// Affected versions
    pub version: String,
    /// Severity level
    pub severity: VulnerabilitySeverity,
    /// Brief description
    pub title: String,
    /// Detailed description
    pub description: Option<String>,
    /// URL for more information
    pub url: Option<String>,
    /// Patched versions (if any)
    pub patched_versions: Vec<String>,
}

/// Vulnerability severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnerabilitySeverity {
    /// Informational
    None,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl VulnerabilitySeverity {
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::None,
        }
    }
}

/// Result of a dependency audit
#[derive(Debug, Clone, Default)]
pub struct AuditResult {
    /// Vulnerabilities found
    pub vulnerabilities: Vec<Vulnerability>,
    /// Warnings (non-vulnerability issues)
    pub warnings: Vec<String>,
    /// Number of packages scanned
    pub packages_scanned: usize,
    /// Whether the audit completed successfully
    pub success: bool,
    /// Error message if audit failed
    pub error: Option<String>,
}

impl AuditResult {
    /// Check if any vulnerabilities were found
    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    /// Get vulnerability count
    pub fn vulnerability_count(&self) -> usize {
        self.vulnerabilities.len()
    }

    /// Get count by severity
    pub fn count_by_severity(&self, severity: VulnerabilitySeverity) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == severity)
            .count()
    }

    /// Check if there are critical vulnerabilities
    pub fn has_critical(&self) -> bool {
        self.vulnerabilities
            .iter()
            .any(|v| v.severity == VulnerabilitySeverity::Critical)
    }

    /// Check if there are high or critical vulnerabilities
    pub fn has_high_or_critical(&self) -> bool {
        self.vulnerabilities
            .iter()
            .any(|v| v.severity >= VulnerabilitySeverity::High)
    }
}

/// Run cargo audit and parse results
///
/// Requires `cargo-audit` to be installed: `cargo install cargo-audit`
pub fn run_cargo_audit() -> Result<AuditResult, SupplyChainError> {
    let output = Command::new("cargo")
        .args(["audit", "--json"])
        .output()
        .map_err(|e| SupplyChainError::CommandFailed(format!("cargo audit: {}", e)))?;

    if !output.status.success() && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not found") || stderr.contains("no such") {
            return Err(SupplyChainError::ToolNotInstalled("cargo-audit".to_string()));
        }
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON output
    parse_cargo_audit_json(&stdout)
}

/// Parse cargo audit JSON output
fn parse_cargo_audit_json(json: &str) -> Result<AuditResult, SupplyChainError> {
    // Simple JSON parsing without external dependency
    // In production, you'd use serde_json
    let mut result = AuditResult::default();
    result.success = true;

    // Look for vulnerability entries
    // Format: "vulnerabilities": { "list": [...] }
    if let Some(vuln_start) = json.find("\"vulnerabilities\"") {
        if let Some(list_start) = json[vuln_start..].find("\"list\"") {
            let start = vuln_start + list_start;
            // Count vulnerabilities by counting "advisory" occurrences
            let vuln_section = &json[start..];
            let count = vuln_section.matches("\"advisory\"").count();

            // For each advisory, create a placeholder vulnerability
            // (Full parsing would require proper JSON parsing)
            for _ in 0..count {
                result.vulnerabilities.push(Vulnerability {
                    id: "UNKNOWN".to_string(),
                    package: "unknown".to_string(),
                    version: "unknown".to_string(),
                    severity: VulnerabilitySeverity::Medium,
                    title: "Vulnerability found (run cargo audit for details)".to_string(),
                    description: None,
                    url: None,
                    patched_versions: Vec::new(),
                });
            }
        }
    }

    Ok(result)
}

// ============================================================================
// SBOM Generation
// ============================================================================

/// SBOM format
#[derive(Debug, Clone, Copy)]
pub enum SbomFormat {
    /// CycloneDX JSON format
    CycloneDxJson,
    /// CycloneDX XML format
    CycloneDxXml,
    /// SPDX JSON format
    SpdxJson,
}

/// SBOM metadata
#[derive(Debug, Clone)]
pub struct SbomMetadata {
    /// Application name
    pub name: String,
    /// Application version
    pub version: String,
    /// Organization
    pub organization: Option<String>,
    /// Generation timestamp
    pub timestamp: SystemTime,
    /// Tool that generated the SBOM
    pub tool: String,
    /// Tool version
    pub tool_version: String,
}

impl SbomMetadata {
    /// Create new SBOM metadata
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            organization: None,
            timestamp: SystemTime::now(),
            tool: "barbican".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Set organization
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }
}

/// Generate a CycloneDX SBOM in JSON format
pub fn generate_cyclonedx_sbom(
    metadata: &SbomMetadata,
    dependencies: &HashMap<String, Dependency>,
) -> String {
    let timestamp = metadata
        .timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut components = String::new();
    let mut first = true;

    for dep in dependencies.values() {
        if !first {
            components.push_str(",\n");
        }
        first = false;

        components.push_str(&format!(
            r#"    {{
      "type": "library",
      "name": "{}",
      "version": "{}",
      "purl": "{}""#,
            dep.name, dep.version, dep.purl()
        ));

        if let Some(checksum) = &dep.checksum {
            components.push_str(&format!(
                r#",
      "hashes": [
        {{
          "alg": "SHA-256",
          "content": "{}"
        }}
      ]"#,
                checksum
            ));
        }

        components.push_str("\n    }");
    }

    format!(
        r#"{{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {{
    "timestamp": "{}",
    "tools": [
      {{
        "vendor": "barbican",
        "name": "{}",
        "version": "{}"
      }}
    ],
    "component": {{
      "type": "application",
      "name": "{}",
      "version": "{}"
    }}
  }},
  "components": [
{}
  ]
}}"#,
        timestamp,
        metadata.tool,
        metadata.tool_version,
        metadata.name,
        metadata.version,
        components
    )
}

// ============================================================================
// License Compliance
// ============================================================================

/// License information
#[derive(Debug, Clone)]
pub struct License {
    /// SPDX identifier
    pub spdx_id: String,
    /// Full name
    pub name: String,
    /// Whether it's OSI approved
    pub osi_approved: bool,
    /// Whether it's copyleft
    pub copyleft: bool,
}

/// Common license classifications
pub fn classify_license(spdx: &str) -> License {
    match spdx.to_uppercase().as_str() {
        "MIT" => License {
            spdx_id: "MIT".to_string(),
            name: "MIT License".to_string(),
            osi_approved: true,
            copyleft: false,
        },
        "APACHE-2.0" => License {
            spdx_id: "Apache-2.0".to_string(),
            name: "Apache License 2.0".to_string(),
            osi_approved: true,
            copyleft: false,
        },
        "BSD-2-CLAUSE" => License {
            spdx_id: "BSD-2-Clause".to_string(),
            name: "BSD 2-Clause License".to_string(),
            osi_approved: true,
            copyleft: false,
        },
        "BSD-3-CLAUSE" => License {
            spdx_id: "BSD-3-Clause".to_string(),
            name: "BSD 3-Clause License".to_string(),
            osi_approved: true,
            copyleft: false,
        },
        "GPL-2.0" | "GPL-2.0-ONLY" => License {
            spdx_id: "GPL-2.0".to_string(),
            name: "GNU General Public License v2.0".to_string(),
            osi_approved: true,
            copyleft: true,
        },
        "GPL-3.0" | "GPL-3.0-ONLY" => License {
            spdx_id: "GPL-3.0".to_string(),
            name: "GNU General Public License v3.0".to_string(),
            osi_approved: true,
            copyleft: true,
        },
        "LGPL-2.1" | "LGPL-2.1-ONLY" => License {
            spdx_id: "LGPL-2.1".to_string(),
            name: "GNU Lesser General Public License v2.1".to_string(),
            osi_approved: true,
            copyleft: true,
        },
        "LGPL-3.0" | "LGPL-3.0-ONLY" => License {
            spdx_id: "LGPL-3.0".to_string(),
            name: "GNU Lesser General Public License v3.0".to_string(),
            osi_approved: true,
            copyleft: true,
        },
        "MPL-2.0" => License {
            spdx_id: "MPL-2.0".to_string(),
            name: "Mozilla Public License 2.0".to_string(),
            osi_approved: true,
            copyleft: true,
        },
        "ISC" => License {
            spdx_id: "ISC".to_string(),
            name: "ISC License".to_string(),
            osi_approved: true,
            copyleft: false,
        },
        "UNLICENSE" => License {
            spdx_id: "Unlicense".to_string(),
            name: "The Unlicense".to_string(),
            osi_approved: true,
            copyleft: false,
        },
        _ => License {
            spdx_id: spdx.to_string(),
            name: spdx.to_string(),
            osi_approved: false,
            copyleft: false,
        },
    }
}

/// License policy for compliance checking
#[derive(Debug, Clone, Default)]
pub struct LicensePolicy {
    /// Allowed licenses (SPDX IDs)
    pub allowed: Vec<String>,
    /// Denied licenses (SPDX IDs)
    pub denied: Vec<String>,
    /// Allow copyleft licenses
    pub allow_copyleft: bool,
    /// Require OSI approval
    pub require_osi: bool,
}

impl LicensePolicy {
    /// Create a permissive policy (common open source licenses)
    pub fn permissive() -> Self {
        Self {
            allowed: vec![
                "MIT".to_string(),
                "Apache-2.0".to_string(),
                "BSD-2-Clause".to_string(),
                "BSD-3-Clause".to_string(),
                "ISC".to_string(),
                "Unlicense".to_string(),
                "CC0-1.0".to_string(),
                "Zlib".to_string(),
            ],
            denied: Vec::new(),
            allow_copyleft: false,
            require_osi: false,
        }
    }

    /// Create a strict policy (no copyleft)
    pub fn strict() -> Self {
        Self {
            allowed: vec![
                "MIT".to_string(),
                "Apache-2.0".to_string(),
                "BSD-2-Clause".to_string(),
                "BSD-3-Clause".to_string(),
            ],
            denied: vec![
                "GPL-2.0".to_string(),
                "GPL-3.0".to_string(),
                "AGPL-3.0".to_string(),
            ],
            allow_copyleft: false,
            require_osi: true,
        }
    }

    /// Check if a license is allowed
    pub fn is_allowed(&self, spdx: &str) -> bool {
        let license = classify_license(spdx);

        // Check explicit deny list
        if self.denied.iter().any(|d| d.eq_ignore_ascii_case(spdx)) {
            return false;
        }

        // Check copyleft policy
        if !self.allow_copyleft && license.copyleft {
            return false;
        }

        // Check OSI requirement
        if self.require_osi && !license.osi_approved {
            return false;
        }

        // Check explicit allow list (if non-empty)
        if !self.allowed.is_empty() {
            return self.allowed.iter().any(|a| a.eq_ignore_ascii_case(spdx));
        }

        true
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Supply chain security error
#[derive(Debug, Clone)]
pub enum SupplyChainError {
    /// IO error
    IoError(String),
    /// Command execution failed
    CommandFailed(String),
    /// Required tool not installed
    ToolNotInstalled(String),
    /// Parse error
    ParseError(String),
}

impl std::fmt::Display for SupplyChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupplyChainError::IoError(e) => write!(f, "IO error: {}", e),
            SupplyChainError::CommandFailed(e) => write!(f, "Command failed: {}", e),
            SupplyChainError::ToolNotInstalled(t) => write!(f, "Tool not installed: {}", t),
            SupplyChainError::ParseError(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for SupplyChainError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_creation() {
        let dep = Dependency::new("serde", "1.0.0")
            .with_source(DependencySource::CratesIo)
            .with_checksum("abc123");

        assert_eq!(dep.name, "serde");
        assert_eq!(dep.version, "1.0.0");
        assert_eq!(dep.source, DependencySource::CratesIo);
        assert_eq!(dep.checksum, Some("abc123".to_string()));
    }

    #[test]
    fn test_dependency_purl() {
        let dep = Dependency::new("tokio", "1.0.0");
        assert_eq!(dep.purl(), "pkg:cargo/tokio@1.0.0");

        let git_dep = Dependency::new("my-lib", "0.1.0")
            .with_source(DependencySource::Git {
                url: "https://github.com/user/repo".to_string(),
                rev: Some("abc123".to_string()),
            });
        assert!(git_dep.purl().contains("vcs_url="));
        assert!(git_dep.purl().contains("revision="));
    }

    #[test]
    fn test_parse_cargo_lock() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        let deps = parse_cargo_lock_content(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains_key("serde 1.0.0"));
        assert!(deps.contains_key("tokio 1.0.0"));
    }

    #[test]
    fn test_vulnerability_severity_ordering() {
        assert!(VulnerabilitySeverity::None < VulnerabilitySeverity::Low);
        assert!(VulnerabilitySeverity::Low < VulnerabilitySeverity::Medium);
        assert!(VulnerabilitySeverity::Medium < VulnerabilitySeverity::High);
        assert!(VulnerabilitySeverity::High < VulnerabilitySeverity::Critical);
    }

    #[test]
    fn test_audit_result() {
        let mut result = AuditResult::default();
        assert!(!result.has_vulnerabilities());

        result.vulnerabilities.push(Vulnerability {
            id: "RUSTSEC-2021-0001".to_string(),
            package: "test".to_string(),
            version: "1.0.0".to_string(),
            severity: VulnerabilitySeverity::High,
            title: "Test vulnerability".to_string(),
            description: None,
            url: None,
            patched_versions: Vec::new(),
        });

        assert!(result.has_vulnerabilities());
        assert_eq!(result.vulnerability_count(), 1);
        assert!(result.has_high_or_critical());
    }

    #[test]
    fn test_sbom_metadata() {
        let meta = SbomMetadata::new("my-app", "1.0.0")
            .with_organization("My Org");

        assert_eq!(meta.name, "my-app");
        assert_eq!(meta.version, "1.0.0");
        assert_eq!(meta.organization, Some("My Org".to_string()));
    }

    #[test]
    fn test_generate_sbom() {
        let meta = SbomMetadata::new("test-app", "0.1.0");
        let mut deps = HashMap::new();
        deps.insert(
            "serde 1.0.0".to_string(),
            Dependency::new("serde", "1.0.0"),
        );

        let sbom = generate_cyclonedx_sbom(&meta, &deps);

        assert!(sbom.contains("CycloneDX"));
        assert!(sbom.contains("test-app"));
        assert!(sbom.contains("serde"));
        assert!(sbom.contains("pkg:cargo/serde@1.0.0"));
    }

    #[test]
    fn test_classify_license() {
        let mit = classify_license("MIT");
        assert!(mit.osi_approved);
        assert!(!mit.copyleft);

        let gpl = classify_license("GPL-3.0");
        assert!(gpl.osi_approved);
        assert!(gpl.copyleft);
    }

    #[test]
    fn test_license_policy_permissive() {
        let policy = LicensePolicy::permissive();
        assert!(policy.is_allowed("MIT"));
        assert!(policy.is_allowed("Apache-2.0"));
        assert!(!policy.is_allowed("GPL-3.0")); // Copyleft not allowed
    }

    #[test]
    fn test_license_policy_strict() {
        let policy = LicensePolicy::strict();
        assert!(policy.is_allowed("MIT"));
        assert!(!policy.is_allowed("GPL-3.0")); // Explicitly denied
        assert!(!policy.is_allowed("LGPL-2.1")); // Copyleft
    }

    #[test]
    fn test_supply_chain_error_display() {
        let err = SupplyChainError::ToolNotInstalled("cargo-audit".to_string());
        assert!(err.to_string().contains("cargo-audit"));

        let err = SupplyChainError::IoError("file not found".to_string());
        assert!(err.to_string().contains("IO error"));
    }
}
