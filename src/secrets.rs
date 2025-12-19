//! Secret Detection Scanner (IA-5(7))
//!
//! NIST SP 800-53 IA-5(7) (No Embedded Unencrypted Static Authenticators)
//! compliant secret detection utilities.
//!
//! # Control Requirement
//!
//! "Ensure that unencrypted static authenticators are not embedded in
//! applications or other forms of static storage."
//!
//! # Design Philosophy
//!
//! This module provides pattern-based detection of common secret types in
//! source code, configuration files, and other text content. It's designed
//! for CI/CD integration and pre-commit hooks.
//!
//! # What This Module Provides
//!
//! - Pattern definitions for common secret types (API keys, tokens, passwords)
//! - Content scanning with configurable sensitivity
//! - File and directory scanning
//! - Allowlist/ignore capabilities
//! - Structured findings for reporting
//!
//! # Usage
//!
//! ```ignore
//! use barbican::secrets::{SecretScanner, SecretPattern, Finding};
//!
//! let scanner = SecretScanner::default();
//!
//! // Scan a string
//! let findings = scanner.scan_content("api_key = 'AKIAIOSFODNN7EXAMPLE'", "config.py");
//! assert!(!findings.is_empty());
//!
//! // Scan a file
//! let findings = scanner.scan_file(Path::new("src/config.rs"))?;
//!
//! // Scan a directory
//! let findings = scanner.scan_directory(Path::new("src/"))?;
//! ```

use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ============================================================================
// Secret Patterns
// ============================================================================

/// Category of secret being detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretCategory {
    /// AWS access keys and secrets
    AwsCredentials,
    /// API keys (generic and provider-specific)
    ApiKey,
    /// Private keys (RSA, EC, etc.)
    PrivateKey,
    /// OAuth/JWT tokens
    Token,
    /// Database connection strings with credentials
    DatabaseCredential,
    /// Generic passwords or secrets
    Password,
    /// GitHub/GitLab tokens
    GitToken,
    /// Slack/Discord webhooks and tokens
    ChatToken,
    /// Cloud provider credentials (GCP, Azure)
    CloudCredential,
    /// Generic high-entropy strings that may be secrets
    HighEntropy,
}

impl SecretCategory {
    /// Human-readable name for this category
    pub fn name(&self) -> &'static str {
        match self {
            Self::AwsCredentials => "AWS Credentials",
            Self::ApiKey => "API Key",
            Self::PrivateKey => "Private Key",
            Self::Token => "OAuth/JWT Token",
            Self::DatabaseCredential => "Database Credential",
            Self::Password => "Password",
            Self::GitToken => "Git Token",
            Self::ChatToken => "Chat Token",
            Self::CloudCredential => "Cloud Credential",
            Self::HighEntropy => "High Entropy String",
        }
    }

    /// Severity level (1-5, higher is more severe)
    pub fn severity(&self) -> u8 {
        match self {
            Self::AwsCredentials => 5,
            Self::PrivateKey => 5,
            Self::DatabaseCredential => 5,
            Self::CloudCredential => 5,
            Self::GitToken => 4,
            Self::Token => 4,
            Self::ApiKey => 4,
            Self::ChatToken => 3,
            Self::Password => 3,
            Self::HighEntropy => 2,
        }
    }
}

/// A pattern for detecting a specific type of secret
#[derive(Debug, Clone)]
pub struct SecretPattern {
    /// Unique identifier for this pattern
    pub id: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Category of secret
    pub category: SecretCategory,
    /// Regex pattern to match
    pattern: Regex,
    /// Keywords that must be near the match (optional)
    pub keywords: Vec<&'static str>,
}

impl SecretPattern {
    /// Create a new secret pattern
    pub fn new(
        id: &'static str,
        description: &'static str,
        category: SecretCategory,
        pattern: &str,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            id,
            description,
            category,
            pattern: Regex::new(pattern)?,
            keywords: Vec::new(),
        })
    }

    /// Add keywords that should be near the match
    pub fn with_keywords(mut self, keywords: Vec<&'static str>) -> Self {
        self.keywords = keywords;
        self
    }

    /// Check if content matches this pattern
    pub fn find_matches(&self, content: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();

        for mat in self.pattern.find_iter(content) {
            // Calculate line number
            let line_num = content[..mat.start()].matches('\n').count() + 1;

            // Get the matched text (redacted for safety)
            let matched_text = mat.as_str();
            let redacted = redact_secret(matched_text);

            matches.push(SecretMatch {
                pattern_id: self.id,
                line: line_num,
                column: mat.start() - content[..mat.start()].rfind('\n').map(|i| i + 1).unwrap_or(0) + 1,
                matched_length: matched_text.len(),
                redacted_match: redacted,
            });
        }

        matches
    }
}

/// A match found by a secret pattern
#[derive(Debug, Clone)]
pub struct SecretMatch {
    /// ID of the pattern that matched
    pub pattern_id: &'static str,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
    /// Length of the matched text
    pub matched_length: usize,
    /// Redacted version of the matched text
    pub redacted_match: String,
}

// ============================================================================
// Built-in Patterns
// ============================================================================

/// Get all built-in secret detection patterns
pub fn builtin_patterns() -> Vec<SecretPattern> {
    let mut patterns = Vec::new();

    // AWS Access Key ID
    if let Ok(p) = SecretPattern::new(
        "aws-access-key-id",
        "AWS Access Key ID",
        SecretCategory::AwsCredentials,
        r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    ) {
        patterns.push(p);
    }

    // AWS Secret Access Key
    if let Ok(p) = SecretPattern::new(
        "aws-secret-key",
        "AWS Secret Access Key",
        SecretCategory::AwsCredentials,
        r#"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key['":\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
    ) {
        patterns.push(p.with_keywords(vec!["aws", "secret", "key"]));
    }

    // Generic API Key patterns
    if let Ok(p) = SecretPattern::new(
        "generic-api-key",
        "Generic API Key",
        SecretCategory::ApiKey,
        r#"(?i)(?:api[_\-\.]?key|apikey)['":\s]*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
    ) {
        patterns.push(p.with_keywords(vec!["api", "key"]));
    }

    // GitHub Personal Access Token
    if let Ok(p) = SecretPattern::new(
        "github-pat",
        "GitHub Personal Access Token",
        SecretCategory::GitToken,
        r"ghp_[A-Za-z0-9]{36}",
    ) {
        patterns.push(p);
    }

    // GitHub OAuth Access Token
    if let Ok(p) = SecretPattern::new(
        "github-oauth",
        "GitHub OAuth Access Token",
        SecretCategory::GitToken,
        r"gho_[A-Za-z0-9]{36}",
    ) {
        patterns.push(p);
    }

    // GitHub App Token
    if let Ok(p) = SecretPattern::new(
        "github-app",
        "GitHub App Token",
        SecretCategory::GitToken,
        r"(?:ghu|ghs)_[A-Za-z0-9]{36}",
    ) {
        patterns.push(p);
    }

    // GitLab Personal Access Token
    if let Ok(p) = SecretPattern::new(
        "gitlab-pat",
        "GitLab Personal Access Token",
        SecretCategory::GitToken,
        r"glpat-[A-Za-z0-9\-_]{20,}",
    ) {
        patterns.push(p);
    }

    // Slack Bot Token
    if let Ok(p) = SecretPattern::new(
        "slack-bot-token",
        "Slack Bot Token",
        SecretCategory::ChatToken,
        r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
    ) {
        patterns.push(p);
    }

    // Slack Webhook URL
    if let Ok(p) = SecretPattern::new(
        "slack-webhook",
        "Slack Webhook URL",
        SecretCategory::ChatToken,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
    ) {
        patterns.push(p);
    }

    // Discord Webhook URL
    if let Ok(p) = SecretPattern::new(
        "discord-webhook",
        "Discord Webhook URL",
        SecretCategory::ChatToken,
        r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    ) {
        patterns.push(p);
    }

    // Private Key (RSA, EC, etc.)
    if let Ok(p) = SecretPattern::new(
        "private-key",
        "Private Key",
        SecretCategory::PrivateKey,
        r"-----BEGIN\s+(?:RSA\s+)?(?:EC\s+)?(?:DSA\s+)?(?:OPENSSH\s+)?PRIVATE\s+KEY-----",
    ) {
        patterns.push(p);
    }

    // JWT Token
    if let Ok(p) = SecretPattern::new(
        "jwt-token",
        "JWT Token",
        SecretCategory::Token,
        r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    ) {
        patterns.push(p);
    }

    // Generic Bearer Token
    if let Ok(p) = SecretPattern::new(
        "bearer-token",
        "Bearer Token",
        SecretCategory::Token,
        r#"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"#,
    ) {
        patterns.push(p.with_keywords(vec!["bearer", "authorization"]));
    }

    // Database connection string with password
    if let Ok(p) = SecretPattern::new(
        "database-url",
        "Database Connection String with Password",
        SecretCategory::DatabaseCredential,
        r"(?i)(?:postgres|mysql|mongodb|redis)(?:ql)?://[^:]+:[^@]+@[^\s]+",
    ) {
        patterns.push(p);
    }

    // Generic password in config
    if let Ok(p) = SecretPattern::new(
        "password-assignment",
        "Password Assignment",
        SecretCategory::Password,
        r#"(?i)(?:password|passwd|pwd)['":\s]*[=:]\s*['"]([^'"]{8,})['"]"#,
    ) {
        patterns.push(p.with_keywords(vec!["password", "passwd", "pwd"]));
    }

    // Google Cloud API Key
    if let Ok(p) = SecretPattern::new(
        "gcp-api-key",
        "Google Cloud API Key",
        SecretCategory::CloudCredential,
        r"AIza[A-Za-z0-9_\-]{35}",
    ) {
        patterns.push(p);
    }

    // Google Cloud Service Account
    if let Ok(p) = SecretPattern::new(
        "gcp-service-account",
        "Google Cloud Service Account Key",
        SecretCategory::CloudCredential,
        r#""type"\s*:\s*"service_account""#,
    ) {
        patterns.push(p.with_keywords(vec!["private_key", "client_email"]));
    }

    // Azure Storage Account Key
    if let Ok(p) = SecretPattern::new(
        "azure-storage-key",
        "Azure Storage Account Key",
        SecretCategory::CloudCredential,
        r#"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86,88}"#,
    ) {
        patterns.push(p);
    }

    // Stripe API Key
    if let Ok(p) = SecretPattern::new(
        "stripe-api-key",
        "Stripe API Key",
        SecretCategory::ApiKey,
        r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}",
    ) {
        patterns.push(p);
    }

    // SendGrid API Key
    if let Ok(p) = SecretPattern::new(
        "sendgrid-api-key",
        "SendGrid API Key",
        SecretCategory::ApiKey,
        r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    ) {
        patterns.push(p);
    }

    // Twilio API Key
    if let Ok(p) = SecretPattern::new(
        "twilio-api-key",
        "Twilio API Key",
        SecretCategory::ApiKey,
        r"SK[A-Za-z0-9]{32}",
    ) {
        patterns.push(p.with_keywords(vec!["twilio"]));
    }

    // npm Token
    if let Ok(p) = SecretPattern::new(
        "npm-token",
        "npm Access Token",
        SecretCategory::ApiKey,
        r"npm_[A-Za-z0-9]{36}",
    ) {
        patterns.push(p);
    }

    // Heroku API Key
    if let Ok(p) = SecretPattern::new(
        "heroku-api-key",
        "Heroku API Key",
        SecretCategory::ApiKey,
        r#"(?i)heroku[_\-\.]?api[_\-\.]?key['"]?\s*[=:]\s*['"]?[A-Za-z0-9\-]{36}"#,
    ) {
        patterns.push(p);
    }

    patterns
}

// ============================================================================
// Scanner
// ============================================================================

/// Secret scanner configuration and state
#[derive(Debug)]
pub struct SecretScanner {
    /// Patterns to scan for
    patterns: Vec<SecretPattern>,
    /// File extensions to scan (empty = scan all)
    file_extensions: HashSet<String>,
    /// Paths to ignore
    ignore_paths: Vec<String>,
    /// Whether to scan for high-entropy strings
    detect_high_entropy: bool,
    /// Minimum entropy threshold for detection
    entropy_threshold: f64,
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self {
            patterns: builtin_patterns(),
            file_extensions: default_file_extensions(),
            ignore_paths: default_ignore_paths(),
            detect_high_entropy: false,
            entropy_threshold: 4.5,
        }
    }
}

impl SecretScanner {
    /// Create a new scanner with custom patterns
    pub fn new(patterns: Vec<SecretPattern>) -> Self {
        Self {
            patterns,
            ..Default::default()
        }
    }

    /// Create a scanner with all built-in patterns
    pub fn with_builtin_patterns() -> Self {
        Self::default()
    }

    /// Enable high-entropy string detection
    pub fn with_high_entropy_detection(mut self, threshold: f64) -> Self {
        self.detect_high_entropy = true;
        self.entropy_threshold = threshold;
        self
    }

    /// Set file extensions to scan
    pub fn with_extensions(mut self, extensions: HashSet<String>) -> Self {
        self.file_extensions = extensions;
        self
    }

    /// Add paths to ignore
    pub fn with_ignore_paths(mut self, paths: Vec<String>) -> Self {
        self.ignore_paths = paths;
        self
    }

    /// Get the number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get pattern IDs
    pub fn pattern_ids(&self) -> Vec<&str> {
        self.patterns.iter().map(|p| p.id).collect()
    }

    /// Scan content for secrets
    pub fn scan_content(&self, content: &str, source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            for mat in pattern.find_matches(content) {
                findings.push(Finding {
                    source: source.to_string(),
                    pattern_id: mat.pattern_id.to_string(),
                    category: pattern.category,
                    description: pattern.description.to_string(),
                    line: mat.line,
                    column: mat.column,
                    redacted_match: mat.redacted_match,
                    severity: pattern.category.severity(),
                });
            }
        }

        // Optional: detect high-entropy strings
        if self.detect_high_entropy {
            for (line_num, line) in content.lines().enumerate() {
                for word in extract_potential_secrets(line) {
                    if shannon_entropy(word) >= self.entropy_threshold && word.len() >= 16 {
                        findings.push(Finding {
                            source: source.to_string(),
                            pattern_id: "high-entropy".to_string(),
                            category: SecretCategory::HighEntropy,
                            description: "High entropy string detected".to_string(),
                            line: line_num + 1,
                            column: line.find(word).unwrap_or(0) + 1,
                            redacted_match: redact_secret(word),
                            severity: SecretCategory::HighEntropy.severity(),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Scan a file for secrets
    pub fn scan_file(&self, path: &Path) -> Result<Vec<Finding>, ScanError> {
        // Check if we should skip this file
        if self.should_skip_path(path) {
            return Ok(Vec::new());
        }

        // Check file extension
        if !self.file_extensions.is_empty() {
            if let Some(ext) = path.extension() {
                if !self.file_extensions.contains(ext.to_string_lossy().as_ref()) {
                    return Ok(Vec::new());
                }
            } else {
                return Ok(Vec::new());
            }
        }

        // Read file content
        let content = std::fs::read_to_string(path).map_err(|e| ScanError::IoError {
            path: path.to_path_buf(),
            error: e.to_string(),
        })?;

        Ok(self.scan_content(&content, &path.to_string_lossy()))
    }

    /// Scan a directory recursively for secrets
    pub fn scan_directory(&self, path: &Path) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        if !path.is_dir() {
            return Err(ScanError::NotADirectory(path.to_path_buf()));
        }

        self.scan_directory_recursive(path, &mut findings)?;
        Ok(findings)
    }

    fn scan_directory_recursive(
        &self,
        path: &Path,
        findings: &mut Vec<Finding>,
    ) -> Result<(), ScanError> {
        for entry in std::fs::read_dir(path).map_err(|e| ScanError::IoError {
            path: path.to_path_buf(),
            error: e.to_string(),
        })? {
            let entry = entry.map_err(|e| ScanError::IoError {
                path: path.to_path_buf(),
                error: e.to_string(),
            })?;
            let entry_path = entry.path();

            if self.should_skip_path(&entry_path) {
                continue;
            }

            if entry_path.is_dir() {
                self.scan_directory_recursive(&entry_path, findings)?;
            } else if entry_path.is_file() {
                match self.scan_file(&entry_path) {
                    Ok(file_findings) => findings.extend(file_findings),
                    Err(ScanError::IoError { .. }) => {
                        // Skip unreadable files silently
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(())
    }

    fn should_skip_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for ignore in &self.ignore_paths {
            if path_str.contains(ignore) {
                return true;
            }
        }

        false
    }
}

// ============================================================================
// Findings
// ============================================================================

/// A secret finding
#[derive(Debug, Clone)]
pub struct Finding {
    /// Source file or identifier
    pub source: String,
    /// ID of the pattern that matched
    pub pattern_id: String,
    /// Category of the secret
    pub category: SecretCategory,
    /// Description of what was found
    pub description: String,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
    /// Redacted version of the match
    pub redacted_match: String,
    /// Severity (1-5)
    pub severity: u8,
}

impl Finding {
    /// Format as a human-readable string
    pub fn to_string_pretty(&self) -> String {
        format!(
            "[{}] {}:{}: {} - {} (severity: {})",
            self.pattern_id,
            self.source,
            self.line,
            self.description,
            self.redacted_match,
            self.severity
        )
    }
}

/// Scan error
#[derive(Debug)]
pub enum ScanError {
    /// IO error reading file
    IoError { path: PathBuf, error: String },
    /// Path is not a directory
    NotADirectory(PathBuf),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError { path, error } => {
                write!(f, "Failed to read {}: {}", path.display(), error)
            }
            Self::NotADirectory(path) => write!(f, "Not a directory: {}", path.display()),
        }
    }
}

impl std::error::Error for ScanError {}

// ============================================================================
// Utility Functions
// ============================================================================

/// Redact a secret, showing only first and last few characters
fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "*".repeat(secret.len());
    }

    let show_chars = 3;
    let start = &secret[..show_chars];
    let end = &secret[secret.len() - show_chars..];
    let hidden_len = secret.len() - (show_chars * 2);

    format!("{}{}{}",start, "*".repeat(hidden_len.min(20)), end)
}

/// Calculate Shannon entropy of a string
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts = std::collections::HashMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    char_counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Extract potential secrets from a line (quoted strings, assignments)
fn extract_potential_secrets(line: &str) -> Vec<&str> {
    let mut secrets = Vec::new();

    // Extract quoted strings
    let mut in_quote = false;
    let mut quote_char = ' ';
    let mut start = 0;

    for (i, c) in line.char_indices() {
        if !in_quote && (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
            start = i + 1;
        } else if in_quote && c == quote_char {
            if i > start {
                secrets.push(&line[start..i]);
            }
            in_quote = false;
        }
    }

    secrets
}

/// Default file extensions to scan
fn default_file_extensions() -> HashSet<String> {
    [
        "rs", "py", "js", "ts", "jsx", "tsx", "java", "go", "rb", "php", "cs", "cpp", "c", "h",
        "hpp", "swift", "kt", "scala", "sh", "bash", "zsh", "yml", "yaml", "json", "toml", "ini",
        "cfg", "conf", "config", "env", "properties", "xml", "tf", "tfvars", "sql", "md", "txt",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Default paths to ignore
fn default_ignore_paths() -> Vec<String> {
    vec![
        ".git".to_string(),
        "node_modules".to_string(),
        "target".to_string(),
        "vendor".to_string(),
        ".venv".to_string(),
        "__pycache__".to_string(),
        "dist".to_string(),
        "build".to_string(),
        ".idea".to_string(),
        ".vscode".to_string(),
        "*.min.js".to_string(),
        "*.min.css".to_string(),
    ]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key_detection() {
        let scanner = SecretScanner::default();
        let content = r#"aws_access_key_id = "AKIAIOSFODNN7EXAMPLE""#;
        let findings = scanner.scan_content(content, "test.py");

        assert!(!findings.is_empty(), "Should detect AWS access key");
        assert_eq!(findings[0].category, SecretCategory::AwsCredentials);
    }

    #[test]
    fn test_github_token_detection() {
        let scanner = SecretScanner::default();
        let content = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let findings = scanner.scan_content(content, "test.sh");

        assert!(!findings.is_empty(), "Should detect GitHub PAT");
        assert_eq!(findings[0].category, SecretCategory::GitToken);
    }

    #[test]
    fn test_private_key_detection() {
        let scanner = SecretScanner::default();
        let content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
"#;
        let findings = scanner.scan_content(content, "test.pem");

        assert!(!findings.is_empty(), "Should detect private key");
        assert_eq!(findings[0].category, SecretCategory::PrivateKey);
    }

    #[test]
    fn test_jwt_detection() {
        let scanner = SecretScanner::default();
        let content = "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let findings = scanner.scan_content(content, "test.js");

        assert!(!findings.is_empty(), "Should detect JWT token");
        assert_eq!(findings[0].category, SecretCategory::Token);
    }

    #[test]
    fn test_database_url_detection() {
        let scanner = SecretScanner::default();
        let content = r#"DATABASE_URL="postgres://user:password123@localhost:5432/mydb""#;
        let findings = scanner.scan_content(content, "test.env");

        assert!(!findings.is_empty(), "Should detect database URL with password");
        assert_eq!(findings[0].category, SecretCategory::DatabaseCredential);
    }

    #[test]
    fn test_slack_webhook_detection() {
        let scanner = SecretScanner::default();
        let content = "webhook_url = https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
        let findings = scanner.scan_content(content, "test.py");

        assert!(!findings.is_empty(), "Should detect Slack webhook");
        assert_eq!(findings[0].category, SecretCategory::ChatToken);
    }

    #[test]
    fn test_stripe_key_detection() {
        let scanner = SecretScanner::default();
        let content = r#"STRIPE_KEY="sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#;
        let findings = scanner.scan_content(content, "test.env");

        assert!(!findings.is_empty(), "Should detect Stripe API key");
        assert_eq!(findings[0].category, SecretCategory::ApiKey);
    }

    #[test]
    fn test_redact_secret() {
        assert_eq!(redact_secret("short"), "*****");
        assert_eq!(redact_secret("AKIAIOSFODNN7EXAMPLE"), "AKI**************PLE");
    }

    #[test]
    fn test_shannon_entropy() {
        // Low entropy (repeated chars)
        let low = shannon_entropy("aaaaaaaaaa");
        assert!(low < 1.0, "Repeated chars should have low entropy");

        // High entropy (mixed chars)
        let high = shannon_entropy("aB3$xY9!mK");
        assert!(high > 3.0, "Mixed chars should have high entropy");
    }

    #[test]
    fn test_builtin_patterns_count() {
        let patterns = builtin_patterns();
        assert!(patterns.len() >= 15, "Should have at least 15 builtin patterns");
    }

    #[test]
    fn test_pattern_categories() {
        let patterns = builtin_patterns();
        let categories: HashSet<_> = patterns.iter().map(|p| p.category).collect();

        assert!(categories.contains(&SecretCategory::AwsCredentials));
        assert!(categories.contains(&SecretCategory::ApiKey));
        assert!(categories.contains(&SecretCategory::GitToken));
        assert!(categories.contains(&SecretCategory::PrivateKey));
    }

    #[test]
    fn test_no_false_positives_on_clean_code() {
        let scanner = SecretScanner::default();
        let content = r#"
fn main() {
    let x = 42;
    println!("Hello, world!");
}
"#;
        let findings = scanner.scan_content(content, "test.rs");
        assert!(findings.is_empty(), "Clean code should have no findings");
    }

    #[test]
    fn test_finding_line_numbers() {
        let scanner = SecretScanner::default();
        let content = "line1\nline2\nghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nline4";
        let findings = scanner.scan_content(content, "test.txt");

        assert!(!findings.is_empty());
        assert_eq!(findings[0].line, 3, "Finding should be on line 3");
    }

    #[test]
    fn test_scanner_pattern_count() {
        let scanner = SecretScanner::default();
        assert!(scanner.pattern_count() >= 15);
    }

    #[test]
    fn test_category_severity() {
        assert_eq!(SecretCategory::AwsCredentials.severity(), 5);
        assert_eq!(SecretCategory::PrivateKey.severity(), 5);
        assert_eq!(SecretCategory::HighEntropy.severity(), 2);
    }

    #[test]
    fn test_category_name() {
        assert_eq!(SecretCategory::AwsCredentials.name(), "AWS Credentials");
        assert_eq!(SecretCategory::ApiKey.name(), "API Key");
    }
}
