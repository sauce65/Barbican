//! Code generation modules
//!
//! Generates Nix and Rust configuration from barbican.toml

pub mod nix;
pub mod rust;

use crate::config::BarbicanConfig;
use crate::error::Result;
use std::path::Path;

/// Output from code generation
#[derive(Debug)]
pub struct GenerationResult {
    /// Files that were generated
    pub files: Vec<GeneratedFile>,

    /// Whether any files changed from previous generation
    pub changed: bool,
}

/// A generated file
#[derive(Debug)]
pub struct GeneratedFile {
    /// Relative path from output directory
    pub path: String,

    /// File content
    pub content: String,

    /// SHA-256 hash of content
    pub hash: String,
}

impl GeneratedFile {
    pub fn new(path: impl Into<String>, content: impl Into<String>) -> Self {
        let content = content.into();
        let hash = compute_hash(&content);
        Self {
            path: path.into(),
            content,
            hash,
        }
    }

    /// Write the file to disk
    pub fn write(&self, base_dir: &Path) -> Result<()> {
        let full_path = base_dir.join(&self.path);

        // Create parent directories
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&full_path, &self.content)?;
        Ok(())
    }

    /// Check if file on disk matches this generated content
    pub fn matches_disk(&self, base_dir: &Path) -> bool {
        let full_path = base_dir.join(&self.path);
        match std::fs::read_to_string(&full_path) {
            Ok(content) => compute_hash(&content) == self.hash,
            Err(_) => false,
        }
    }
}

/// Compute SHA-256 hash of content
fn compute_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate all outputs (Nix and Rust)
pub fn generate_all(config: &BarbicanConfig, output_dir: &Path) -> Result<GenerationResult> {
    let mut files = Vec::new();

    // Generate Nix configuration
    let nix_files = nix::generate(config)?;
    files.extend(nix_files);

    // Generate Rust configuration
    let rust_files = rust::generate(config)?;
    files.extend(rust_files);

    // Check for changes
    let changed = files.iter().any(|f| !f.matches_disk(output_dir));

    // Write all files
    for file in &files {
        file.write(output_dir)?;
    }

    Ok(GenerationResult { files, changed })
}

/// Check if generated files match disk (drift detection)
pub fn check_drift(config: &BarbicanConfig, output_dir: &Path) -> Result<Vec<String>> {
    let mut drifted = Vec::new();

    // Check Nix files
    let nix_files = nix::generate(config)?;
    for file in nix_files {
        if !file.matches_disk(output_dir) {
            drifted.push(file.path);
        }
    }

    // Check Rust files
    let rust_files = rust::generate(config)?;
    for file in rust_files {
        if !file.matches_disk(output_dir) {
            drifted.push(file.path);
        }
    }

    Ok(drifted)
}
