//! Parsing utilities for human-readable configuration values

use std::time::Duration;

/// Parse human-readable size string (e.g., "10MB", "1GB", "512KB")
///
/// Returns bytes as usize. Defaults to 1MB if parsing fails.
///
/// # Supported formats
/// - `"1GB"` - gigabytes
/// - `"10MB"` - megabytes
/// - `"512KB"` - kilobytes
/// - `"1024B"` or `"1024"` - bytes
pub fn parse_size(s: &str) -> usize {
    let s = s.trim().to_uppercase();
    let (num_str, multiplier) = if s.ends_with("GB") {
        (&s[..s.len()-2], 1024 * 1024 * 1024)
    } else if s.ends_with("MB") {
        (&s[..s.len()-2], 1024 * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len()-2], 1024)
    } else if s.ends_with("B") {
        (&s[..s.len()-1], 1)
    } else {
        (s.as_str(), 1)
    };

    num_str.trim().parse::<usize>()
        .map(|n| n * multiplier)
        .unwrap_or(1024 * 1024)
}

/// Parse duration string (e.g., "30s", "5m", "1h", "100ms")
///
/// Returns Duration. Defaults to 30 seconds if parsing fails.
///
/// # Supported formats
/// - `"1h"` - hours
/// - `"5m"` - minutes
/// - `"30s"` or `"30"` - seconds
/// - `"100ms"` - milliseconds
pub fn parse_duration(s: &str) -> Duration {
    let s = s.trim().to_lowercase();
    let (num_str, multiplier) = if s.ends_with("ms") {
        (&s[..s.len()-2], 1)
    } else if s.ends_with('s') {
        (&s[..s.len()-1], 1000)
    } else if s.ends_with('m') {
        (&s[..s.len()-1], 60 * 1000)
    } else if s.ends_with('h') {
        (&s[..s.len()-1], 60 * 60 * 1000)
    } else {
        (s.as_str(), 1000)
    };

    num_str.trim().parse::<u64>()
        .map(|n| Duration::from_millis(n * multiplier))
        .unwrap_or(Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1KB"), 1024);
        assert_eq!(parse_size("10MB"), 10 * 1024 * 1024);
        assert_eq!(parse_size("1GB"), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512B"), 512);
        assert_eq!(parse_size("100"), 100);
        assert_eq!(parse_size("  5MB  "), 5 * 1024 * 1024);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("100ms"), Duration::from_millis(100));
        assert_eq!(parse_duration("30s"), Duration::from_secs(30));
        assert_eq!(parse_duration("5m"), Duration::from_secs(300));
        assert_eq!(parse_duration("1h"), Duration::from_secs(3600));
        assert_eq!(parse_duration("60"), Duration::from_secs(60));
    }
}
