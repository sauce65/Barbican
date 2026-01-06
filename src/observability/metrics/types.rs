//! Core metric types: Counter, Histogram, Gauge
//!
//! Thread-safe metric primitives with label support for Prometheus-compatible metrics.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Thread-safe labeled counter using interior mutability.
///
/// Counters are monotonically increasing values (e.g., total requests, errors).
#[derive(Debug, Default)]
pub struct LabeledCounter {
    values: RwLock<HashMap<String, AtomicU64>>,
}

impl LabeledCounter {
    /// Create a new labeled counter.
    pub fn new() -> Self {
        Self {
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Increment counter by 1 for the given label combination.
    ///
    /// Labels should be formatted as `key1="value1",key2="value2"`.
    pub fn inc(&self, labels: &str) {
        self.add(labels, 1);
    }

    /// Add value to counter for the given label combination.
    pub fn add(&self, labels: &str, value: u64) {
        // Fast path: try to read existing counter
        {
            let values = self.values.read();
            if let Some(counter) = values.get(labels) {
                counter.fetch_add(value, Ordering::Relaxed);
                return;
            }
        }

        // Slow path: create new counter
        let mut values = self.values.write();
        values
            .entry(labels.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(value, Ordering::Relaxed);
    }

    /// Get current value for the given label combination.
    pub fn get(&self, labels: &str) -> u64 {
        let values = self.values.read();
        values
            .get(labels)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get all label/value pairs.
    pub fn get_all(&self) -> Vec<(String, u64)> {
        let values = self.values.read();
        values
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect()
    }

    /// Reset all counters to zero (primarily for testing).
    pub fn reset(&self) {
        let values = self.values.read();
        for counter in values.values() {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

/// Thread-safe gauge (can increase or decrease).
///
/// Gauges represent current values (e.g., active connections, queue depth).
#[derive(Debug, Default)]
pub struct Gauge {
    values: RwLock<HashMap<String, AtomicI64>>,
}

impl Gauge {
    /// Create a new gauge.
    pub fn new() -> Self {
        Self {
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Set gauge to a specific value.
    pub fn set(&self, labels: &str, value: i64) {
        // Fast path: try to read existing gauge
        {
            let values = self.values.read();
            if let Some(gauge) = values.get(labels) {
                gauge.store(value, Ordering::Relaxed);
                return;
            }
        }

        // Slow path: create new gauge
        let mut values = self.values.write();
        values
            .entry(labels.to_string())
            .or_insert_with(|| AtomicI64::new(0))
            .store(value, Ordering::Relaxed);
    }

    /// Increment gauge by 1.
    pub fn inc(&self, labels: &str) {
        self.add(labels, 1);
    }

    /// Decrement gauge by 1.
    pub fn dec(&self, labels: &str) {
        self.add(labels, -1);
    }

    /// Add value to gauge (can be negative).
    pub fn add(&self, labels: &str, value: i64) {
        // Fast path: try to read existing gauge
        {
            let values = self.values.read();
            if let Some(gauge) = values.get(labels) {
                gauge.fetch_add(value, Ordering::Relaxed);
                return;
            }
        }

        // Slow path: create new gauge
        let mut values = self.values.write();
        values
            .entry(labels.to_string())
            .or_insert_with(|| AtomicI64::new(0))
            .fetch_add(value, Ordering::Relaxed);
    }

    /// Get current value for the given label combination.
    pub fn get(&self, labels: &str) -> i64 {
        let values = self.values.read();
        values
            .get(labels)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get all label/value pairs.
    pub fn get_all(&self) -> Vec<(String, i64)> {
        let values = self.values.read();
        values
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect()
    }
}

/// Thread-safe histogram with configurable buckets.
///
/// Histograms track the distribution of values (e.g., request durations).
#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<f64>,
    counts: RwLock<HashMap<String, Vec<AtomicU64>>>,
    sums: RwLock<HashMap<String, f64>>,
    totals: RwLock<HashMap<String, u64>>,
}

impl Histogram {
    /// Create a new histogram with the given bucket boundaries.
    ///
    /// Bucket boundaries should be sorted in ascending order.
    pub fn new(buckets: &[f64]) -> Self {
        Self {
            buckets: buckets.to_vec(),
            counts: RwLock::new(HashMap::new()),
            sums: RwLock::new(HashMap::new()),
            totals: RwLock::new(HashMap::new()),
        }
    }

    /// Get the bucket boundaries.
    pub fn buckets(&self) -> &[f64] {
        &self.buckets
    }

    /// Observe a value for the given label combination.
    pub fn observe(&self, labels: &str, value: f64) {
        // Initialize bucket counts if needed
        {
            let counts = self.counts.read();
            if !counts.contains_key(labels) {
                drop(counts);
                let mut counts = self.counts.write();
                if !counts.contains_key(labels) {
                    let bucket_counts: Vec<AtomicU64> =
                        (0..self.buckets.len()).map(|_| AtomicU64::new(0)).collect();
                    counts.insert(labels.to_string(), bucket_counts);
                }
            }
        }

        // Update bucket counts (cumulative)
        let counts = self.counts.read();
        if let Some(bucket_counts) = counts.get(labels) {
            for (i, &bound) in self.buckets.iter().enumerate() {
                if value <= bound {
                    bucket_counts[i].fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Update sum and total
        {
            let mut sums = self.sums.write();
            *sums.entry(labels.to_string()).or_insert(0.0) += value;
        }
        {
            let mut totals = self.totals.write();
            *totals.entry(labels.to_string()).or_insert(0) += 1;
        }
    }

    /// Get histogram data for export.
    pub fn get_all(&self) -> Vec<HistogramData> {
        let counts = self.counts.read();
        let sums = self.sums.read();
        let totals = self.totals.read();

        counts
            .iter()
            .map(|(labels, bucket_counts)| {
                let bucket_values: Vec<u64> = bucket_counts
                    .iter()
                    .map(|c| c.load(Ordering::Relaxed))
                    .collect();
                HistogramData {
                    labels: labels.clone(),
                    buckets: self.buckets.clone(),
                    counts: bucket_values,
                    sum: *sums.get(labels).unwrap_or(&0.0),
                    count: *totals.get(labels).unwrap_or(&0),
                }
            })
            .collect()
    }
}

/// Histogram data for a single label combination.
#[derive(Debug, Clone)]
pub struct HistogramData {
    /// Label string (e.g., `method="GET",path="/api"`)
    pub labels: String,
    /// Bucket boundaries
    pub buckets: Vec<f64>,
    /// Cumulative counts for each bucket
    pub counts: Vec<u64>,
    /// Sum of all observed values
    pub sum: f64,
    /// Total number of observations
    pub count: u64,
}

/// Common histogram buckets for HTTP request durations (in seconds).
pub const HTTP_DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Common histogram buckets for job/task durations (in seconds).
pub const JOB_DURATION_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0,
];

/// Common histogram buckets for database query durations (in seconds).
pub const DB_DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_basic() {
        let counter = LabeledCounter::new();
        counter.inc("method=\"GET\"");
        counter.inc("method=\"GET\"");
        counter.inc("method=\"POST\"");

        assert_eq!(counter.get("method=\"GET\""), 2);
        assert_eq!(counter.get("method=\"POST\""), 1);
        assert_eq!(counter.get("method=\"PUT\""), 0);
    }

    #[test]
    fn test_counter_add() {
        let counter = LabeledCounter::new();
        counter.add("status=\"200\"", 10);
        counter.add("status=\"200\"", 5);

        assert_eq!(counter.get("status=\"200\""), 15);
    }

    #[test]
    fn test_gauge_basic() {
        let gauge = Gauge::new();
        gauge.set("", 10);
        assert_eq!(gauge.get(""), 10);

        gauge.inc("");
        assert_eq!(gauge.get(""), 11);

        gauge.dec("");
        assert_eq!(gauge.get(""), 10);
    }

    #[test]
    fn test_gauge_labels() {
        let gauge = Gauge::new();
        gauge.set("queue=\"jobs\"", 5);
        gauge.set("queue=\"events\"", 3);

        assert_eq!(gauge.get("queue=\"jobs\""), 5);
        assert_eq!(gauge.get("queue=\"events\""), 3);
    }

    #[test]
    fn test_histogram_basic() {
        let hist = Histogram::new(&[0.1, 0.5, 1.0]);
        hist.observe("", 0.05);
        hist.observe("", 0.3);
        hist.observe("", 0.8);

        let data = hist.get_all();
        assert_eq!(data.len(), 1);

        let d = &data[0];
        assert_eq!(d.count, 3);
        assert!((d.sum - 1.15).abs() < 0.001);
        // Cumulative: 0.05 <= 0.1, 0.3 <= 0.5, 0.8 <= 1.0
        assert_eq!(d.counts, vec![1, 2, 3]);
    }

    #[test]
    fn test_histogram_labels() {
        let hist = Histogram::new(&[1.0, 5.0]);
        hist.observe("method=\"GET\"", 0.5);
        hist.observe("method=\"POST\"", 2.0);

        let data = hist.get_all();
        assert_eq!(data.len(), 2);
    }
}
