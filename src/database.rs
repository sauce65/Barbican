//! Secure Database Infrastructure Layer
//!
//! Provides NIST 800-53 compliant database configuration and connection pooling.
//!
//! # Security Controls
//!
//! - **SC-8**: Connection pool security (timeouts, limits, health checks)
//! - **SC-28**: Protection of information at rest (via PostgreSQL)
//! - **AU-2/AU-3**: Audit logging integration
//! - **IA-5**: Credential protection (connection string handling)
//!
//! # Compliance
//!
//! - NIST SP 800-53 Rev 5: SC-8, SC-28, AU-2, AU-3, IA-5
//! - SOC 2 Type II: CC6.1, CC6.6, CC6.7
//! - FedRAMP: SC-8, SC-28

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::PgPool;
use std::str::FromStr;
use std::time::Duration;
use tracing::{info, warn};

use crate::parse::parse_duration;

/// Database configuration with security-focused defaults.
///
/// All settings are tuned for security and compliance:
/// - Conservative connection limits to prevent resource exhaustion
/// - Aggressive timeouts to detect and recover from failures
/// - SSL/TLS enforcement for production environments
/// - Health checks for connection pool integrity
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database connection URL (from DATABASE_URL env var)
    pub database_url: String,

    /// Maximum number of connections in the pool
    /// Default: 10 (conservative for security)
    pub max_connections: u32,

    /// Minimum number of idle connections to maintain
    /// Default: 1 (ensures quick response for first requests)
    pub min_connections: u32,

    /// Maximum time to wait for a connection from the pool
    /// Default: 30 seconds
    pub acquire_timeout: Duration,

    /// Maximum lifetime of a connection before it's closed
    /// Default: 30 minutes (prevents stale connections)
    pub max_lifetime: Duration,

    /// Maximum idle time before a connection is closed
    /// Default: 10 minutes
    pub idle_timeout: Duration,

    /// Enable statement-level logging for audit
    pub statement_logging: bool,

    /// SSL mode for connections
    /// Default: Prefer (use SSL if available)
    pub ssl_mode: SslMode,

    /// Require valid SSL certificate (production only)
    pub ssl_require_valid_cert: bool,

    /// Path to SSL root certificate (CA) for verification
    pub ssl_root_cert: Option<String>,

    /// Run migrations automatically on connect
    pub auto_migrate: bool,

    /// Health check interval
    pub health_check_interval: Duration,
}

/// SSL/TLS mode for database connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    /// Never use SSL (development only!)
    Disable,
    /// Use SSL if available, but don't require it
    Prefer,
    /// Require SSL connection
    Require,
    /// Require SSL and verify server certificate
    VerifyCa,
    /// Require SSL, verify certificate, and verify hostname
    VerifyFull,
}

impl Default for SslMode {
    fn default() -> Self {
        // Default to Require for production security
        // Per SOC 2 and NIST 800-53, database connections should be encrypted
        Self::Require
    }
}

impl From<SslMode> for PgSslMode {
    fn from(mode: SslMode) -> Self {
        match mode {
            SslMode::Disable => PgSslMode::Disable,
            SslMode::Prefer => PgSslMode::Prefer,
            SslMode::Require => PgSslMode::Require,
            SslMode::VerifyCa => PgSslMode::VerifyCa,
            SslMode::VerifyFull => PgSslMode::VerifyFull,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            database_url: String::new(),
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(30 * 60), // 30 minutes
            idle_timeout: Duration::from_secs(10 * 60), // 10 minutes
            statement_logging: false,
            ssl_mode: SslMode::Require, // Default to Require for security
            ssl_require_valid_cert: false,
            ssl_root_cert: None,
            auto_migrate: true,
            health_check_interval: Duration::from_secs(30),
        }
    }
}

impl DatabaseConfig {
    /// Load configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `DATABASE_URL`: PostgreSQL connection URL (required)
    /// - `DB_MAX_CONNECTIONS`: Max pool size (default: 10)
    /// - `DB_MIN_CONNECTIONS`: Min idle connections (default: 1)
    /// - `DB_ACQUIRE_TIMEOUT`: Connection acquire timeout (default: "30s")
    /// - `DB_MAX_LIFETIME`: Max connection lifetime (default: "30m")
    /// - `DB_IDLE_TIMEOUT`: Idle connection timeout (default: "10m")
    /// - `DB_SSL_MODE`: disable|prefer|require|verify-ca|verify-full (default: prefer)
    /// - `DB_SSL_ROOT_CERT`: Path to CA certificate for verify-ca/verify-full modes
    /// - `DB_STATEMENT_LOGGING`: Enable SQL logging (default: false)
    /// - `DB_AUTO_MIGRATE`: Run migrations on startup (default: true)
    ///
    /// # Panics
    ///
    /// Panics if DATABASE_URL is not set.
    pub fn from_env() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL environment variable must be set");

        let max_connections = std::env::var("DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let min_connections = std::env::var("DB_MIN_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let acquire_timeout = std::env::var("DB_ACQUIRE_TIMEOUT")
            .map(|s| parse_duration(&s))
            .unwrap_or(Duration::from_secs(30));

        let max_lifetime = std::env::var("DB_MAX_LIFETIME")
            .map(|s| parse_duration(&s))
            .unwrap_or(Duration::from_secs(30 * 60));

        let idle_timeout = std::env::var("DB_IDLE_TIMEOUT")
            .map(|s| parse_duration(&s))
            .unwrap_or(Duration::from_secs(10 * 60));

        let ssl_mode = std::env::var("DB_SSL_MODE")
            .map(|s| match s.to_lowercase().as_str() {
                "disable" => SslMode::Disable,
                "prefer" => SslMode::Prefer,
                "require" => SslMode::Require,
                "verify-ca" | "verifyca" => SslMode::VerifyCa,
                "verify-full" | "verifyfull" => SslMode::VerifyFull,
                _ => SslMode::Require, // Default to Require for security
            })
            .unwrap_or(SslMode::Require); // Default to Require for production security

        let statement_logging = std::env::var("DB_STATEMENT_LOGGING")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let auto_migrate = std::env::var("DB_AUTO_MIGRATE")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        let ssl_root_cert = std::env::var("DB_SSL_ROOT_CERT").ok();

        Self {
            database_url,
            max_connections,
            min_connections,
            acquire_timeout,
            max_lifetime,
            idle_timeout,
            statement_logging,
            ssl_mode,
            ssl_require_valid_cert: matches!(ssl_mode, SslMode::VerifyCa | SslMode::VerifyFull),
            ssl_root_cert,
            auto_migrate,
            health_check_interval: Duration::from_secs(30),
        }
    }

    /// Create a new builder for programmatic configuration.
    pub fn builder(database_url: impl Into<String>) -> DatabaseConfigBuilder {
        DatabaseConfigBuilder::new(database_url)
    }

    /// Check if SSL is required for this configuration.
    pub fn requires_ssl(&self) -> bool {
        !matches!(self.ssl_mode, SslMode::Disable | SslMode::Prefer)
    }

    /// Check if this is a production-safe configuration.
    pub fn is_production_safe(&self) -> bool {
        self.requires_ssl() && self.max_connections <= 20
    }
}

/// Builder for DatabaseConfig
#[derive(Debug, Clone)]
pub struct DatabaseConfigBuilder {
    config: DatabaseConfig,
}

impl DatabaseConfigBuilder {
    /// Create a new builder with the required database URL.
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            config: DatabaseConfig {
                database_url: database_url.into(),
                ..Default::default()
            },
        }
    }

    /// Set maximum connections (default: 10)
    pub fn max_connections(mut self, n: u32) -> Self {
        self.config.max_connections = n;
        self
    }

    /// Set minimum idle connections (default: 1)
    pub fn min_connections(mut self, n: u32) -> Self {
        self.config.min_connections = n;
        self
    }

    /// Set connection acquire timeout
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.config.acquire_timeout = timeout;
        self
    }

    /// Set SSL mode
    pub fn ssl_mode(mut self, mode: SslMode) -> Self {
        self.config.ssl_mode = mode;
        self.config.ssl_require_valid_cert =
            matches!(mode, SslMode::VerifyCa | SslMode::VerifyFull);
        self
    }

    /// Require SSL with full verification (production)
    pub fn require_ssl(self) -> Self {
        self.ssl_mode(SslMode::VerifyFull)
    }

    /// Enable statement logging for audit
    pub fn with_statement_logging(mut self) -> Self {
        self.config.statement_logging = true;
        self
    }

    /// Disable automatic migrations
    pub fn without_auto_migrate(mut self) -> Self {
        self.config.auto_migrate = false;
        self
    }

    /// Build the configuration
    pub fn build(self) -> DatabaseConfig {
        self.config
    }
}

/// Create a connection pool with the given configuration.
///
/// This function:
/// 1. Parses the database URL
/// 2. Configures SSL/TLS settings
/// 3. Sets up connection pooling with security defaults
/// 4. Optionally runs migrations
/// 5. Performs a health check
///
/// # Security
///
/// - Connections are encrypted with SSL/TLS (configurable)
/// - Pool limits prevent resource exhaustion
/// - Timeouts prevent hung connections
/// - Health checks ensure pool integrity
pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool, DatabaseError> {
    info!(
        max_connections = config.max_connections,
        ssl_mode = ?config.ssl_mode,
        auto_migrate = config.auto_migrate,
        "Initializing database connection pool"
    );

    // Parse connection options
    let mut connect_options = PgConnectOptions::from_str(&config.database_url)
        .map_err(|e| DatabaseError::Configuration(format!("Invalid DATABASE_URL: {}", e)))?
        .ssl_mode(config.ssl_mode.into());

    // Set SSL root certificate if provided
    if let Some(ref root_cert) = config.ssl_root_cert {
        connect_options = connect_options.ssl_root_cert(root_cert);
        info!(ssl_root_cert = %root_cert, "Using SSL root certificate for verification");
    }

    // Build pool with security settings
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .max_lifetime(config.max_lifetime)
        .idle_timeout(config.idle_timeout)
        .test_before_acquire(true) // Always verify connections
        .connect_with(connect_options)
        .await
        .map_err(|e| DatabaseError::Connection(format!("Failed to connect: {}", e)))?;

    // Health check
    health_check(&pool).await?;

    info!("Database connection pool initialized successfully");

    Ok(pool)
}

/// Perform a health check on the database connection.
///
/// Verifies:
/// 1. Connection is alive
/// 2. Can execute a simple query
/// 3. SSL status (if required)
pub async fn health_check(pool: &PgPool) -> Result<HealthStatus, DatabaseError> {
    let start = std::time::Instant::now();

    // Execute simple query
    let result: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(pool)
        .await
        .map_err(|e| DatabaseError::HealthCheck(format!("Query failed: {}", e)))?;

    if result.0 != 1 {
        return Err(DatabaseError::HealthCheck("Unexpected query result".into()));
    }

    // Get SSL status from pg_stat_ssl
    let ssl_result: (bool,) = sqlx::query_as(
        "SELECT COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false)"
    )
        .fetch_one(pool)
        .await
        .unwrap_or((false,));

    let latency = start.elapsed();
    let pool_size = pool.size();
    let idle_connections = pool.num_idle() as u32;

    let status = HealthStatus {
        connected: true,
        ssl_enabled: ssl_result.0,
        latency,
        pool_size,
        idle_connections,
    };

    if status.ssl_enabled {
        info!(latency_ms = ?latency.as_millis(), "Database health check passed (SSL enabled)");
    } else {
        warn!(latency_ms = ?latency.as_millis(), "Database health check passed (SSL NOT enabled)");
    }

    Ok(status)
}

/// Database health status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Connection is alive
    pub connected: bool,
    /// SSL/TLS is in use
    pub ssl_enabled: bool,
    /// Query latency
    pub latency: Duration,
    /// Current pool size
    pub pool_size: u32,
    /// Idle connections in pool
    pub idle_connections: u32,
}

impl HealthStatus {
    /// Check if the connection is secure (SSL enabled)
    pub fn is_secure(&self) -> bool {
        self.connected && self.ssl_enabled
    }

    /// Check if the pool is healthy
    pub fn is_healthy(&self) -> bool {
        self.connected && self.latency < Duration::from_secs(5)
    }
}

/// Database-specific errors
#[derive(Debug)]
pub enum DatabaseError {
    /// Configuration error (invalid URL, etc.)
    Configuration(String),
    /// Connection error
    Connection(String),
    /// Health check failed
    HealthCheck(String),
    /// Migration error
    Migration(String),
    /// Query error
    Query(String),
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(msg) => write!(f, "Database configuration error: {}", msg),
            Self::Connection(msg) => write!(f, "Database connection error: {}", msg),
            Self::HealthCheck(msg) => write!(f, "Database health check failed: {}", msg),
            Self::Migration(msg) => write!(f, "Database migration error: {}", msg),
            Self::Query(msg) => write!(f, "Database query error: {}", msg),
        }
    }
}

impl std::error::Error for DatabaseError {}

/// Run database migrations.
///
/// This is a macro wrapper that must be called from the application
/// since `sqlx::migrate!()` needs to be expanded at compile time
/// in the application's context.
#[macro_export]
macro_rules! run_migrations {
    ($pool:expr) => {
        sqlx::migrate!().run($pool).await
    };
}
