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
///
/// Settings are organized by which layer they configure:
/// - **PostgreSQL (libpq)**: Connection string parameters sent to the database server
/// - **SQLx Pool**: Connection pool management settings
/// - **Application**: Barbican-specific settings
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    // =========================================================================
    // PostgreSQL Connection Settings (libpq)
    // These parameters are sent to PostgreSQL via the connection string
    // =========================================================================

    /// Database connection URL
    /// **Layer**: PostgreSQL (libpq)
    ///
    /// Format: `postgres://user:password@host:port/database`
    pub database_url: String,

    /// Application name shown in pg_stat_activity and server logs
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: AU-2, AU-3 (Audit Events, Audit Content)
    ///
    /// Critical for audit trails - without this, database logs show generic
    /// client names, making it impossible to correlate queries to applications.
    /// Default: "barbican"
    pub application_name: String,

    /// TCP connection timeout in seconds
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-5 (Denial of Service Protection)
    ///
    /// Prevents connection attempts from hanging indefinitely on network
    /// partition. Different from `acquire_timeout` which is pool wait time.
    /// Default: 10 seconds
    pub connect_timeout: Duration,

    /// Maximum time a query can run before being killed
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-5 (DoS Protection), AC-3 (Access Enforcement)
    ///
    /// Prevents runaway queries from monopolizing database resources.
    /// Essential for multi-tenant systems. Set to 0 to disable.
    /// Default: 30 seconds
    pub statement_timeout: Duration,

    /// Maximum time to wait for locks before aborting
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-5 (DoS Protection)
    ///
    /// Prevents deadlock-related hangs. Set to 0 to disable.
    /// Default: 10 seconds
    pub lock_timeout: Duration,

    // =========================================================================
    // PostgreSQL SSL/TLS Settings (libpq)
    // =========================================================================

    /// SSL mode for connections
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-8 (Transmission Confidentiality)
    ///
    /// Default: Require (encrypted connections mandatory)
    pub ssl_mode: SslMode,

    /// Path to SSL root certificate (CA) for server verification
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-8 (Transmission Confidentiality)
    ///
    /// Required for VerifyCa and VerifyFull modes.
    pub ssl_root_cert: Option<String>,

    /// Path to client SSL certificate for mTLS
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-8 (Transmission Confidentiality), IA-2 (Identification)
    ///
    /// For mutual TLS - the server verifies the client's identity.
    /// Required for FedRAMP High when mTLS is mandated.
    pub ssl_cert: Option<String>,

    /// Path to client SSL private key for mTLS
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-8 (Transmission Confidentiality), IA-2 (Identification)
    ///
    /// Must be paired with `ssl_cert` for mTLS.
    pub ssl_key: Option<String>,

    /// Path to Certificate Revocation List (CRL) file
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-8 (Transmission Confidentiality)
    ///
    /// For checking if server certificates have been revoked.
    /// Required for proper PKI hygiene in high-security environments.
    pub ssl_crl: Option<String>,

    /// SCRAM channel binding mode
    /// **Layer**: PostgreSQL (libpq)
    /// **Controls**: SC-8 (MITM Prevention), IA-5 (Authenticator Management)
    ///
    /// Cryptographically binds SCRAM authentication to the TLS channel,
    /// preventing credential forwarding/relay attacks. PostgreSQL 11+.
    /// Default: Prefer
    pub channel_binding: ChannelBinding,

    // =========================================================================
    // SQLx Connection Pool Settings
    // These are managed by sqlx's PgPoolOptions, not sent to PostgreSQL
    // =========================================================================

    /// Maximum number of connections in the pool
    /// **Layer**: SQLx Pool
    /// **Controls**: SC-5 (DoS Protection)
    ///
    /// Conservative limit prevents resource exhaustion.
    /// Default: 10
    pub max_connections: u32,

    /// Minimum number of idle connections to maintain
    /// **Layer**: SQLx Pool
    /// **Controls**: SC-5 (Availability)
    ///
    /// Ensures quick response for first requests after idle period.
    /// Default: 1
    pub min_connections: u32,

    /// Maximum time to wait for a connection from the pool
    /// **Layer**: SQLx Pool
    /// **Controls**: SC-5 (DoS Protection)
    ///
    /// Prevents request pile-up when pool is exhausted.
    /// Default: 30 seconds
    pub acquire_timeout: Duration,

    /// Maximum lifetime of a connection before it's closed
    /// **Layer**: SQLx Pool
    /// **Controls**: SC-5 (DoS Protection)
    ///
    /// Prevents stale connections and ensures credential rotation takes effect.
    /// Default: 30 minutes
    pub max_lifetime: Duration,

    /// Maximum idle time before a connection is closed
    /// **Layer**: SQLx Pool
    /// **Controls**: SC-5 (Resource Management)
    ///
    /// Releases unused connections back to the database.
    /// Default: 10 minutes
    pub idle_timeout: Duration,

    // =========================================================================
    // Application Settings (Barbican-specific)
    // =========================================================================

    /// Enable statement-level logging for audit
    /// **Layer**: Application
    /// **Controls**: AU-2, AU-3 (Audit Events, Audit Content)
    ///
    /// Logs all SQL statements. Use with caution in production due to
    /// volume and potential for logging sensitive data.
    pub statement_logging: bool,

    /// Run migrations automatically on connect
    /// **Layer**: Application
    /// **Controls**: CM-3 (Configuration Change Control)
    ///
    /// Default: true
    pub auto_migrate: bool,

    /// Health check interval for connection pool monitoring
    /// **Layer**: Application
    /// **Controls**: SI-4 (System Monitoring)
    ///
    /// Default: 30 seconds
    pub health_check_interval: Duration,

    /// Derived flag: SSL requires valid certificate
    /// **Layer**: Application (derived from ssl_mode)
    ///
    /// True when ssl_mode is VerifyCa or VerifyFull.
    pub ssl_require_valid_cert: bool,
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

/// SCRAM channel binding mode for PostgreSQL connections
///
/// **Layer**: PostgreSQL (libpq)
/// **Controls**: SC-8 (MITM Prevention), IA-5 (Authenticator Management)
///
/// Channel binding cryptographically ties SCRAM authentication to the TLS
/// channel, preventing man-in-the-middle attacks where an attacker could
/// relay credentials to a different server. Requires PostgreSQL 11+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBinding {
    /// Never use channel binding (not recommended)
    Disable,
    /// Use channel binding if server supports it (default)
    Prefer,
    /// Require channel binding, fail if not supported
    Require,
}

impl Default for ChannelBinding {
    fn default() -> Self {
        // Default to Prefer - use if available but don't break older servers
        Self::Prefer
    }
}

impl ChannelBinding {
    /// Convert to PostgreSQL connection string parameter value
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            // PostgreSQL connection settings
            database_url: String::new(),
            application_name: "barbican".to_string(),
            connect_timeout: Duration::from_secs(10),
            statement_timeout: Duration::from_secs(30),
            lock_timeout: Duration::from_secs(10),

            // PostgreSQL SSL/TLS settings
            ssl_mode: SslMode::Require,
            ssl_root_cert: None,
            ssl_cert: None,
            ssl_key: None,
            ssl_crl: None,
            channel_binding: ChannelBinding::default(),

            // SQLx pool settings
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(30 * 60), // 30 minutes
            idle_timeout: Duration::from_secs(10 * 60), // 10 minutes

            // Application settings
            statement_logging: false,
            auto_migrate: true,
            health_check_interval: Duration::from_secs(30),
            ssl_require_valid_cert: false,
        }
    }
}

impl DatabaseConfig {
    /// Load configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// ## PostgreSQL Connection (libpq)
    /// - `DATABASE_URL`: PostgreSQL connection URL (required)
    /// - `DB_APPLICATION_NAME`: Application name for audit logs (default: "barbican")
    /// - `DB_CONNECT_TIMEOUT`: TCP connection timeout (default: "10s")
    /// - `DB_STATEMENT_TIMEOUT`: Max query execution time (default: "30s")
    /// - `DB_LOCK_TIMEOUT`: Max lock wait time (default: "10s")
    ///
    /// ## PostgreSQL SSL/TLS (libpq)
    /// - `DB_SSL_MODE`: disable|prefer|require|verify-ca|verify-full (default: require)
    /// - `DB_SSL_ROOT_CERT`: Path to CA certificate for server verification
    /// - `DB_SSL_CERT`: Path to client certificate for mTLS
    /// - `DB_SSL_KEY`: Path to client private key for mTLS
    /// - `DB_SSL_CRL`: Path to Certificate Revocation List
    /// - `DB_CHANNEL_BINDING`: disable|prefer|require (default: prefer)
    ///
    /// ## SQLx Pool
    /// - `DB_MAX_CONNECTIONS`: Max pool size (default: 10)
    /// - `DB_MIN_CONNECTIONS`: Min idle connections (default: 1)
    /// - `DB_ACQUIRE_TIMEOUT`: Connection acquire timeout (default: "30s")
    /// - `DB_MAX_LIFETIME`: Max connection lifetime (default: "30m")
    /// - `DB_IDLE_TIMEOUT`: Idle connection timeout (default: "10m")
    ///
    /// ## Application
    /// - `DB_STATEMENT_LOGGING`: Enable SQL logging (default: false)
    /// - `DB_AUTO_MIGRATE`: Run migrations on startup (default: true)
    ///
    /// # Panics
    ///
    /// Panics if DATABASE_URL is not set.
    pub fn from_env() -> Self {
        // PostgreSQL connection settings
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL environment variable must be set");

        let application_name = std::env::var("DB_APPLICATION_NAME")
            .unwrap_or_else(|_| "barbican".to_string());

        let connect_timeout = std::env::var("DB_CONNECT_TIMEOUT")
            .map(|s| parse_duration(&s))
            .unwrap_or(Duration::from_secs(10));

        let statement_timeout = std::env::var("DB_STATEMENT_TIMEOUT")
            .map(|s| parse_duration(&s))
            .unwrap_or(Duration::from_secs(30));

        let lock_timeout = std::env::var("DB_LOCK_TIMEOUT")
            .map(|s| parse_duration(&s))
            .unwrap_or(Duration::from_secs(10));

        // PostgreSQL SSL/TLS settings
        let ssl_mode = std::env::var("DB_SSL_MODE")
            .map(|s| match s.to_lowercase().as_str() {
                "disable" => SslMode::Disable,
                "prefer" => SslMode::Prefer,
                "require" => SslMode::Require,
                "verify-ca" | "verifyca" => SslMode::VerifyCa,
                "verify-full" | "verifyfull" => SslMode::VerifyFull,
                _ => SslMode::Require,
            })
            .unwrap_or(SslMode::Require);

        let ssl_root_cert = std::env::var("DB_SSL_ROOT_CERT").ok();
        let ssl_cert = std::env::var("DB_SSL_CERT").ok();
        let ssl_key = std::env::var("DB_SSL_KEY").ok();
        let ssl_crl = std::env::var("DB_SSL_CRL").ok();

        let channel_binding = std::env::var("DB_CHANNEL_BINDING")
            .map(|s| match s.to_lowercase().as_str() {
                "disable" => ChannelBinding::Disable,
                "require" => ChannelBinding::Require,
                _ => ChannelBinding::Prefer,
            })
            .unwrap_or(ChannelBinding::Prefer);

        // SQLx pool settings
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

        // Application settings
        let statement_logging = std::env::var("DB_STATEMENT_LOGGING")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let auto_migrate = std::env::var("DB_AUTO_MIGRATE")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        Self {
            // PostgreSQL connection
            database_url,
            application_name,
            connect_timeout,
            statement_timeout,
            lock_timeout,

            // PostgreSQL SSL/TLS
            ssl_mode,
            ssl_root_cert,
            ssl_cert,
            ssl_key,
            ssl_crl,
            channel_binding,

            // SQLx pool
            max_connections,
            min_connections,
            acquire_timeout,
            max_lifetime,
            idle_timeout,

            // Application
            statement_logging,
            auto_migrate,
            health_check_interval: Duration::from_secs(30),
            ssl_require_valid_cert: matches!(ssl_mode, SslMode::VerifyCa | SslMode::VerifyFull),
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

    /// Validate configuration against compliance requirements
    ///
    /// Checks that database configuration meets the requirements of the
    /// selected compliance profile.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TLS is required but SSL mode is Disable or Prefer
    /// - mTLS is required but SSL mode is not VerifyFull
    ///
    /// # Example
    ///
    /// ```ignore
    /// use barbican::{DatabaseConfig, compliance::ComplianceConfig};
    ///
    /// let db_config = DatabaseConfig::from_env();
    /// let compliance = barbican::compliance::config();
    /// db_config.validate_compliance(compliance)?;
    /// ```
    pub fn validate_compliance(
        &self,
        config: &crate::compliance::ComplianceConfig,
    ) -> Result<(), crate::compliance::ComplianceError> {
        use crate::compliance::ComplianceError;

        // SC-8: Transmission confidentiality - TLS required
        if config.require_tls && !self.requires_ssl() {
            return Err(ComplianceError::Sc8Violation(
                "TLS required but database SSL mode is Disable or Prefer".into(),
            ));
        }

        // SC-8(1): mTLS requirement - must have VerifyFull mode
        if config.require_mtls && !matches!(self.ssl_mode, SslMode::VerifyFull) {
            return Err(ComplianceError::Sc8Violation(
                "mTLS required but database SSL mode is not VerifyFull".into(),
            ));
        }

        // SC-8(1), IA-2: mTLS requirement - must have client certificate
        if config.require_mtls && (self.ssl_cert.is_none() || self.ssl_key.is_none()) {
            return Err(ComplianceError::Ia2Violation(
                "mTLS required but client certificate (ssl_cert) or key (ssl_key) not configured".into(),
            ));
        }

        // SC-28: Encryption at rest - we can't verify this from config,
        // but we log a warning in health checks
        if config.require_encryption_at_rest {
            tracing::debug!(
                "SC-28: Encryption at rest required - verify PostgreSQL TDE or disk encryption"
            );
        }

        // AU-2, AU-3: Warn if application name is default (less useful for audit)
        if self.application_name == "barbican" {
            tracing::debug!(
                "AU-2/AU-3: Consider setting a unique application name for better audit trails"
            );
        }

        Ok(())
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

    // =========================================================================
    // PostgreSQL Connection Settings (libpq)
    // =========================================================================

    /// Set application name for audit logs (AU-2, AU-3)
    ///
    /// This appears in pg_stat_activity and server logs.
    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.config.application_name = name.into();
        self
    }

    /// Set TCP connection timeout (SC-5)
    ///
    /// Prevents hanging on network partition.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set statement timeout (SC-5, AC-3)
    ///
    /// Kills queries exceeding this duration.
    pub fn statement_timeout(mut self, timeout: Duration) -> Self {
        self.config.statement_timeout = timeout;
        self
    }

    /// Set lock timeout (SC-5)
    ///
    /// Maximum time to wait for locks.
    pub fn lock_timeout(mut self, timeout: Duration) -> Self {
        self.config.lock_timeout = timeout;
        self
    }

    // =========================================================================
    // PostgreSQL SSL/TLS Settings (libpq)
    // =========================================================================

    /// Set SSL mode (SC-8)
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

    /// Set SSL root certificate for server verification (SC-8)
    pub fn ssl_root_cert(mut self, path: impl Into<String>) -> Self {
        self.config.ssl_root_cert = Some(path.into());
        self
    }

    /// Set client certificate for mTLS (SC-8, IA-2)
    pub fn ssl_cert(mut self, path: impl Into<String>) -> Self {
        self.config.ssl_cert = Some(path.into());
        self
    }

    /// Set client private key for mTLS (SC-8, IA-2)
    pub fn ssl_key(mut self, path: impl Into<String>) -> Self {
        self.config.ssl_key = Some(path.into());
        self
    }

    /// Set Certificate Revocation List path (SC-8)
    pub fn ssl_crl(mut self, path: impl Into<String>) -> Self {
        self.config.ssl_crl = Some(path.into());
        self
    }

    /// Configure mTLS with client certificate and key (SC-8, IA-2)
    ///
    /// Convenience method that sets ssl_mode to VerifyFull along with
    /// the required certificates.
    pub fn with_mtls(
        mut self,
        root_cert: impl Into<String>,
        client_cert: impl Into<String>,
        client_key: impl Into<String>,
    ) -> Self {
        self.config.ssl_mode = SslMode::VerifyFull;
        self.config.ssl_require_valid_cert = true;
        self.config.ssl_root_cert = Some(root_cert.into());
        self.config.ssl_cert = Some(client_cert.into());
        self.config.ssl_key = Some(client_key.into());
        self
    }

    /// Set SCRAM channel binding mode (SC-8, IA-5)
    pub fn channel_binding(mut self, mode: ChannelBinding) -> Self {
        self.config.channel_binding = mode;
        self
    }

    /// Require SCRAM channel binding (SC-8, IA-5)
    ///
    /// Prevents credential relay attacks. Requires PostgreSQL 11+.
    pub fn require_channel_binding(mut self) -> Self {
        self.config.channel_binding = ChannelBinding::Require;
        self
    }

    // =========================================================================
    // SQLx Pool Settings
    // =========================================================================

    /// Set maximum connections (default: 10) (SC-5)
    pub fn max_connections(mut self, n: u32) -> Self {
        self.config.max_connections = n;
        self
    }

    /// Set minimum idle connections (default: 1)
    pub fn min_connections(mut self, n: u32) -> Self {
        self.config.min_connections = n;
        self
    }

    /// Set connection acquire timeout (SC-5)
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.config.acquire_timeout = timeout;
        self
    }

    /// Set maximum connection lifetime (SC-5)
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.config.max_lifetime = lifetime;
        self
    }

    /// Set idle connection timeout (SC-5)
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    // =========================================================================
    // Application Settings
    // =========================================================================

    /// Enable statement logging for audit (AU-2, AU-3)
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
/// 2. Configures PostgreSQL connection parameters (application_name, timeouts)
/// 3. Configures SSL/TLS settings including mTLS if provided
/// 4. Sets up connection pooling with security defaults
/// 5. Performs a health check
///
/// # Security Controls
///
/// - **SC-8**: SSL/TLS encryption, mTLS client certificates, channel binding
/// - **SC-5**: Connection and query timeouts prevent resource exhaustion
/// - **AU-2/AU-3**: Application name enables audit correlation
/// - **IA-2**: Client certificate authentication for mTLS
pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool, DatabaseError> {
    info!(
        application_name = %config.application_name,
        max_connections = config.max_connections,
        ssl_mode = ?config.ssl_mode,
        channel_binding = ?config.channel_binding,
        "Initializing database connection pool"
    );

    // Parse base connection options from URL
    let mut connect_options = PgConnectOptions::from_str(&config.database_url)
        .map_err(|e| DatabaseError::Configuration(format!("Invalid DATABASE_URL: {}", e)))?;

    // =========================================================================
    // PostgreSQL Connection Settings (libpq)
    // =========================================================================

    // AU-2, AU-3: Application name for audit trails
    connect_options = connect_options.application_name(&config.application_name);

    // SC-5: Build runtime options string for timeouts
    // These are set as PostgreSQL runtime parameters via the options connection parameter
    let mut pg_options = Vec::new();

    // Statement timeout (SC-5, AC-3)
    if !config.statement_timeout.is_zero() {
        pg_options.push(format!(
            "-c statement_timeout={}",
            config.statement_timeout.as_millis()
        ));
    }

    // Lock timeout (SC-5)
    if !config.lock_timeout.is_zero() {
        pg_options.push(format!(
            "-c lock_timeout={}",
            config.lock_timeout.as_millis()
        ));
    }

    // Apply runtime options if any were set
    if !pg_options.is_empty() {
        connect_options = connect_options.options(pg_options.iter().map(|s| s.as_str()));
    }

    // =========================================================================
    // PostgreSQL SSL/TLS Settings (libpq)
    // =========================================================================

    // SC-8: SSL mode
    connect_options = connect_options.ssl_mode(config.ssl_mode.into());

    // SC-8: SSL root certificate for server verification
    if let Some(ref root_cert) = config.ssl_root_cert {
        connect_options = connect_options.ssl_root_cert(root_cert);
        info!(ssl_root_cert = %root_cert, "Using SSL CA certificate for server verification");
    }

    // SC-8, IA-2: Client certificate for mTLS
    if let Some(ref client_cert) = config.ssl_cert {
        connect_options = connect_options.ssl_client_cert(client_cert);
        info!(ssl_cert = %client_cert, "Using client certificate for mTLS");
    }

    // SC-8, IA-2: Client private key for mTLS
    if let Some(ref client_key) = config.ssl_key {
        connect_options = connect_options.ssl_client_key(client_key);
        info!("Client private key configured for mTLS");
    }

    // Note: ssl_crl and channel_binding are not directly supported by sqlx's
    // PgConnectOptions API. They would need to be passed in the connection URL
    // or via libpq environment variables (PGSSLCRL, PGCHANNELBINDING).
    // Log warnings if these are configured so users know to set them externally.
    if config.ssl_crl.is_some() {
        warn!(
            ssl_crl = ?config.ssl_crl,
            "CRL path configured but must be set via PGSSLCRL environment variable"
        );
    }

    if config.channel_binding != ChannelBinding::Prefer {
        info!(
            channel_binding = ?config.channel_binding,
            "Channel binding configured - ensure PGCHANNELBINDING env var is set if not in URL"
        );
    }

    // Log mTLS status
    if config.ssl_cert.is_some() && config.ssl_key.is_some() {
        info!("mTLS enabled: client will present certificate to server");
    }

    // =========================================================================
    // SQLx Pool Settings
    // =========================================================================

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .max_lifetime(config.max_lifetime)
        .idle_timeout(config.idle_timeout)
        .test_before_acquire(true) // Always verify connections before handing out
        .connect_with(connect_options)
        .await
        .map_err(|e| DatabaseError::Connection(format!("Failed to connect: {}", e)))?;

    // Health check
    health_check(&pool).await?;

    info!(
        pool_size = pool.size(),
        "Database connection pool initialized successfully"
    );

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
