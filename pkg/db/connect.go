package db

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Default connection pool parameters used when corresponding DBConf fields are unset (== 0).
// A negative value (e.g. -1) explicitly disables the limit (passes 0 to database/sql).
const (
	DefaultMaxIdleConns    = 10
	DefaultMaxOpenConns    = 100
	DefaultConnMaxLifetime = time.Hour
	DefaultConnMaxIdleTime = 30 * time.Minute
)

// DBConf database configuration structure for configuring database connection parameters
type DBConf struct {
	Type            string        `yaml:"type" json:"type"`                             // Database type, supports mysql, postgres, sqlite, sqlserver, opengauss
	Dsn             string        `yaml:"dsn" json:"dsn"`                               // Database connection string (DSN)
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`         // Maximum idle connections (0 uses DefaultMaxIdleConns; < 0 disables idle connection caching)
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns"`         // Maximum open connections (0 uses DefaultMaxOpenConns; < 0 means unlimited)
	LogSQL          bool          `yaml:"log_sql" json:"log_sql"`                       // Whether to log SQL
	SlowThreshold   time.Duration `yaml:"slow_threshold" json:"slow_threshold"`         // Slow query threshold for logging (default 1s)
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`   // Maximum connection lifetime (0 uses DefaultConnMaxLifetime; < 0 means reuse indefinitely)
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" json:"conn_max_idle_time"` // Maximum connection idle time (0 uses DefaultConnMaxIdleTime; < 0 means no maximum idle time)         // Apply schema migrations at startup (development convenience; prefer -migrate in production)
}

// NewGormConfig creates a gorm configuration with standard log.Logger.
// Deprecated: Use NewGormConfigWithLogger or NewGormConfigWithSlog instead.
func NewGormConfig(dbLog *log.Logger) *gorm.Config {
	var gc gorm.Config
	gc.SkipDefaultTransaction = false
	gc.FullSaveAssociations = false
	gc.TranslateError = true
	if dbLog != nil {
		gc.Logger = logger.New(dbLog, logger.Config{
			SlowThreshold:             time.Second,
			Colorful:                  false,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			LogLevel:                  logger.Info,
		})
	}
	return &gc
}

// NewGormConfigWithSlog creates a gorm configuration backed by the custom slog adapter.
func NewGormConfigWithSlog(cfg SlogLoggerConfig) *gorm.Config {
	var gc gorm.Config
	gc.SkipDefaultTransaction = false
	gc.FullSaveAssociations = false
	gc.TranslateError = true
	gc.Logger = NewSlogLogger(cfg)
	return &gc
}

// NewGormConfigWithLogger creates a gorm configuration backed by SlogLogger using the provided slog.Logger.
// It sets up query logging based on DBConf settings (slow query threshold and log_sql).
func NewGormConfigWithLogger(baseLogger *slog.Logger, c *DBConf) *gorm.Config {
	slowThreshold := time.Second
	logSQL := false
	if c != nil {
		if c.SlowThreshold > 0 {
			slowThreshold = c.SlowThreshold
		}
		logSQL = c.LogSQL
	}

	logLevel := logger.Warn
	if logSQL {
		logLevel = logger.Info
	}

	return NewGormConfigWithSlog(SlogLoggerConfig{
		SlowThreshold:             slowThreshold,
		ParameterizedQueries:      true,
		IgnoreRecordNotFoundError: true,
		LogLevel:                  logLevel,
		BaseLogger:                baseLogger,
	})
}

// NewGormDB initializes a GORM database connection using context.Background().
// Kept for backward compatibility.
func NewGormDB(c *DBConf, gc *gorm.Config) (*gorm.DB, error) {
	return NewGormDBContext(context.Background(), c, gc)
}

// NewGormDBContext initializes a GORM database connection with context cancellation support.
// c: database configuration
// gc: GORM configuration
// Returns GORM database instance and possible error
func NewGormDBContext(ctx context.Context, c *DBConf, gc *gorm.Config) (*gorm.DB, error) {
	var (
		db      *gorm.DB // GORM database instance
		openErr error    // Database open error
	)

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if c == nil {
		return nil, errors.New("database configuration cannot be nil")
	}

	// A typed-nil *gorm.Config must not be forwarded to gorm.Open: it satisfies the
	// Option interface but is dereferenced by GORM, causing a nil-pointer panic.
	if gc == nil {
		gc = NewGormConfig(nil)
	}

	// Make a shallow copy of gc so we don't mutate caller's configuration
	cfg := *gc

	// Apply LogSQL setting to configure query logging.
	slowThreshold := c.SlowThreshold
	if slowThreshold <= 0 {
		slowThreshold = time.Second
	}

	if cfg.Logger == nil {
		slogLevel := logger.Warn
		if c.LogSQL {
			slogLevel = logger.Info
		}
		cfg.Logger = NewSlogLogger(SlogLoggerConfig{
			SlowThreshold:             slowThreshold,
			ParameterizedQueries:      true,
			IgnoreRecordNotFoundError: true,
			LogLevel:                  slogLevel,
		})
	} else if c.LogSQL {
		cfg.Logger = cfg.Logger.LogMode(logger.Info)
	} else if sl, ok := cfg.Logger.(*SlogLogger); ok && sl.Config.LogLevel == 0 {
		cfg.Logger = sl.LogMode(logger.Warn)
	}

	// Lookup driver factory from registry
	driverFn, ok := GetDriver(c.Type)
	if !ok {
		return nil, errors.WrapWithDetails(ErrUnsupportedDriver, "unsupported database driver type", "type", c.Type, "registered", RegisteredDrivers())
	}

	dialector := driverFn(c.Dsn)
	db, openErr = gorm.Open(dialector, &cfg)

	// If database connection open failed, return error
	if openErr != nil {
		return nil, errors.Wrap(MapError(openErr), "failed to open database connection")
	}

	if err := ctx.Err(); err != nil {
		if sqlDB, dbErr := db.DB(); dbErr == nil && sqlDB != nil {
			_ = sqlDB.Close()
		}
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, errors.Wrap(MapError(err), "failed to get database connection")
	}
	// Set connection pool parameters.
	// When values are 0 (unset), apply sensible defaults.
	// When values are negative (e.g. -1), pass 0 to database/sql to explicitly disable the limit/caching.
	maxIdleConns := c.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = DefaultMaxIdleConns
	} else if maxIdleConns < 0 {
		maxIdleConns = 0
	}
	maxOpenConns := c.MaxOpenConns
	if maxOpenConns == 0 {
		maxOpenConns = DefaultMaxOpenConns
	} else if maxOpenConns < 0 {
		maxOpenConns = 0
	}
	connMaxLifetime := c.ConnMaxLifetime
	if connMaxLifetime == 0 {
		connMaxLifetime = DefaultConnMaxLifetime
	} else if connMaxLifetime < 0 {
		connMaxLifetime = 0
	}
	connMaxIdleTime := c.ConnMaxIdleTime
	if connMaxIdleTime == 0 {
		connMaxIdleTime = DefaultConnMaxIdleTime
	} else if connMaxIdleTime < 0 {
		connMaxIdleTime = 0
	}

	sqlDB.SetMaxIdleConns(maxIdleConns)       // Maximum idle connections
	sqlDB.SetMaxOpenConns(maxOpenConns)       // Maximum open connections
	sqlDB.SetConnMaxLifetime(connMaxLifetime) // Maximum connection lifetime
	sqlDB.SetConnMaxIdleTime(connMaxIdleTime) // Maximum connection idle time

	// Perform health check ping with retries on startup to avoid lazy connection issues.
	if err := pingWithRetry(ctx, sqlDB, 3); err != nil {
		_ = sqlDB.Close()
		return nil, errors.Wrap(err, "database connection health check failed")
	}
	return db, nil
}

// pingWithRetry pings the database with retries to tolerate transient startup failures,
// respecting context cancellation both during ping operations and during retry sleep intervals.
func pingWithRetry(ctx context.Context, sqlDB *sql.DB, attempts int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = sqlDB.PingContext(pingCtx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return err
}

// CloseGormDB closes the GORM database connection
// db: GORM database instance
// Returns possible error from closing operation
func CloseGormDB(db *gorm.DB) error {
	// Check if database instance is valid
	if db == nil {
		return errors.New("database instance is nil")
	}

	// Get underlying database connection
	sqlDB, err := db.DB()
	if err != nil {
		return errors.Wrap(err, "failed to get database connection")
	}

	// Close database connection
	return errors.Wrap(sqlDB.Close(), "failed to close database connection")
}
