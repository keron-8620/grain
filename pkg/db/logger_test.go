package db

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type testTraceKey struct{}

type testContextHandler struct {
	slog.Handler
}

func (h *testContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if v, ok := ctx.Value(testTraceKey{}).(string); ok && v != "" {
		r.AddAttrs(slog.String("trace_id", v))
	}
	return h.Handler.Handle(ctx, r)
}

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return slog.New(&testContextHandler{Handler: h})
}

func TestSlogLogger_ContextLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	baseLogger := newTestLogger(buf)
	ctx := context.WithValue(context.Background(), testTraceKey{}, "trace-xyz-789")

	sl := NewSlogLogger(SlogLoggerConfig{
		LogLevel:   gormlogger.Info,
		BaseLogger: baseLogger,
	})

	sl.Trace(ctx, time.Now().Add(-10*time.Millisecond), func() (string, int64) {
		return "SELECT * FROM users", 1
	}, nil)

	output := buf.String()
	assert.Contains(t, output, "gorm query")
	assert.Contains(t, output, "SELECT * FROM users")
	assert.Contains(t, output, "trace_id=trace-xyz-789")
}

func TestSlogLogger_FallbackToBaseLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	baseLogger := newTestLogger(buf)

	// GetLogger returns nil -> should fallback to BaseLogger
	sl := NewSlogLogger(SlogLoggerConfig{
		LogLevel:   gormlogger.Info,
		BaseLogger: baseLogger,
	})

	sl.Trace(context.Background(), time.Now().Add(-10*time.Millisecond), func() (string, int64) {
		return "SELECT * FROM orders", 2
	}, nil)

	output := buf.String()
	assert.Contains(t, output, "gorm query")
	assert.Contains(t, output, "SELECT * FROM orders")
}

func TestSlogLogger_FallbackToDefault(t *testing.T) {
	// Neither GetLogger nor BaseLogger provided -> falls back to slog.Default() safely without panic
	sl := NewSlogLogger(SlogLoggerConfig{
		LogLevel: gormlogger.Silent,
	})

	assert.NotPanics(t, func() {
		sl.Info(context.Background(), "test message")
		sl.Warn(context.Background(), "test warning")
		sl.Error(context.Background(), "test error")
		sl.Trace(context.Background(), time.Now(), func() (string, int64) {
			return "SELECT 1", 1
		}, nil)
	})
}

func TestSlogLogger_SlowQuery(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newTestLogger(buf)

	sl := NewSlogLogger(SlogLoggerConfig{
		SlowThreshold: 50 * time.Millisecond,
		LogLevel:      gormlogger.Warn,
		BaseLogger:    logger,
	})

	// 1. Simulate slow query exceeding threshold
	sl.Trace(context.Background(), time.Now().Add(-100*time.Millisecond), func() (string, int64) {
		return "SELECT * FROM heavy_table", 100
	}, nil)

	output := buf.String()
	assert.Contains(t, output, "gorm slow query")
	assert.Contains(t, output, "threshold=50ms")
	assert.Contains(t, output, "heavy_table")

	// 2. Query within threshold should not log warning
	buf.Reset()
	sl.Trace(context.Background(), time.Now().Add(-10*time.Millisecond), func() (string, int64) {
		return "SELECT * FROM fast_table", 1
	}, nil)
	assert.Empty(t, buf.String())
}

func TestSlogLogger_QueryError(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newTestLogger(buf)

	sl := NewSlogLogger(SlogLoggerConfig{
		LogLevel:   gormlogger.Error,
		BaseLogger: logger,
	})

	queryErr := errors.New("syntax error at or near 'INVALID'")
	sl.Trace(context.Background(), time.Now(), func() (string, int64) {
		return "INVALID SQL", -1
	}, queryErr)

	output := buf.String()
	assert.Contains(t, output, "gorm query error")
	assert.Contains(t, output, "syntax error at or near 'INVALID'")
}

func TestSlogLogger_IgnoreRecordNotFoundError(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newTestLogger(buf)

	// Case 1: IgnoreRecordNotFoundError is true
	sl := NewSlogLogger(SlogLoggerConfig{
		LogLevel:                  gormlogger.Error,
		IgnoreRecordNotFoundError: true,
		BaseLogger:                logger,
	})

	sl.Trace(context.Background(), time.Now(), func() (string, int64) {
		return "SELECT * FROM users WHERE id = 1", 0
	}, gorm.ErrRecordNotFound)

	assert.Empty(t, buf.String())

	// Case 2: IgnoreRecordNotFoundError is false
	slNotIgnored := NewSlogLogger(SlogLoggerConfig{
		LogLevel:                  gormlogger.Error,
		IgnoreRecordNotFoundError: false,
		BaseLogger:                logger,
	})

	slNotIgnored.Trace(context.Background(), time.Now(), func() (string, int64) {
		return "SELECT * FROM users WHERE id = 1", 0
	}, gorm.ErrRecordNotFound)

	assert.Contains(t, buf.String(), "gorm query error")
	assert.Contains(t, buf.String(), "record not found")
}

func TestSlogLogger_ParamsFilter(t *testing.T) {
	slDisabled := NewSlogLogger(SlogLoggerConfig{
		ParameterizedQueries: false,
	})
	sql, params := slDisabled.ParamsFilter(context.Background(), "SELECT * FROM users WHERE id = ?", 123)
	assert.Equal(t, "SELECT * FROM users WHERE id = ?", sql)
	assert.Equal(t, []any{123}, params)

	slEnabled := NewSlogLogger(SlogLoggerConfig{
		ParameterizedQueries: true,
	})
	sql2, params2 := slEnabled.ParamsFilter(context.Background(), "SELECT * FROM users WHERE id = ?", 123)
	assert.Equal(t, "SELECT * FROM users WHERE id = ?", sql2)
	assert.Nil(t, params2)
}

func TestSlogLogger_LogLevels(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newTestLogger(buf)

	sl := NewSlogLogger(SlogLoggerConfig{
		LogLevel:   gormlogger.Silent,
		BaseLogger: logger,
	})

	ctx := context.Background()
	sl.Info(ctx, "info test")
	sl.Warn(ctx, "warn test")
	sl.Error(ctx, "error test")
	sl.Trace(ctx, time.Now(), func() (string, int64) { return "SELECT 1", 1 }, nil)
	assert.Empty(t, buf.String())

	// Change LogMode to Info
	slInfo := sl.LogMode(gormlogger.Info)
	slInfo.Info(ctx, "formatted message %s", "arg")
	slInfo.Warn(ctx, "warning %d", 42)
	slInfo.Error(ctx, "error message")

	out := buf.String()
	assert.Contains(t, out, "formatted message arg")
	assert.Contains(t, out, "warning 42")
	assert.Contains(t, out, "error message")
}

func TestNewGormConfigWithSlog(t *testing.T) {
	cfg := NewGormConfigWithSlog(SlogLoggerConfig{
		SlowThreshold: 2 * time.Second,
		LogLevel:      gormlogger.Info,
	})
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Logger)

	slogAdapter, ok := cfg.Logger.(*SlogLogger)
	require.True(t, ok)
	assert.Equal(t, 2*time.Second, slogAdapter.Config.SlowThreshold)
	assert.Equal(t, gormlogger.Info, slogAdapter.Config.LogLevel)
	assert.True(t, cfg.TranslateError)
}

func TestSlogLogger_WithGormExecution(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newTestLogger(buf)

	gc := NewGormConfigWithSlog(SlogLoggerConfig{
		LogLevel:   gormlogger.Info,
		BaseLogger: logger,
	})

	conf := &DBConf{
		Type:         "sqlite",
		Dsn:          ":memory:",
		LogSQL:       true,
		MaxIdleConns: 5,
		MaxOpenConns: 10,
	}

	db, err := NewGormDB(conf, gc)
	require.NoError(t, err)
	defer func() {
		_ = CloseGormDB(db)
	}()

	type DemoUser struct {
		ID   uint `gorm:"primaryKey"`
		Name string
	}

	require.NoError(t, db.AutoMigrate(&DemoUser{}))
	require.NoError(t, db.Create(&DemoUser{Name: "Alice"}).Error)

	var u DemoUser
	require.NoError(t, db.First(&u, "name = ?", "Alice").Error)
	assert.Equal(t, "Alice", u.Name)

	output := buf.String()
	assert.True(t, strings.Contains(output, "CREATE TABLE") || strings.Contains(output, "INSERT INTO") || strings.Contains(output, "SELECT * FROM"))
}

func TestSlogLogger_HandlerLevelDisabled(t *testing.T) {
	buf := &bytes.Buffer{}
	// Handler is configured at LevelError (Warn and Info disabled)
	errOnlyLogger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	sl := NewSlogLogger(SlogLoggerConfig{
		SlowThreshold: 10 * time.Millisecond,
		LogLevel:      gormlogger.Info, // GORM level is Info
		BaseLogger:    errOnlyLogger,
	})

	ctx := context.Background()

	// 1. Slow query (Warn) should be suppressed by handler's LevelError
	fcCalled := false
	sl.Trace(ctx, time.Now().Add(-50*time.Millisecond), func() (string, int64) {
		fcCalled = true
		return "SELECT * FROM slow_suppressed", 1
	}, nil)
	assert.False(t, fcCalled, "fc should not be invoked when handler has Warn disabled")
	assert.Empty(t, buf.String())

	// 2. Info query should be suppressed by handler's LevelError
	fcCalled = false
	sl.Trace(ctx, time.Now().Add(-2*time.Millisecond), func() (string, int64) {
		fcCalled = true
		return "SELECT * FROM info_suppressed", 1
	}, nil)
	assert.False(t, fcCalled, "fc should not be invoked when handler has Info disabled")
	assert.Empty(t, buf.String())

	// 3. Error query should pass through
	sl.Trace(ctx, time.Now(), func() (string, int64) {
		return "SELECT * FROM err_allowed", -1
	}, errors.New("db error"))
	assert.Contains(t, buf.String(), "gorm query error")
	assert.Contains(t, buf.String(), "err_allowed")
}

func TestSlogLogger_CallerPointsToCaller(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newTestLogger(buf)

	sl := NewSlogLogger(SlogLoggerConfig{
		LogLevel:   gormlogger.Info,
		BaseLogger: logger,
	})

	sl.Trace(context.Background(), time.Now(), func() (string, int64) {
		return "SELECT 1", 1
	}, nil)

	output := buf.String()
	assert.Contains(t, output, "logger_test.go")
	assert.NotContains(t, output, "logger.go:165")
}
