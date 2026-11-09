package db

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"emperror.dev/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestDBOpKind_Methods(t *testing.T) {
	assert.Equal(t, "read", OpRead.Label())
	assert.Equal(t, "write", OpWrite.Label())
	assert.Equal(t, "list", OpList.Label())
	assert.Equal(t, "read", DBOpKind(99).Label())

	timeouts := &DBTimeout{
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 20 * time.Millisecond,
		ListTimeout:  30 * time.Millisecond,
	}
	assert.Equal(t, 10*time.Millisecond, OpRead.Timeout(timeouts))
	assert.Equal(t, 20*time.Millisecond, OpWrite.Timeout(timeouts))
	assert.Equal(t, 30*time.Millisecond, OpList.Timeout(timeouts))
	assert.Equal(t, defaultDBOpTimeout, OpRead.Timeout(nil))
	assert.Equal(t, defaultDBOpTimeout, OpRead.Timeout(&DBTimeout{ReadTimeout: -1}))

	slow := &DBSlowThreshold{
		ReadSlow:  100 * time.Millisecond,
		WriteSlow: 200 * time.Millisecond,
		ListSlow:  300 * time.Millisecond,
	}
	assert.Equal(t, 100*time.Millisecond, OpRead.SlowThreshold(slow))
	assert.Equal(t, 200*time.Millisecond, OpWrite.SlowThreshold(slow))
	assert.Equal(t, 300*time.Millisecond, OpList.SlowThreshold(slow))
	assert.Equal(t, defaultSlowThreshold, OpRead.SlowThreshold(nil))
	assert.Equal(t, defaultSlowThreshold, OpRead.SlowThreshold(&DBSlowThreshold{ReadSlow: 0}))
}

func TestRunDBOp_Success(t *testing.T) {
	ctx := context.Background()
	executed := false

	err := RunDBOp(ctx, nil, nil, nil, OpRead, "get test", func(opCtx context.Context) error {
		executed = true
		assert.NotNil(t, opCtx)
		return nil
	}, slog.String("key", "val"))

	require.NoError(t, err)
	assert.True(t, executed)
}

func TestRunDBOp_Timeout(t *testing.T) {
	ctx := context.Background()
	timeouts := &DBTimeout{
		WriteTimeout: 20 * time.Millisecond,
	}

	err := RunDBOp(ctx, nil, timeouts, nil, OpWrite, "save record", func(opCtx context.Context) error {
		<-opCtx.Done()
		return opCtx.Err()
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "save record: database operation failed")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRunDBOp_SlowQueryWarning(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	slow := &DBSlowThreshold{
		ReadSlow: 10 * time.Millisecond,
	}

	err := RunDBOp(ctx, logger, nil, slow, OpRead, "slow find", func(opCtx context.Context) error {
		time.Sleep(25 * time.Millisecond)
		return nil
	}, slog.String("table", "users"))

	require.NoError(t, err)
	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "slow query threshold")
	assert.Contains(t, logOutput, "table=users")
	assert.Contains(t, logOutput, "level=WARN")
}

func TestRunDBOp_RecordNotFound(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	err := RunDBOp(ctx, logger, nil, nil, OpRead, "find user", func(opCtx context.Context) error {
		return gorm.ErrRecordNotFound
	}, slog.Int("id", 42))

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRecordNotFound)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Equal(t, ErrRecordNotFound, err)

	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "record not found")
	assert.Contains(t, logOutput, "level=DEBUG")
	assert.NotContains(t, logOutput, "level=ERROR")
}

func TestRunDBOp_GeneralError(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dbErr := errors.New("connection broken")
	err := RunDBOp(ctx, logger, nil, nil, OpWrite, "insert user", func(opCtx context.Context) error {
		return dbErr
	}, slog.String("user", "test_user"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "insert user: database operation failed")
	assert.ErrorIs(t, err, dbErr)

	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "level=ERROR")
	assert.Contains(t, logOutput, "insert user: database operation failed")
	assert.Contains(t, logOutput, "user=test_user")
}

func TestRunDBOp_NoDuplicateGormLogs(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	sl := NewSlogLogger(SlogLoggerConfig{
		SlowThreshold:             5 * time.Millisecond,
		IgnoreRecordNotFoundError: true,
		LogLevel:                  gormlogger.Warn,
		BaseLogger:                logger,
	})

	t.Run("error emits single ERROR log with SQL context", func(t *testing.T) {
		logBuf.Reset()
		dbErr := errors.New("duplicate key value")
		err := RunDBOp(ctx, logger, nil, nil, OpWrite, "create user", func(opCtx context.Context) error {
			sl.Trace(opCtx, time.Now().Add(-20*time.Millisecond), func() (string, int64) {
				return "INSERT INTO users (name) VALUES ('alice')", 0
			}, dbErr)
			return dbErr
		}, slog.String("username", "alice"))

		require.Error(t, err)
		out := logBuf.String()
		assert.Equal(t, 1, strings.Count(out, "level=ERROR"), "expected exactly one ERROR log, got:\n%s", out)
		assert.NotContains(t, out, "gorm query error")
		assert.Contains(t, out, "create user: database operation failed")
		assert.Contains(t, out, "INSERT INTO users")
	})

	t.Run("slow query emits single WARN log with SQL context", func(t *testing.T) {
		logBuf.Reset()
		slow := &DBSlowThreshold{ReadSlow: 10 * time.Millisecond}
		err := RunDBOp(ctx, logger, nil, slow, OpRead, "get user", func(opCtx context.Context) error {
			time.Sleep(15 * time.Millisecond)
			sl.Trace(opCtx, time.Now().Add(-15*time.Millisecond), func() (string, int64) {
				return "SELECT * FROM users WHERE id = 1", 1
			}, nil)
			return nil
		}, slog.Int("id", 1))

		require.NoError(t, err)
		out := logBuf.String()
		assert.Equal(t, 1, strings.Count(out, "level=WARN"), "expected exactly one WARN log, got:\n%s", out)
		assert.NotContains(t, out, "gorm slow query")
		assert.Contains(t, out, "get user: database operation exceeded the slow query threshold")
		assert.Contains(t, out, "SELECT * FROM users WHERE id = 1")
	})

	t.Run("info mode logs query at INFO and single WARN when slow", func(t *testing.T) {
		logBuf.Reset()
		slInfo := sl.LogMode(gormlogger.Info)
		slow := &DBSlowThreshold{ReadSlow: 10 * time.Millisecond}
		err := RunDBOp(ctx, logger, nil, slow, OpRead, "list users", func(opCtx context.Context) error {
			time.Sleep(15 * time.Millisecond)
			slInfo.Trace(opCtx, time.Now().Add(-15*time.Millisecond), func() (string, int64) {
				return "SELECT * FROM users", 5
			}, nil)
			return nil
		})

		require.NoError(t, err)
		out := logBuf.String()
		assert.Equal(t, 1, strings.Count(out, "level=INFO"), "expected one INFO log")
		assert.Equal(t, 1, strings.Count(out, "level=WARN"), "expected one WARN log")
		assert.Contains(t, out, "rows=5")
	})

	t.Run("record not found logs single DEBUG with SQL context", func(t *testing.T) {
		logBuf.Reset()
		err := RunDBOp(ctx, logger, nil, nil, OpRead, "find missing user", func(opCtx context.Context) error {
			sl.Trace(opCtx, time.Now().Add(-2*time.Millisecond), func() (string, int64) {
				return "SELECT * FROM users WHERE id = 999", 0
			}, gorm.ErrRecordNotFound)
			return gorm.ErrRecordNotFound
		})

		require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		out := logBuf.String()
		assert.Equal(t, 1, strings.Count(out, "level=DEBUG"))
		assert.Equal(t, 0, strings.Count(out, "level=ERROR"))
		assert.Contains(t, out, "SELECT * FROM users WHERE id = 999")
	})

	t.Run("multi-query operation below individual threshold captures slowest query and count in slow warning", func(t *testing.T) {
		logBuf.Reset()
		slow := &DBSlowThreshold{WriteSlow: 15 * time.Millisecond}
		err := RunDBOp(ctx, logger, nil, slow, OpWrite, "multi query tx", func(opCtx context.Context) error {
			time.Sleep(10 * time.Millisecond)
			sl.Trace(opCtx, time.Now().Add(-8*time.Millisecond), func() (string, int64) {
				return "INSERT INTO users (name) VALUES ('bob')", 1
			}, nil)

			time.Sleep(10 * time.Millisecond)
			sl.Trace(opCtx, time.Now().Add(-10*time.Millisecond), func() (string, int64) {
				return "INSERT INTO profiles (user_id) VALUES (1)", 1
			}, nil)
			return nil
		})

		require.NoError(t, err)
		out := logBuf.String()
		assert.Equal(t, 1, strings.Count(out, "level=WARN"))
		assert.Contains(t, out, "queries_count=2")
		assert.Contains(t, out, "INSERT INTO profiles")
	})

	t.Run("erroring query SQL is not overwritten by subsequent slower query or cascading error", func(t *testing.T) {
		logBuf.Reset()
		rootErr := errors.New("foreign key violation")
		err := RunDBOp(ctx, logger, nil, nil, OpWrite, "tx with cleanup", func(opCtx context.Context) error {
			// First query fails in 5ms
			sl.Trace(opCtx, time.Now().Add(-5*time.Millisecond), func() (string, int64) {
				return "INSERT INTO orders (user_id) VALUES (999)", 0
			}, rootErr)

			// Subsequent cleanup/rollback or slower query takes 25ms and succeeds
			sl.Trace(opCtx, time.Now().Add(-25*time.Millisecond), func() (string, int64) {
				return "DELETE FROM temp_locks WHERE user_id = 999", 1
			}, nil)

			// Cascading error on aborted tx
			sl.Trace(opCtx, time.Now().Add(-30*time.Millisecond), func() (string, int64) {
				return "SELECT 1", -1
			}, errors.New("current transaction is aborted"))

			return rootErr
		})

		require.ErrorIs(t, err, rootErr)
		out := logBuf.String()
		assert.Equal(t, 1, strings.Count(out, "level=ERROR"))
		assert.Contains(t, out, "queries_count=3")
		assert.Contains(t, out, "INSERT INTO orders (user_id) VALUES (999)")
		assert.NotContains(t, out, "DELETE FROM temp_locks")
	})
}

func TestRunDBOp_NilLoggerFallback(t *testing.T) {
	// logger is nil -> falls back to slog.Default() safely without panic
	dbErr := errors.New("timeout failure")
	err := RunDBOp(context.Background(), nil, nil, nil, OpWrite, "update inventory", func(opCtx context.Context) error {
		return dbErr
	}, slog.String("sku", "ITEM-999"))

	require.Error(t, err)
	assert.ErrorIs(t, err, dbErr)
}
