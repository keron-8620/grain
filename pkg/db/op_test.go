package db

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"emperror.dev/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestDBOpKind_Methods(t *testing.T) {
	assert.Equal(t, "read", OpRead.label())
	assert.Equal(t, "write", OpWrite.label())
	assert.Equal(t, "list", OpList.label())
	assert.Equal(t, "read", DBOpKind(99).label())

	timeouts := &DBTimeout{
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 20 * time.Millisecond,
		ListTimeout:  30 * time.Millisecond,
	}
	assert.Equal(t, 10*time.Millisecond, OpRead.timeout(timeouts))
	assert.Equal(t, 20*time.Millisecond, OpWrite.timeout(timeouts))
	assert.Equal(t, 30*time.Millisecond, OpList.timeout(timeouts))
	assert.Equal(t, defaultDBOpTimeout, OpRead.timeout(nil))
	assert.Equal(t, defaultDBOpTimeout, OpRead.timeout(&DBTimeout{ReadTimeout: -1}))

	slow := &DBSlowThreshold{
		ReadSlow:  100 * time.Millisecond,
		WriteSlow: 200 * time.Millisecond,
		ListSlow:  300 * time.Millisecond,
	}
	assert.Equal(t, 100*time.Millisecond, OpRead.slowThreshold(slow))
	assert.Equal(t, 200*time.Millisecond, OpWrite.slowThreshold(slow))
	assert.Equal(t, 300*time.Millisecond, OpList.slowThreshold(slow))
	assert.Equal(t, defaultSlowThreshold, OpRead.slowThreshold(nil))
	assert.Equal(t, defaultSlowThreshold, OpRead.slowThreshold(&DBSlowThreshold{ReadSlow: 0}))
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
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Equal(t, gorm.ErrRecordNotFound, err)

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
