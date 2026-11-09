package iam

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/db"
)

func TestRunPolicyOp(t *testing.T) {
	ctx := context.Background()

	t.Run("success without slow threshold", func(t *testing.T) {
		called := false
		err := runPolicyOp(ctx, nil, nil, nil, "test op", func(opCtx context.Context) error {
			called = true
			return nil
		})
		require.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("op returns error", func(t *testing.T) {
		err := runPolicyOp(ctx, slog.Default(), nil, nil, "fail op", func(opCtx context.Context) error {
			return errors.New("underlying policy error")
		}, slog.String("detail", "test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fail op: policy operation failed")
		assert.Contains(t, err.Error(), "underlying policy error")
	})

	t.Run("slow operation alert", func(t *testing.T) {
		slow := &db.DBSlowThreshold{
			WriteSlow: 5 * time.Millisecond,
		}
		err := runPolicyOp(ctx, slog.Default(), nil, slow, "slow op", func(opCtx context.Context) error {
			time.Sleep(10 * time.Millisecond)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("context cancelled", func(t *testing.T) {
		cancCtx, cancel := context.WithCancel(ctx)
		cancel()

		err := runPolicyOp(cancCtx, nil, nil, nil, "canceled op", func(opCtx context.Context) error {
			return opCtx.Err()
		})
		require.Error(t, err)
	})
}
