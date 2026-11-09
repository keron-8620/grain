package iam

import (
	"context"
	"log/slog"
	"time"

	"emperror.dev/errors"

	"grain/pkg/db"
)

// runPolicyOp uniformly wraps timeout control, duration accounting, slow operation alerts, and error wrapping for Casbin permission policy operations.
// op is the operation name (e.g. "add API policy").
func runPolicyOp(
	ctx context.Context,
	logger *slog.Logger,
	timeouts *db.DBTimeout,
	slow *db.DBSlowThreshold,
	op string,
	fn func(context.Context) error,
	attrs ...slog.Attr,
) error {
	if logger == nil {
		logger = slog.Default()
	}
	startTime := time.Now()

	timeout := db.OpWrite.Timeout(timeouts)
	slowThreshold := db.OpWrite.SlowThreshold(slow)

	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	opStart := time.Now()
	err := fn(opCtx)
	opDuration := time.Since(opStart)

	if err != nil {
		logAttrs := make([]slog.Attr, 0, 3+len(attrs))
		logAttrs = append(logAttrs,
			slog.Any("error", err),
			slog.Duration("op_duration", opDuration),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		logAttrs = append(logAttrs, attrs...)
		logger.LogAttrs(
			ctx,
			slog.LevelError,
			op+": policy operation failed",
			logAttrs...,
		)
		return errors.WrapIf(err, op+": policy operation failed")
	}
	if opDuration > slowThreshold {
		logAttrs := make([]slog.Attr, 0, 2+len(attrs))
		logAttrs = append(logAttrs,
			slog.Duration("op_duration", opDuration),
			slog.Duration("threshold", slowThreshold),
		)
		logAttrs = append(logAttrs, attrs...)
		logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			op+": policy operation exceeded the threshold and may affect performance",
			logAttrs...,
		)
	}
	return nil
}
