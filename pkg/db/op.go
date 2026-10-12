package db

import (
	"context"
	"log/slog"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

// DBTimeout holds database operation timeout parameters.
type DBTimeout struct {
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	ListTimeout  time.Duration
}

// DBSlowThreshold holds database slow query thresholds -- used only for log alerts, not for control flow.
type DBSlowThreshold struct {
	ReadSlow  time.Duration // single-record slow query threshold
	WriteSlow time.Duration // write slow query threshold
	ListSlow  time.Duration // list slow query threshold
}

// DBOpKind labels the database operation kind and determines which timeout and slow query threshold to use.
type DBOpKind int

const (
	OpRead DBOpKind = iota
	OpWrite
	OpList
)

// defaultDBOpTimeout is used when the configured duration for an operation kind is unset (zero or
// negative). context.WithTimeout with a non-positive duration expires immediately, so falling back
// to this default keeps an incomplete configuration from failing every database and policy call.
const defaultDBOpTimeout = 5 * time.Second

// defaultSlowThreshold is the fallback slow-query threshold; it only controls log verbosity.
const defaultSlowThreshold = time.Second

func (k DBOpKind) timeout(t *DBTimeout) time.Duration {
	if t == nil {
		return defaultDBOpTimeout
	}
	var configured time.Duration
	switch k {
	case OpWrite:
		configured = t.WriteTimeout
	case OpList:
		configured = t.ListTimeout
	default:
		configured = t.ReadTimeout
	}
	if configured <= 0 {
		return defaultDBOpTimeout
	}
	return configured
}

func (k DBOpKind) slowThreshold(t *DBSlowThreshold) time.Duration {
	if t == nil {
		return defaultSlowThreshold
	}
	var configured time.Duration
	switch k {
	case OpWrite:
		configured = t.WriteSlow
	case OpList:
		configured = t.ListSlow
	default:
		configured = t.ReadSlow
	}
	if configured <= 0 {
		return defaultSlowThreshold
	}
	return configured
}

func (k DBOpKind) label() string {
	switch k {
	case OpWrite:
		return "write"
	case OpList:
		return "list"
	default:
		return "read"
	}
}

// RunDBOp uniformly wraps timeout control, duration accounting, slow query alerts, and error log wrapping for database operations,
// eliminating duplicated boilerplate across repository methods. op is the operation name (e.g. "find user model");
// error logs and wrapped messages use the form "<op>: database operation failed"; operation arguments (conditions/fields, etc.)
// can be passed via attrs and are emitted in slow query alerts, failure, and not-found logs to ease production troubleshooting.
func RunDBOp(
	ctx context.Context,
	logger *slog.Logger,
	timeouts *DBTimeout,
	slow *DBSlowThreshold,
	kind DBOpKind,
	op string,
	fn func(context.Context) error,
	attrs ...slog.Attr,
) error {
	if logger == nil {
		logger = slog.Default()
	}
	startTime := time.Now()

	dbCtx, cancel := context.WithTimeout(ctx, kind.timeout(timeouts))
	defer cancel()

	opStart := time.Now()
	err := fn(dbCtx)
	opDuration := time.Since(opStart)

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if logger.Enabled(ctx, slog.LevelDebug) {
				logAttrs := make([]slog.Attr, 0, 2+len(attrs))
				logAttrs = append(logAttrs,
					slog.String("op_kind", kind.label()),
					slog.Duration("op_duration", opDuration),
				)
				logAttrs = append(logAttrs, attrs...)
				logger.LogAttrs(
					ctx,
					slog.LevelDebug,
					op+": record not found",
					logAttrs...,
				)
			}
			return err
		}
		logAttrs := make([]slog.Attr, 0, 4+len(attrs))
		logAttrs = append(logAttrs,
			slog.Any("error", err),
			slog.String("op_kind", kind.label()),
			slog.Duration("op_duration", opDuration),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		logAttrs = append(logAttrs, attrs...)
		logger.LogAttrs(
			ctx,
			slog.LevelError,
			op+": database operation failed",
			logAttrs...,
		)
		return errors.WrapIf(err, op+": database operation failed")
	}
	if opDuration > kind.slowThreshold(slow) {
		logAttrs := make([]slog.Attr, 0, 3+len(attrs))
		logAttrs = append(logAttrs,
			slog.String("op_kind", kind.label()),
			slog.Duration("op_duration", opDuration),
			slog.Duration("threshold", kind.slowThreshold(slow)),
		)
		logAttrs = append(logAttrs, attrs...)
		logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			op+": database operation exceeded the slow query threshold and may affect performance",
			logAttrs...,
		)
	}
	return nil
}
