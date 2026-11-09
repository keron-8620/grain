package db

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

type dbOpTraceKey struct{}

// dbOpTraceState coordinates between RunDBOp and SlogLogger.Trace within a single operation
// to prevent duplicate error/slow-query log entries while preserving SQL statement context.
type dbOpTraceState struct {
	mu           sync.Mutex
	sql          string
	rows         int64
	hasSQL       bool
	hasErr       bool
	maxElapsed   time.Duration
	queriesCount int
}

func hasDBOpTrace(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(dbOpTraceKey{}).(*dbOpTraceState)
	return ok
}

func (s *dbOpTraceState) record(sql string, rows int64, elapsed time.Duration, force bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queriesCount++
	if force {
		if !s.hasErr {
			s.sql = sql
			s.rows = rows
			s.hasSQL = true
			s.hasErr = true
		}
		if elapsed > s.maxElapsed {
			s.maxElapsed = elapsed
		}
		return
	}
	if s.hasErr {
		if elapsed > s.maxElapsed {
			s.maxElapsed = elapsed
		}
		return
	}
	if !s.hasSQL || elapsed >= s.maxElapsed {
		s.sql = sql
		s.rows = rows
		s.hasSQL = true
		if elapsed > s.maxElapsed {
			s.maxElapsed = elapsed
		}
	}
}

func (s *dbOpTraceState) appendAttrs(attrs []slog.Attr) []slog.Attr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasSQL {
		return attrs
	}
	if s.queriesCount > 1 {
		attrs = append(attrs, slog.Int("queries_count", s.queriesCount))
	}
	attrs = append(attrs, slog.String("sql", s.sql))
	if s.rows != -1 {
		attrs = append(attrs, slog.Int64("rows", s.rows))
	}
	return attrs
}

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

func (k DBOpKind) Timeout(t *DBTimeout) time.Duration {
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

func (k DBOpKind) SlowThreshold(t *DBSlowThreshold) time.Duration {
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

func (k DBOpKind) Label() string {
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
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		logger = slog.Default()
	}
	startTime := time.Now()
	slowThreshold := kind.SlowThreshold(slow)
	traceState := &dbOpTraceState{
		rows: -1,
	}

	dbCtx, cancel := context.WithTimeout(
		context.WithValue(ctx, dbOpTraceKey{}, traceState),
		kind.Timeout(timeouts),
	)
	defer cancel()

	opStart := time.Now()
	err := fn(dbCtx)
	opDuration := time.Since(opStart)

	if err != nil {
		err = MapError(err)
		if errors.Is(err, ErrRecordNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			if logger.Enabled(ctx, slog.LevelDebug) {
				logAttrs := make([]slog.Attr, 0, 4+len(attrs))
				logAttrs = append(logAttrs,
					slog.String("op_kind", kind.Label()),
					slog.Duration("op_duration", opDuration),
				)
				logAttrs = traceState.appendAttrs(logAttrs)
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
		logAttrs := make([]slog.Attr, 0, 6+len(attrs))
		logAttrs = append(logAttrs,
			slog.Any("error", err),
			slog.String("op_kind", kind.Label()),
			slog.Duration("op_duration", opDuration),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		logAttrs = traceState.appendAttrs(logAttrs)
		logAttrs = append(logAttrs, attrs...)
		logger.LogAttrs(
			ctx,
			slog.LevelError,
			op+": database operation failed",
			logAttrs...,
		)
		return errors.WrapIf(err, op+": database operation failed")
	}
	if opDuration > slowThreshold {
		logAttrs := make([]slog.Attr, 0, 5+len(attrs))
		logAttrs = append(logAttrs,
			slog.String("op_kind", kind.Label()),
			slog.Duration("op_duration", opDuration),
			slog.Duration("threshold", slowThreshold),
		)
		logAttrs = traceState.appendAttrs(logAttrs)
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
