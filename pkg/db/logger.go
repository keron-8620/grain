package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/utils"
)

// SlogLoggerConfig configures the GORM slog adapter.
type SlogLoggerConfig struct {
	SlowThreshold             time.Duration       // Duration above which queries are logged as warnings
	ParameterizedQueries      bool                // When true, hide statement parameters in logs
	IgnoreRecordNotFoundError bool                // When true, ErrRecordNotFound is not logged as an error
	LogLevel                  gormlogger.LogLevel // GORM log level (Silent, Error, Warn, Info)
	BaseLogger                *slog.Logger
}

// SlogLogger implements gormlogger.Interface and gormlogger.ParamsFilter using slog.
type SlogLogger struct {
	Config SlogLoggerConfig
}

// NewSlogLogger creates a new GORM logger adapter backed by slog.
func NewSlogLogger(cfg SlogLoggerConfig) *SlogLogger {
	if cfg.SlowThreshold <= 0 {
		cfg.SlowThreshold = time.Second
	}
	return &SlogLogger{Config: cfg}
}

// LogMode sets the log level and returns a new logger interface instance.
func (l *SlogLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	clone := *l
	clone.Config.LogLevel = level
	return &clone
}

// Info logs informative messages.
func (l *SlogLogger) Info(ctx context.Context, msg string, data ...any) {
	if l.Config.LogLevel < gormlogger.Info {
		return
	}
	logger := l.getLogger()
	if !logger.Enabled(ctx, slog.LevelInfo) {
		return
	}
	frame, _ := resolveCaller()
	l.emit(ctx, logger, slog.LevelInfo, formatMsg(msg, data...), frame, nil)
}

// Warn logs warning messages.
func (l *SlogLogger) Warn(ctx context.Context, msg string, data ...any) {
	if l.Config.LogLevel < gormlogger.Warn {
		return
	}
	logger := l.getLogger()
	if !logger.Enabled(ctx, slog.LevelWarn) {
		return
	}
	frame, _ := resolveCaller()
	l.emit(ctx, logger, slog.LevelWarn, formatMsg(msg, data...), frame, nil)
}

// Error logs error messages.
func (l *SlogLogger) Error(ctx context.Context, msg string, data ...any) {
	if l.Config.LogLevel < gormlogger.Error {
		return
	}
	logger := l.getLogger()
	if !logger.Enabled(ctx, slog.LevelError) {
		return
	}
	frame, _ := resolveCaller()
	l.emit(ctx, logger, slog.LevelError, formatMsg(msg, data...), frame, nil)
}

// Trace logs SQL execution, duration, rows affected, errors, and slow query alerts.
// When invoked inside RunDBOp (detected via dbOpTraceState in ctx), error and slow-query
// alerts are delegated to RunDBOp so only one unified log entry is emitted with SQL context.
func (l *SlogLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if l.Config.LogLevel <= gormlogger.Silent {
		return
	}

	elapsed := time.Since(begin)

	var opState *dbOpTraceState
	if ctx != nil {
		opState, _ = ctx.Value(dbOpTraceKey{}).(*dbOpTraceState)
	}

	if opState != nil {
		isRecordNotFound := errors.Is(err, ErrRecordNotFound) || errors.Is(err, gorm.ErrRecordNotFound)

		// Error path: only record into opState; RunDBOp emits the unified log.
		if err != nil && (!l.Config.IgnoreRecordNotFoundError || !isRecordNotFound) {
			sql, rows := fc()
			opState.record(sql, rows, elapsed, true)
			return
		}

		// Success path with per-query logging enabled.
		if err == nil && l.Config.LogLevel >= gormlogger.Info {
			logger := l.getLogger()
			if logger.Enabled(ctx, slog.LevelInfo) {
				frame, fileLine := resolveCaller()
				sql, rows := fc()
				opState.record(sql, rows, elapsed, false)

				attrs := []slog.Attr{
					slog.String("caller", fileLine),
					slog.Duration("duration", elapsed),
					slog.String("sql", sql),
				}
				if rows != -1 {
					attrs = append(attrs, slog.Int64("rows", rows))
				}
				l.emit(ctx, logger, slog.LevelInfo, "gorm query", frame, attrs)
				return
			}
		}

		// Always record SQL for queries executed inside RunDBOp.
		// Even if this individual query is below the per-query threshold,
		// cumulative execution across multiple queries may exceed RunDBOp's threshold.
		sql, rows := fc()
		opState.record(sql, rows, elapsed, false)
		return
	}

	logger := l.getLogger()

	switch {
	case err != nil &&
		l.Config.LogLevel >= gormlogger.Error &&
		(!l.Config.IgnoreRecordNotFoundError || !(errors.Is(err, ErrRecordNotFound) || errors.Is(err, gorm.ErrRecordNotFound))):

		if !logger.Enabled(ctx, slog.LevelError) {
			return
		}
		frame, fileLine := resolveCaller()
		sql, rows := fc()
		attrs := []slog.Attr{
			slog.String("caller", fileLine),
			slog.Duration("duration", elapsed),
			slog.String("sql", sql),
			slog.String("error", err.Error()),
		}
		if rows != -1 {
			attrs = append(attrs, slog.Int64("rows", rows))
		}
		l.emit(ctx, logger, slog.LevelError, "gorm query error", frame, attrs)

	case l.Config.SlowThreshold != 0 &&
		elapsed > l.Config.SlowThreshold &&
		l.Config.LogLevel >= gormlogger.Warn:

		if !logger.Enabled(ctx, slog.LevelWarn) {
			return
		}
		frame, fileLine := resolveCaller()
		sql, rows := fc()
		attrs := []slog.Attr{
			slog.String("caller", fileLine),
			slog.Duration("duration", elapsed),
			slog.Duration("threshold", l.Config.SlowThreshold),
			slog.String("sql", sql),
		}
		if rows != -1 {
			attrs = append(attrs, slog.Int64("rows", rows))
		}
		l.emit(ctx, logger, slog.LevelWarn, "gorm slow query", frame, attrs)

	case l.Config.LogLevel >= gormlogger.Info:
		if !logger.Enabled(ctx, slog.LevelInfo) {
			return
		}
		frame, fileLine := resolveCaller()
		sql, rows := fc()
		attrs := []slog.Attr{
			slog.String("caller", fileLine),
			slog.Duration("duration", elapsed),
			slog.String("sql", sql),
		}
		if rows != -1 {
			attrs = append(attrs, slog.Int64("rows", rows))
		}
		l.emit(ctx, logger, slog.LevelInfo, "gorm query", frame, attrs)
	}
}

// ParamsFilter masks query parameters when ParameterizedQueries is true.
func (l *SlogLogger) ParamsFilter(ctx context.Context, sql string, params ...any) (string, []any) {
	if l.Config.ParameterizedQueries {
		return sql, nil
	}
	return sql, params
}

func (l *SlogLogger) getLogger() *slog.Logger {
	if l.Config.BaseLogger != nil {
		return l.Config.BaseLogger
	}
	return slog.Default()
}

func (l *SlogLogger) emit(
	ctx context.Context,
	lg *slog.Logger,
	level slog.Level,
	msg string,
	frame runtime.Frame,
	attrs []slog.Attr,
) {
	r := slog.NewRecord(time.Now(), level, msg, frame.PC)
	if len(attrs) > 0 {
		r.AddAttrs(attrs...)
	}
	_ = lg.Handler().Handle(ctx, r)
}

func formatMsg(msg string, data ...any) string {
	if len(data) == 0 {
		return msg
	}
	if !strings.Contains(msg, "%") {
		return msg + " " + fmt.Sprint(data...)
	}
	return fmt.Sprintf(msg, data...)
}

// resolveCaller finds the first frame outside gorm.io and pkg/db helper wrappers (except test files).
func resolveCaller() (runtime.Frame, string) {
	var pcs [20]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		file := frame.File
		if !strings.Contains(file, "gorm.io/") &&
			!(strings.Contains(file, "pkg/db/") && !strings.HasSuffix(file, "_test.go")) {
			return frame, fmt.Sprintf("%s:%d", frame.File, frame.Line)
		}
		if !more {
			break
		}
	}
	frame := utils.CallerFrame()
	return frame, utils.FileWithLineNum()
}
