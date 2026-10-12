package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	GetLogger                 func(context.Context) *slog.Logger
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
	logger := l.getLogger(ctx)
	if !logger.Enabled(ctx, slog.LevelInfo) {
		return
	}
	if len(data) > 0 {
		msg = fmt.Sprintf(msg, data...)
	}
	l.log(ctx, logger, slog.LevelInfo, msg)
}

// Warn logs warning messages.
func (l *SlogLogger) Warn(ctx context.Context, msg string, data ...any) {
	if l.Config.LogLevel < gormlogger.Warn {
		return
	}
	logger := l.getLogger(ctx)
	if !logger.Enabled(ctx, slog.LevelWarn) {
		return
	}
	if len(data) > 0 {
		msg = fmt.Sprintf(msg, data...)
	}
	l.log(ctx, logger, slog.LevelWarn, msg)
}

// Error logs error messages.
func (l *SlogLogger) Error(ctx context.Context, msg string, data ...any) {
	if l.Config.LogLevel < gormlogger.Error {
		return
	}
	logger := l.getLogger(ctx)
	if !logger.Enabled(ctx, slog.LevelError) {
		return
	}
	if len(data) > 0 {
		msg = fmt.Sprintf(msg, data...)
	}
	l.log(ctx, logger, slog.LevelError, msg)
}

// Trace logs SQL execution, duration, rows affected, errors, and slow query alerts.
func (l *SlogLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if l.Config.LogLevel <= gormlogger.Silent {
		return
	}

	elapsed := time.Since(begin)
	logger := l.getLogger(ctx)
	fileLine := utils.FileWithLineNum()

	switch {
	case err != nil && l.Config.LogLevel >= gormlogger.Error && (!l.Config.IgnoreRecordNotFoundError || !errors.Is(err, gorm.ErrRecordNotFound)):
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
		l.logWithAttrs(ctx, logger, slog.LevelError, "gorm query error", attrs...)

	case l.Config.SlowThreshold != 0 && elapsed > l.Config.SlowThreshold && l.Config.LogLevel >= gormlogger.Warn:
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
		l.logWithAttrs(ctx, logger, slog.LevelWarn, "gorm slow query", attrs...)

	case l.Config.LogLevel >= gormlogger.Info:
		if !logger.Enabled(ctx, slog.LevelInfo) {
			return
		}
		sql, rows := fc()
		attrs := []slog.Attr{
			slog.String("caller", fileLine),
			slog.Duration("duration", elapsed),
			slog.String("sql", sql),
		}
		if rows != -1 {
			attrs = append(attrs, slog.Int64("rows", rows))
		}
		l.logWithAttrs(ctx, logger, slog.LevelInfo, "gorm query", attrs...)
	}
}

// ParamsFilter masks query parameters when ParameterizedQueries is true.
func (l *SlogLogger) ParamsFilter(ctx context.Context, sql string, params ...any) (string, []any) {
	if l.Config.ParameterizedQueries {
		return sql, nil
	}
	return sql, params
}

func (l *SlogLogger) getLogger(ctx context.Context) *slog.Logger {
	if ctx != nil && l.Config.GetLogger != nil {
		if lg := l.Config.GetLogger(ctx); lg != nil {
			return lg
		}
	}
	if l.Config.BaseLogger != nil {
		return l.Config.BaseLogger
	}
	return slog.Default()
}

func (l *SlogLogger) log(ctx context.Context, lg *slog.Logger, level slog.Level, msg string) {
	frame := utils.CallerFrame()
	r := slog.NewRecord(time.Now(), level, msg, frame.PC)
	_ = lg.Handler().Handle(ctx, r)
}

func (l *SlogLogger) logWithAttrs(ctx context.Context, lg *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	frame := utils.CallerFrame()
	r := slog.NewRecord(time.Now(), level, msg, frame.PC)
	r.AddAttrs(attrs...)
	_ = lg.Handler().Handle(ctx, r)
}
