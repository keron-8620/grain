package logx

import (
	"context"
	"log/slog"
)

type loggerKey struct{}

// ---------- Logger 存取 ----------

// WithLogger 把 logger 放入 context
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerKey{}, l)
}

// FromContext 从 context 取出 logger，取不到则返回 slog.Default()
func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// LoggerFromContext 从 context 取出 logger，取不到则返回 nil
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return nil
	}
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return nil
}
