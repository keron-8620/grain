package middleware

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"grain/pkg/errorx"
)

func isWebSocketRequest(c *gin.Context) bool {
	if !strings.EqualFold(c.GetHeader("Upgrade"), "websocket") {
		return false
	}
	if c.GetHeader("Sec-WebSocket-Version") == "" {
		return false
	}
	conn := strings.ToLower(c.GetHeader("Connection"))
	if strings.Contains(conn, "upgrade") {
		return true
	}
	for _, v := range c.Request.Header["Connection"] {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

type PathTimeout struct {
	Path    string
	Timeout time.Duration
}

type TimeoutMiddlewareOption func(*timeoutMiddlewareConfig)

type timeoutMiddlewareConfig struct {
	DefaultTimeout time.Duration
	PathTimeouts   []PathTimeout
	AllowList      []string
}

func WithPathTimeout(path string, timeout time.Duration) TimeoutMiddlewareOption {
	return func(cfg *timeoutMiddlewareConfig) {
		cfg.PathTimeouts = append(cfg.PathTimeouts, PathTimeout{Path: path, Timeout: timeout})
	}
}

func WithAllowList(paths []string) TimeoutMiddlewareOption {
	return func(cfg *timeoutMiddlewareConfig) {
		cfg.AllowList = append(cfg.AllowList, paths...)
	}
}

func TimeoutMiddleware(logger *slog.Logger, defaultTimeout time.Duration, options ...TimeoutMiddlewareOption) gin.HandlerFunc {
	cfg := &timeoutMiddlewareConfig{
		DefaultTimeout: defaultTimeout,
		PathTimeouts:   make([]PathTimeout, 0),
		AllowList:      make([]string, 0),
	}

	for _, option := range options {
		option(cfg)
	}

	return func(c *gin.Context) {
		startTime := time.Now()
		ctx := c.Request.Context()

		if isWebSocketRequest(c) {
			logger.DebugContext(ctx,
				"WebSocket请求跳过超时中间件",
				slog.String("path", c.Request.URL.Path),
				slog.String("request_method", c.Request.Method),
			)
			c.Next()
			return
		}

		for _, path := range cfg.AllowList {
			if strings.HasPrefix(c.Request.URL.Path, path) {
				logger.DebugContext(ctx,
					"请求在允许列表中，跳过超时中间件",
					slog.String("path", c.Request.URL.Path),
					slog.String("request_method", c.Request.Method),
				)
				c.Next()
				return
			}
		}

		timeout := cfg.DefaultTimeout
		for _, pt := range cfg.PathTimeouts {
			if strings.HasPrefix(c.Request.URL.Path, pt.Path) {
				timeout = pt.Timeout
				break
			}
		}

		if timeout <= 0 {
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)

		// Gin Context 和 ResponseWriter 不能由多个 goroutine 并发操作。
		// 这里仅传播 deadline，由下游数据库、SSH 和业务逻辑主动响应取消。
		c.Next()

		timedOut := ctx.Err() == context.DeadlineExceeded
		if timedOut {
			logger.ErrorContext(ctx,
				"请求处理超过超时限制",
				slog.String("path", c.Request.URL.Path),
				slog.String("request_method", c.Request.Method),
				slog.Duration("timeout", timeout),
				slog.Duration("elapsed", time.Since(startTime)),
			)
			if !c.Writer.Written() {
				c.Header("X-Request-Timeout", "true")
				c.Header("Retry-After", "5")
				rErr := errorx.CodeRequestTimeout.Error()
				errorx.RespondWithError(c, rErr)
				c.Abort()
			}
		}

		logger.DebugContext(ctx,
			"请求处理完成",
			slog.String("path", c.Request.URL.Path),
			slog.String("request_method", c.Request.Method),
			slog.Duration("elapsed", time.Since(startTime)),
			slog.Duration("timeout", timeout),
			slog.Bool("is_timeout", timedOut),
		)
	}
}
