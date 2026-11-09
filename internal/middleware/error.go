package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	emperrors "emperror.dev/errors"
	"github.com/gin-gonic/gin"

	"grain/pkg/errorx"
)

func isBrokenPipe(r any) bool {
	err, ok := r.(error)
	if !ok {
		return false
	}
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, http.ErrAbortHandler) {
		return true
	}
	var netOpErr *net.OpError
	if errors.As(err, &netOpErr) {
		var sysErr *os.SyscallError
		if errors.As(netOpErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.EPIPE) || errors.Is(sysErr.Err, syscall.ECONNRESET) {
				return true
			}
		}
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "broken pipe") || strings.Contains(errStr, "connection reset by peer")
}

// ErrorMiddleware 异常处理中间件
// 拦截所有panic并记录堆栈，进行统一处理和安全响应；同时统一处理未写入响应的 context 错误
func ErrorMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				c.Abort()

				ctx := c.Request.Context()

				// 构造错误对象
				var err error
				switch v := r.(type) {
				case error:
					err = emperrors.WithStack(v)
				case string:
					err = emperrors.New(v)
				default:
					err = emperrors.New(fmt.Sprintf("%v", v))
				}

				if isBrokenPipe(r) {
					logger.WarnContext(
						ctx,
						"client connection broken pipe",
						slog.Any("error", err),
						slog.String("method", c.Request.Method),
						slog.String("url", c.Request.URL.String()),
						slog.String("client_ip", c.ClientIP()),
					)
					_ = c.Error(err)
					return
				}

				stack := debug.Stack()
				err = emperrors.WrapWithDetails(
					err,
					"panic recovered",
					"method", c.Request.Method,
					"url", c.Request.URL.String(),
					"client_ip", c.ClientIP(),
					"user_agent", c.Request.UserAgent(),
				)

				logger.ErrorContext(
					ctx,
					"panic recovered",
					slog.Any("error", err),
					slog.Any("panic", r),
					slog.String("stack", string(stack)),
					slog.String("method", c.Request.Method),
					slog.String("url", c.Request.URL.String()),
					slog.String("client_ip", c.ClientIP()),
					slog.String("user_agent", c.Request.UserAgent()),
				)

				if !c.Writer.Written() {
					rErr := errorx.CodeUnknown.Error()
					errorx.RespondWithError(c, rErr)
				}
			}
		}()

		// 继续处理请求
		c.Next()

		// 处理未被捕获并附加在 Context 上的错误
		if !c.Writer.Written() && len(c.Errors) > 0 {
			lastErr := c.Errors.Last()
			if lastErr != nil && lastErr.Err != nil {
				logger.ErrorContext(
					c.Request.Context(),
					"unhandled error in context",
					slog.String("error", lastErr.Error()),
					slog.String("method", c.Request.Method),
					slog.String("path", c.Request.URL.Path),
				)
				errorx.RespondWithError(c, lastErr.Err)
			}
		}
	}
}
