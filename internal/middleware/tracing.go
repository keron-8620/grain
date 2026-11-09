package middleware

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"grain/pkg/logx"
)

type tracingResponseWriter struct {
	gin.ResponseWriter
	start       time.Time
	wroteHeader bool
}

func (w *tracingResponseWriter) ensureCostHeader() {
	if !w.wroteHeader {
		w.wroteHeader = true
		duration := time.Since(w.start)
		w.Header().Set("X-Cost-MS", strconv.FormatInt(duration.Milliseconds(), 10))
	}
}

func (w *tracingResponseWriter) WriteHeader(code int) {
	w.ensureCostHeader()
	w.ResponseWriter.WriteHeader(code)
}

func (w *tracingResponseWriter) WriteHeaderNow() {
	w.ensureCostHeader()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *tracingResponseWriter) Write(data []byte) (int, error) {
	w.ensureCostHeader()
	return w.ResponseWriter.Write(data)
}

func (w *tracingResponseWriter) WriteString(s string) (int, error) {
	w.ensureCostHeader()
	return w.ResponseWriter.WriteString(s)
}

func (w *tracingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func TracingMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 生成或获取请求ID
		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			traceID = uuid.NewString()
		}
		ctx := c.Request.Context()
		newCtx := logx.ContextWithTraceID(ctx, traceID)
		c.Request = c.Request.WithContext(newCtx)
		c.Header("X-Trace-ID", traceID)

		// 开始时间
		start := time.Now()

		// 记录请求开始
		logger.DebugContext(
			newCtx,
			"请求开始",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.String("client_ip", c.ClientIP()),
		)

		trw := &tracingResponseWriter{
			ResponseWriter: c.Writer,
			start:          start,
		}
		c.Writer = trw

		// 处理请求
		c.Next()

		// 处理可能存在的未显式写入情况
		trw.ensureCostHeader()

		// 计算请求耗时
		duration := time.Since(start)

		statusCode := c.Writer.Status()
		endCtx := c.Request.Context()

		// 日志级别分层：5xx 错误记录为 Error，4xx 客户端异常记录为 Warn，正常请求记录为 Info
		switch {
		case statusCode >= http.StatusInternalServerError:
			logger.ErrorContext(
				endCtx,
				"请求结束",
				slog.String("method", c.Request.Method),
				slog.String("path", c.Request.URL.Path),
				slog.Int("status_code", statusCode),
				slog.Duration("total_duration", duration),
			)
		case statusCode >= http.StatusBadRequest:
			logger.WarnContext(
				endCtx,
				"请求结束",
				slog.String("method", c.Request.Method),
				slog.String("path", c.Request.URL.Path),
				slog.Int("status_code", statusCode),
				slog.Duration("total_duration", duration),
			)
		default:
			logger.InfoContext(
				endCtx,
				"请求结束",
				slog.String("method", c.Request.Method),
				slog.String("path", c.Request.URL.Path),
				slog.Int("status_code", statusCode),
				slog.Duration("total_duration", duration),
			)
		}
	}
}
