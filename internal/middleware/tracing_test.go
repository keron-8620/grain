package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/logx"
)

func TestTracingMiddleware(t *testing.T) {
	t.Run("generates trace id if missing and populates headers and context", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		r := gin.New()
		r.Use(TracingMiddleware(logger))

		var capturedTraceID string
		var rawStringVal any
		r.GET("/trace-test", func(c *gin.Context) {
			attrs := logx.AttrsFromContext(c.Request.Context())
			for _, attr := range attrs {
				if attr.Key == "trace_id" {
					capturedTraceID = attr.Value.String()
				}
			}
			rawStringVal = c.Request.Context().Value("trace_id")
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/trace-test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		respTraceID := w.Header().Get("X-Trace-ID")
		assert.NotEmpty(t, respTraceID)
		_, err := uuid.Parse(respTraceID)
		assert.NoError(t, err)

		// Context has typed trace_id
		assert.Equal(t, respTraceID, capturedTraceID)
		// Raw string context key was removed
		assert.Nil(t, rawStringVal)
		// Cost header is present
		assert.NotEmpty(t, w.Header().Get("X-Cost-MS"))
	})

	t.Run("preserves incoming trace id", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		r := gin.New()
		r.Use(TracingMiddleware(logger))

		incomingTraceID := "custom-trace-uuid-12345"
		r.GET("/trace-test", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/trace-test", nil)
		req.Header.Set("X-Trace-ID", incomingTraceID)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, incomingTraceID, w.Header().Get("X-Trace-ID"))
	})

	t.Run("cost header is received by real HTTP client over TCP", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		r := gin.New()
		r.Use(TracingMiddleware(logger))
		r.GET("/real-http", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		ts := httptest.NewServer(r)
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/real-http")
		require.NoError(t, err)
		defer resp.Body.Close()

		_, _ = io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		costHeader := resp.Header.Get("X-Cost-MS")
		assert.NotEmpty(t, costHeader, "X-Cost-MS should be present in real HTTP response")
		traceIDHeader := resp.Header.Get("X-Trace-ID")
		assert.NotEmpty(t, traceIDHeader)
	})

	t.Run("empty handler without explicit write receives cost header", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		r := gin.New()
		r.Use(TracingMiddleware(logger))
		r.GET("/empty-handler", func(c *gin.Context) {
			// Do not write anything explicitly
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/empty-handler", nil)
		r.ServeHTTP(w, req)

		assert.NotEmpty(t, w.Header().Get("X-Cost-MS"))
	})

	t.Run("response writer unwrap and writer methods", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		r := gin.New()
		r.Use(TracingMiddleware(logger))
		r.GET("/writer-methods", func(c *gin.Context) {
			trw, ok := c.Writer.(*tracingResponseWriter)
			assert.True(t, ok)
			assert.NotNil(t, trw.Unwrap())

			c.Writer.WriteHeaderNow()
			_, _ = c.Writer.WriteString("hello string")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/writer-methods", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "hello string", w.Body.String())
		assert.NotEmpty(t, w.Header().Get("X-Cost-MS"))
	})

	t.Run("stratified logging: 2xx logs info, 4xx logs warn, 5xx logs error", func(t *testing.T) {
		var logBuf bytes.Buffer
		logHandler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
		logger := slog.New(logHandler)

		r := gin.New()
		r.Use(TracingMiddleware(logger))

		r.GET("/status-200", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		r.GET("/status-404", func(c *gin.Context) {
			c.Status(http.StatusNotFound)
		})
		r.GET("/status-500", func(c *gin.Context) {
			c.Status(http.StatusInternalServerError)
		})

		// 1. 200 -> INFO
		logBuf.Reset()
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/status-200", nil)
		r.ServeHTTP(w1, req1)
		assert.Contains(t, logBuf.String(), "level=INFO")
		assert.Contains(t, logBuf.String(), "status_code=200")

		// 2. 404 -> WARN
		logBuf.Reset()
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/status-404", nil)
		r.ServeHTTP(w2, req2)
		assert.Contains(t, logBuf.String(), "level=WARN")
		assert.Contains(t, logBuf.String(), "status_code=404")

		// 3. 500 -> ERROR
		logBuf.Reset()
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest(http.MethodGet, "/status-500", nil)
		r.ServeHTTP(w3, req3)
		assert.Contains(t, logBuf.String(), "level=ERROR")
		assert.Contains(t, logBuf.String(), "status_code=500")
	})
}
