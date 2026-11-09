package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestTimeoutMiddleware(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	t.Run("fast request succeeds", func(t *testing.T) {
		r := gin.New()
		r.Use(TimeoutMiddleware(logger, 100*time.Millisecond))
		r.GET("/fast", func(c *gin.Context) {
			c.String(http.StatusOK, "fast response")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/fast", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "fast response", w.Body.String())
	})

	t.Run("slow request times out and returns 408", func(t *testing.T) {
		r := gin.New()
		r.Use(TimeoutMiddleware(logger, 20*time.Millisecond))
		r.GET("/slow", func(c *gin.Context) {
			select {
			case <-time.After(50 * time.Millisecond):
				c.String(http.StatusOK, "done")
			case <-c.Request.Context().Done():
				// Context cancelled by timeout
				return
			}
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/slow", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusRequestTimeout, w.Code)
		assert.Equal(t, "true", w.Header().Get("X-Request-Timeout"))
		assert.Equal(t, "5", w.Header().Get("Retry-After"))
		assert.Contains(t, w.Body.String(), "10408") // CodeRequestTimeout
	})

	t.Run("slow request already written does not double-write", func(t *testing.T) {
		r := gin.New()
		r.Use(TimeoutMiddleware(logger, 20*time.Millisecond))
		r.GET("/slow-written", func(c *gin.Context) {
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.Write([]byte("written early"))
			c.Writer.Flush()
			<-time.After(40 * time.Millisecond)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/slow-written", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "written early", w.Body.String())
	})

	t.Run("websocket upgrade request with compound connection header skips timeout", func(t *testing.T) {
		r := gin.New()
		r.Use(TimeoutMiddleware(logger, 20*time.Millisecond))
		r.GET("/ws", func(c *gin.Context) {
			time.Sleep(40 * time.Millisecond)
			c.String(http.StatusOK, "ws ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ws", nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "keep-alive, Upgrade")
		req.Header.Set("Sec-WebSocket-Version", "13")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ws ok", w.Body.String())
	})

	t.Run("allow list paths skip timeout", func(t *testing.T) {
		r := gin.New()
		r.Use(TimeoutMiddleware(logger, 20*time.Millisecond, WithAllowList([]string{"/long-job"})))
		r.GET("/long-job/run", func(c *gin.Context) {
			time.Sleep(40 * time.Millisecond)
			c.String(http.StatusOK, "completed")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/long-job/run?action=start", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "completed", w.Body.String())
	})

	t.Run("path timeout override applies correctly with query string", func(t *testing.T) {
		r := gin.New()
		r.Use(TimeoutMiddleware(
			logger,
			10*time.Millisecond,
			WithPathTimeout("/custom", 60*time.Millisecond),
		))
		r.GET("/custom/item", func(c *gin.Context) {
			time.Sleep(30 * time.Millisecond)
			c.String(http.StatusOK, "custom ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/custom/item?id=123", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "custom ok", w.Body.String())
	})

	t.Run("zero or negative timeout disables timeout", func(t *testing.T) {
		r := gin.New()
		r.Use(TimeoutMiddleware(logger, 0))
		r.GET("/no-timeout", func(c *gin.Context) {
			c.String(http.StatusOK, "no timeout")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/no-timeout", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
