package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"grain/internal/conf"
)

func TestCorsMiddleware(t *testing.T) {
	setupRouter := func(cfg *conf.AllowConfig) *gin.Engine {
		r := gin.New()
		r.Use(CorsMiddleware(cfg))
		r.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})
		r.POST("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "created")
		})
		return r
	}

	t.Run("default config allows any origin without credentials", func(t *testing.T) {
		r := setupRouter(nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-Trace-ID")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-Timestamp")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-Nonce")
		assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-Trace-ID")
		assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-Cost-MS")
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("preflight options request returns 204", func(t *testing.T) {
		r := setupRouter(nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodOptions, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"))
	})

	t.Run("skip cors headers when origin header is missing", func(t *testing.T) {
		r := setupRouter(nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("origin not in allowed list skips cors headers", func(t *testing.T) {
		cfg := &conf.AllowConfig{
			AllowOrigins: []string{"http://trusted.com"},
		}
		r := setupRouter(cfg)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://attacker.com")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("allowed origin with credentials echoes origin and sets vary", func(t *testing.T) {
		cfg := &conf.AllowConfig{
			AllowOrigins:     []string{"*"},
			AllowCredentials: true,
			ExposeHeaders:    []string{"X-Custom-Expose"},
		}
		r := setupRouter(cfg)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://app.example.com")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w.Header().Get("Vary"))
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "X-Custom-Expose", w.Header().Get("Access-Control-Expose-Headers"))
	})
}
