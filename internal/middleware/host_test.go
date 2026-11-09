package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHostGuard(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	setupRouter := func(allowed ...string) *gin.Engine {
		r := gin.New()
		r.Use(HostGuard(logger, allowed...))
		r.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})
		return r
	}

	t.Run("allowed host without port allows request with port", func(t *testing.T) {
		r := setupRouter("example.com")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req.Host = "example.com:8080"
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "pong", w.Body.String())
	})

	t.Run("case insensitive host match", func(t *testing.T) {
		r := setupRouter("example.com")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req.Host = "EXAMPLE.COM:8080"
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ipv6 host matching", func(t *testing.T) {
		r := setupRouter("::1")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req.Host = "[::1]:8080"
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("missing host header is rejected", func(t *testing.T) {
		r := setupRouter("example.com")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req.Host = ""
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10201") // CodeHostHeaderInvalid
	})

	t.Run("unauthorized host is rejected", func(t *testing.T) {
		r := setupRouter("example.com")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req.Host = "evil.com"
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10201") // CodeHostHeaderInvalid
	})

	t.Run("strict port matching when configured with port", func(t *testing.T) {
		r := setupRouter("example.com:8080")

		// Exact match
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req1.Host = "example.com:8080"
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Port mismatch is rejected
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req2.Host = "example.com:9999"
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusBadRequest, w2.Code)

		// Missing port when rule requires port is rejected
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req3.Host = "example.com"
		r.ServeHTTP(w3, req3)
		assert.Equal(t, http.StatusBadRequest, w3.Code)
	})

	t.Run("wildcard domain matching", func(t *testing.T) {
		r := setupRouter("*.example.com")

		// Subdomain match
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req1.Host = "api.example.com"
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Multi-level subdomain match
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req2.Host = "v1.api.example.com:8080"
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)

		// Base domain match
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req3.Host = "example.com"
		r.ServeHTTP(w3, req3)
		assert.Equal(t, http.StatusOK, w3.Code)

		// Suffix match fraud rejected
		w4 := httptest.NewRecorder()
		req4, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req4.Host = "notexample.com"
		r.ServeHTTP(w4, req4)
		assert.Equal(t, http.StatusBadRequest, w4.Code)
	})

	t.Run("catch-all wildcard match", func(t *testing.T) {
		r := setupRouter("*")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		req.Host = "anydomain.org:3000"
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
