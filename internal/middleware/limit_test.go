package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestRateLimiterMiddleware(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	t.Run("global rate limiter allows within burst and rejects excess", func(t *testing.T) {
		r := gin.New()
		// Limit to 1 request per second with burst 2
		r.Use(GlobalRateLimiterMiddleware(logger, rate.Limit(1), 2))
		r.GET("/api/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		// First 2 requests within burst should pass
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/ping", nil)
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// 3rd request immediately following should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/ping", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "1", w.Header().Get("Retry-After"))
		assert.Contains(t, w.Body.String(), "10430") // CodeRateLimitExceeded
	})

	t.Run("disabled rate limit when r <= 0 allows unlimited requests", func(t *testing.T) {
		r := gin.New()
		r.Use(GlobalRateLimiterMiddleware(logger, rate.Limit(0), 0))
		r.GET("/api/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/ping", nil)
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}
	})

	t.Run("ip based rate limiter isolates different ips", func(t *testing.T) {
		r := gin.New()
		r.Use(IPBasedRateLimiterMiddleware(logger, rate.Limit(1), 1))
		r.GET("/api/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		// IP A: 1st request succeeds
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/api/ping", nil)
		req1.RemoteAddr = "192.168.1.1:12345"
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// IP A: 2nd request fails
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/api/ping", nil)
		req2.RemoteAddr = "192.168.1.1:12345"
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusTooManyRequests, w2.Code)

		// IP B: 1st request succeeds despite IP A being rate limited
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest(http.MethodGet, "/api/ping", nil)
		req3.RemoteAddr = "192.168.1.2:12345"
		r.ServeHTTP(w3, req3)
		assert.Equal(t, http.StatusOK, w3.Code)
	})

	t.Run("ip based rate limiter with r <= 0 passes through", func(t *testing.T) {
		r := gin.New()
		r.Use(IPBasedRateLimiterMiddleware(logger, rate.Limit(-1), 0))
		r.GET("/api/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/ping", nil)
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}
	})

	t.Run("ip rate limiter close and idempotent close", func(t *testing.T) {
		limiter := NewIPRateLimiter(rate.Limit(10), 10)
		assert.NotNil(t, limiter)
		limiter.Close()
		// Idempotent
		limiter.Close()
	})

	t.Run("ip rate limiter cache eviction respects maxEntries", func(t *testing.T) {
		limiter := NewIPRateLimiter(rate.Limit(10), 10)
		defer limiter.Close()

		limiter.SetMaxEntries(2)
		limiter.SetTTL(20 * time.Millisecond)

		// Add IP1 and IP2
		_ = limiter.GetLimiter("1.1.1.1")
		_ = limiter.GetLimiter("2.2.2.2")

		// Wait for TTL to expire
		time.Sleep(30 * time.Millisecond)

		// Add IP3 - should clean up expired IP1 and IP2
		_ = limiter.GetLimiter("3.3.3.3")

		limiter.mu.RLock()
		count := len(limiter.limiters)
		limiter.mu.RUnlock()
		assert.LessOrEqual(t, count, 2)

		// Add IP4 without sleeping - should evict oldest
		_ = limiter.GetLimiter("4.4.4.4")
		limiter.mu.RLock()
		count = len(limiter.limiters)
		limiter.mu.RUnlock()
		assert.LessOrEqual(t, count, 2)
	})

	t.Run("ip rate limiter batch eviction frees 10 percent", func(t *testing.T) {
		limiter := NewIPRateLimiter(rate.Limit(10), 10)
		defer limiter.Close()

		const maxEntries = 50
		limiter.SetMaxEntries(maxEntries)
		limiter.SetTTL(10 * time.Minute) // do not expire

		// Fill up to maxEntries (50)
		for i := 0; i < maxEntries; i++ {
			_ = limiter.GetLimiter(fmt.Sprintf("10.0.0.%d", i))
		}

		limiter.mu.RLock()
		assert.Equal(t, maxEntries, len(limiter.limiters))
		limiter.mu.RUnlock()

		// Add 51st IP - triggers batch eviction (10% of 50 = 5 entries evicted, leaving 45, plus 1 new = 46)
		_ = limiter.GetLimiter("10.0.0.50")

		limiter.mu.RLock()
		count := len(limiter.limiters)
		limiter.mu.RUnlock()
		assert.Equal(t, 46, count)
	})

	t.Run("cleanupExpired directly cleans up expired entries", func(t *testing.T) {
		limiter := NewIPRateLimiter(rate.Limit(10), 10)
		defer limiter.Close()

		limiter.SetTTL(10 * time.Millisecond)
		_ = limiter.GetLimiter("1.2.3.4")

		time.Sleep(20 * time.Millisecond)
		limiter.cleanupExpired()

		limiter.mu.RLock()
		assert.Equal(t, 0, len(limiter.limiters))
		limiter.mu.RUnlock()
	})

	t.Run("ip based rate limiter with supplied limiter", func(t *testing.T) {
		limiter := NewIPRateLimiter(rate.Limit(5), 5)
		defer limiter.Close()

		r := gin.New()
		r.Use(IPBasedRateLimiterMiddlewareWithLimiter(logger, limiter))
		r.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ip based rate limiter with nil limiter passes through", func(t *testing.T) {
		r := gin.New()
		r.Use(IPBasedRateLimiterMiddlewareWithLimiter(logger, nil))
		r.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("legacy rate limiter alias calls global limiter", func(t *testing.T) {
		r := gin.New()
		r.Use(RateLimiterMiddleware(logger, rate.Limit(1), 1))
		r.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
