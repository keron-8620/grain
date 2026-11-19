package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
)

type mockNonceStore struct {
	mu     sync.Mutex
	nonces map[string]bool
}

func (m *mockNonceStore) Add(k string, _ any, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nonces[k] {
		return errors.New("key already exists")
	}
	m.nonces[k] = true
	return nil
}

func TestTimestampMiddleware(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	setupRouter := func(store NonceStore, tol, futureTol int64, exp time.Duration, opts ...TimestampOption) *gin.Engine {
		r := gin.New()
		r.Use(TimestampMiddleware(logger, store, tol, futureTol, exp, opts...))
		r.GET("/api/secure", func(c *gin.Context) {
			c.String(http.StatusOK, "secure data")
		})
		r.GET("/public/info", func(c *gin.Context) {
			c.String(http.StatusOK, "public info")
		})
		r.GET("/custom/secure", func(c *gin.Context) {
			c.String(http.StatusOK, "custom secure")
		})
		return r
	}

	t.Run("non-api routes bypass timestamp check", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/public/info", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "public info", w.Body.String())
	})

	t.Run("nil nonce store returns config error", func(t *testing.T) {
		r := setupRouter(nil, 300000, 60000, time.Minute)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20004") // CodeConfigError
	})

	t.Run("typed nil pointer nonce store returns config error", func(t *testing.T) {
		var typedNil *cache.Cache
		r := setupRouter(typedNil, 300000, 60000, time.Minute)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20004") // CodeConfigError
	})

	t.Run("missing timestamp header returns 400", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req.Header.Set("X-Nonce", "nonce-1")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10204") // CodeTimestampNotFound
	})

	t.Run("missing nonce header returns 400", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10202") // CodeNonceNotFound
	})

	t.Run("invalid timestamp string returns 400", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req.Header.Set("X-Timestamp", "not-a-number")
		req.Header.Set("X-Nonce", "nonce-2")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10205") // CodeTimestampInvalid
	})

	t.Run("expired timestamp in past returns 400", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 1000, 1000, time.Minute)

		pastTime := time.Now().Add(-10 * time.Second).UnixMilli()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req.Header.Set("X-Timestamp", fmt.Sprintf("%d", pastTime))
		req.Header.Set("X-Nonce", "nonce-3")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10206") // CodeTimestampExpired
	})

	t.Run("future timestamp beyond futureTolerance returns 400", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 10000, 1000, time.Minute)

		futureTime := time.Now().Add(10 * time.Second).UnixMilli()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req.Header.Set("X-Timestamp", fmt.Sprintf("%d", futureTime))
		req.Header.Set("X-Nonce", "nonce-4")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10206") // CodeTimestampExpired
	})

	t.Run("valid timestamp and nonce succeeds, sequential replay is blocked", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute)

		ts := fmt.Sprintf("%d", time.Now().UnixMilli())
		nonce := "unique-nonce-100"

		// 1st request succeeds
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req1.Header.Set("X-Timestamp", ts)
		req1.Header.Set("X-Nonce", nonce)
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// 2nd request with same nonce fails with CodeReplayAttack
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req2.Header.Set("X-Timestamp", ts)
		req2.Header.Set("X-Nonce", nonce)
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusBadRequest, w2.Code)
		assert.Contains(t, w2.Body.String(), "10203") // CodeReplayAttack
	})

	t.Run("concurrent replay attack: atomic Add ensures exactly one request succeeds", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute)

		ts := fmt.Sprintf("%d", time.Now().UnixMilli())
		sharedNonce := "race-nonce-concurrent"

		const concurrency = 20
		var successCount atomic.Int32
		var replayBlockedCount atomic.Int32

		var wg sync.WaitGroup
		startSignal := make(chan struct{})

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-startSignal // sync start for maximum concurrency

				w := httptest.NewRecorder()
				req, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
				req.Header.Set("X-Timestamp", ts)
				req.Header.Set("X-Nonce", sharedNonce)
				r.ServeHTTP(w, req)

				switch w.Code {
				case http.StatusOK:
					successCount.Add(1)
				case http.StatusBadRequest:
					replayBlockedCount.Add(1)
				}
			}()
		}

		close(startSignal) // trigger all goroutines simultaneously
		wg.Wait()

		// Exactly one must succeed, remainder must be blocked by atomic Add
		assert.Equal(t, int32(1), successCount.Load(), "exactly one request should succeed")
		assert.Equal(t, int32(concurrency-1), replayBlockedCount.Load(), "all other concurrent requests must be rejected")
	})

	t.Run("custom route prefix option", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute, WithRoutePrefix("/custom"))

		// /api/secure should bypass check
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// /custom/secure requires timestamp & nonce
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/custom/secure", nil)
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusBadRequest, w2.Code)
		assert.Contains(t, w2.Body.String(), "10204")
	})

	t.Run("empty route prefix protects all routes", func(t *testing.T) {
		store := cache.New(time.Minute, time.Minute)
		r := setupRouter(store, 300000, 60000, time.Minute, WithRoutePrefix(""))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/public/info", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "10204")
	})

	t.Run("custom mock NonceStore implementation", func(t *testing.T) {
		mockStore := &mockNonceStore{nonces: make(map[string]bool)}
		r := setupRouter(mockStore, 300000, 60000, time.Minute)

		ts := fmt.Sprintf("%d", time.Now().UnixMilli())
		nonce := "mock-nonce-1"

		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req1.Header.Set("X-Timestamp", ts)
		req1.Header.Set("X-Nonce", nonce)
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/api/secure", nil)
		req2.Header.Set("X-Timestamp", ts)
		req2.Header.Set("X-Nonce", nonce)
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusBadRequest, w2.Code)
		assert.Contains(t, w2.Body.String(), "10203")
	})
}
