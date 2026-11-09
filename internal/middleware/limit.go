package middleware

import (
	"cmp"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"grain/pkg/errorx"
)

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64
}

// IPRateLimiter IP限流器管理
type IPRateLimiter struct {
	limiters   map[string]*ipLimiterEntry
	mu         sync.RWMutex
	r          rate.Limit
	b          int
	ttl        time.Duration
	maxEntries int
	stopChan   chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
}

// NewIPRateLimiter 创建IP限流器管理器
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	rl := &IPRateLimiter{
		limiters:   make(map[string]*ipLimiterEntry),
		r:          r,
		b:          b,
		ttl:        10 * time.Minute,
		maxEntries: 10000,
		stopChan:   make(chan struct{}),
	}
	rl.wg.Add(1)
	go rl.cleanup()
	return rl
}

func (i *IPRateLimiter) cleanup() {
	defer i.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			i.cleanupExpired()
		case <-i.stopChan:
			return
		}
	}
}

func (i *IPRateLimiter) cleanupExpired() {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now().UnixNano()
	for ip, entry := range i.limiters {
		if now-entry.lastSeen.Load() > int64(i.ttl) {
			delete(i.limiters, ip)
		}
	}
}

// Close 停止后台清理协程并等待其安全退出
func (i *IPRateLimiter) Close() {
	i.closeOnce.Do(func() {
		close(i.stopChan)
		i.wg.Wait()
	})
}

// SetMaxEntries 设置最大缓存条目数（供测试与微调）
func (i *IPRateLimiter) SetMaxEntries(n int) {
	i.mu.Lock()
	i.maxEntries = n
	i.mu.Unlock()
}

// SetTTL 设置缓存条目有效期（供测试与微调）
func (i *IPRateLimiter) SetTTL(d time.Duration) {
	i.mu.Lock()
	i.ttl = d
	i.mu.Unlock()
}

// GetLimiter 获取指定IP的限流器
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	if i.r <= 0 {
		return rate.NewLimiter(rate.Inf, i.b)
	}

	i.mu.RLock()
	entry, exists := i.limiters[ip]
	i.mu.RUnlock()

	if exists {
		entry.lastSeen.Store(time.Now().UnixNano())
		return entry.limiter
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	entry, exists = i.limiters[ip]
	if exists {
		entry.lastSeen.Store(time.Now().UnixNano())
		return entry.limiter
	}

	// 达到最大容量，进行单趟扫描与批量驱逐 (默认驱逐 10%)
	if len(i.limiters) >= i.maxEntries {
		now := time.Now().UnixNano()
		batchSize := int(float64(i.maxEntries) * 0.10)
		if batchSize < 1 {
			batchSize = 1
		}

		type candidate struct {
			ip   string
			seen int64
		}
		candidates := make([]candidate, 0, len(i.limiters))

		for k, v := range i.limiters {
			seen := v.lastSeen.Load()
			if now-seen > int64(i.ttl) {
				delete(i.limiters, k)
			} else {
				candidates = append(candidates, candidate{ip: k, seen: seen})
			}
		}

		targetLen := i.maxEntries - batchSize
		if targetLen < 0 {
			targetLen = 0
		}

		if len(i.limiters) > targetLen {
			needed := len(i.limiters) - targetLen
			if needed > len(candidates) {
				needed = len(candidates)
			}
			slices.SortFunc(candidates, func(a, b candidate) int {
				return cmp.Compare(a.seen, b.seen)
			})
			for idx := 0; idx < needed; idx++ {
				delete(i.limiters, candidates[idx].ip)
			}
		}
	}

	entry = &ipLimiterEntry{
		limiter: rate.NewLimiter(i.r, i.b),
	}
	entry.lastSeen.Store(time.Now().UnixNano())
	i.limiters[ip] = entry

	return entry.limiter
}

// GlobalRateLimiterMiddleware 全局限流中间件
func GlobalRateLimiterMiddleware(logger *slog.Logger, r rate.Limit, b int) gin.HandlerFunc {
	if r <= 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	limiter := rate.NewLimiter(r, b)

	return func(c *gin.Context) {
		if !limiter.Allow() {
			logger.WarnContext(
				c.Request.Context(),
				"rate limit exceeded",
				"route", c.FullPath(),
				"method", c.Request.Method,
				"client_ip", c.ClientIP(),
			)

			c.Header("Retry-After", "1")
			rErr := errorx.CodeRateLimitExceeded.Error()
			errorx.RespondWithError(c, rErr)
			return
		}
		c.Next()
	}
}

// IPBasedRateLimiterMiddlewareWithLimiter 基于已有 IPRateLimiter 实例创建 IP 限流中间件
func IPBasedRateLimiterMiddlewareWithLimiter(logger *slog.Logger, ipLimiter *IPRateLimiter) gin.HandlerFunc {
	if ipLimiter == nil || ipLimiter.r <= 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		limiter := ipLimiter.GetLimiter(c.ClientIP())
		if !limiter.Allow() {
			logger.WarnContext(
				c.Request.Context(),
				"rate limit exceeded",
				"route", c.FullPath(),
				"method", c.Request.Method,
				"client_ip", c.ClientIP(),
			)
			c.Header("Retry-After", "1")
			rErr := errorx.CodeRateLimitExceeded.Error()
			errorx.RespondWithError(c, rErr)
			return
		}
		c.Next()
	}
}

// IPBasedRateLimiterMiddleware IP限流中间件
func IPBasedRateLimiterMiddleware(logger *slog.Logger, r rate.Limit, b int) gin.HandlerFunc {
	if r <= 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	ipLimiter := NewIPRateLimiter(r, b)
	return IPBasedRateLimiterMiddlewareWithLimiter(logger, ipLimiter)
}

// RateLimiterMiddleware 向后兼容的限流中间件
func RateLimiterMiddleware(logger *slog.Logger, r rate.Limit, b int) gin.HandlerFunc {
	return GlobalRateLimiterMiddleware(logger, r, b)
}
