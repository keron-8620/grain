package middleware

import (
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"grain/pkg/errorx"
)

// NonceStore 抽象防重放 Nonce 存储接口（兼容 *cache.Cache 与 Redis 等存储）
type NonceStore interface {
	Add(k string, x any, d time.Duration) error
}

type TimestampOption func(*timestampConfig)

type timestampConfig struct {
	routePrefix string
}

func defaultTimestampConfig() *timestampConfig {
	return &timestampConfig{
		routePrefix: "/api",
	}
}

// WithRoutePrefix 配置时间戳中间件校验的路由前缀。
// 默认为 "/api"；如果设置为空字符串 ""，则对所有请求进行时间戳与防重放校验。
func WithRoutePrefix(prefix string) TimestampOption {
	return func(cfg *timestampConfig) {
		cfg.routePrefix = prefix
	}
}

func isNilNonceStore(s NonceStore) bool {
	if s == nil {
		return true
	}
	v := reflect.ValueOf(s)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return true
	}
	return false
}

// TimestampMiddleware 创建防重放攻击中间件
// logger: 日志记录器
// tolerance: 时间容忍度（毫秒），默认300000（5分钟）
// futureTolerance: 允许未来时间的容忍度（毫秒），默认60000（1分钟）
func TimestampMiddleware(
	logger *slog.Logger,
	nonceStore NonceStore,
	tolerance, futureTolerance int64,
	defaultExpiration time.Duration,
	opts ...TimestampOption,
) gin.HandlerFunc {
	// 设置默认值
	if tolerance <= 0 {
		tolerance = 300000 // 默认5分钟
	}
	if futureTolerance <= 0 {
		futureTolerance = 60000 // 默认1分钟
	}

	cfg := defaultTimestampConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	return func(c *gin.Context) {
		// 检查是否匹配受保护的路由前缀
		if cfg.routePrefix != "" && !strings.HasPrefix(c.Request.URL.Path, cfg.routePrefix) {
			c.Next()
			return
		}

		ctx := c.Request.Context()

		if isNilNonceStore(nonceStore) {
			logger.ErrorContext(ctx, "nonce store is not configured")
			rErr := errorx.CodeConfigError.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		// 从请求头获取 X-Timestamp
		timestampStr := c.GetHeader("X-Timestamp")
		if timestampStr == "" {
			logger.ErrorContext(ctx, "请求缺少 X-Timestamp 头")
			rErr := errorx.CodeTimestampNotFound.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		// 从请求头获取 X-Nonce
		nonce := c.GetHeader("X-Nonce")
		if nonce == "" {
			logger.ErrorContext(ctx, "请求缺少 X-Nonce 头")
			rErr := errorx.CodeNonceNotFound.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		// 解析时间戳
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			logger.ErrorContext(ctx,
				"请求时间戳解释失败",
				slog.String("timestamp", timestampStr),
				slog.String("error", err.Error()),
			)
			rErr := errorx.CodeTimestampInvalid.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		// 验证时间戳范围（防止异常大的时间戳）
		now := time.Now().UnixMilli()

		// 检查时间戳是否过期
		if abs(now-timestamp) > tolerance || timestamp > now+futureTolerance {
			logger.ErrorContext(ctx,
				"时间戳超出允许范围",
				slog.Int64("current", now),
				slog.Int64("received", timestamp),
				slog.Int64("tolerance", tolerance),
				slog.Int64("difference", abs(now-timestamp)),
			)
			rErr := errorx.CodeTimestampExpired.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		// 原子写入 Nonce，防止并发重放竞态 (Check-Then-Act)
		if err := nonceStore.Add(nonce, struct{}{}, defaultExpiration); err != nil {
			logger.WarnContext(ctx,
				"检测到重复的请求，可能存在重放攻击",
				slog.String("nonce", nonce),
				slog.Int64("timestamp", timestamp),
				slog.String("method", c.Request.Method),
				slog.String("path", c.Request.URL.Path),
				slog.String("client_ip", c.ClientIP()),
				slog.Any("error", err),
			)
			rErr := errorx.CodeReplayAttack.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		c.Next()
	}
}

// abs 返回绝对值
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
