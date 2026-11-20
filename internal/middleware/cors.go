package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"grain/internal/conf"
)

var (
	defaultAllowMethods  = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
	defaultAllowHeaders  = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Trace-ID", "X-Timestamp", "X-Nonce"}
	defaultExposeHeaders = []string{"X-Trace-ID", "X-Cost-MS", "Retry-After"}
)

// CorsMiddleware 跨域中间件。
//
// 未配置（cfg == nil）时保留历史行为：允许任意来源且不带凭证。
// 显式配置但 allow_origins 为空时不发送任何 CORS 头（仅同源），避免
// “留空即放开所有来源”的隐患。
func CorsMiddleware(cfg *conf.AllowConfig) gin.HandlerFunc {
	allowOrigins := []string{"*"}
	allowCredentials := false
	allowMethods := defaultAllowMethods
	allowHeaders := defaultAllowHeaders
	exposeHeaders := defaultExposeHeaders

	if cfg != nil {
		allowOrigins = cfg.AllowOrigins
		allowCredentials = cfg.AllowCredentials
		if len(cfg.AllowMethods) > 0 {
			allowMethods = cfg.AllowMethods
		}
		if len(cfg.AllowHeaders) > 0 {
			allowHeaders = cfg.AllowHeaders
		}
		if len(cfg.ExposeHeaders) > 0 {
			exposeHeaders = cfg.ExposeHeaders
		}
	}

	// 预处理允许的源
	allowAllOrigins := false
	specificOrigins := make(map[string]bool)

	for _, origin := range allowOrigins {
		if origin == "*" {
			allowAllOrigins = true
			break
		}
		specificOrigins[origin] = true
	}

	// "*" + credentials 是规范禁止且危险的组合（等价于关闭同源策略）。
	// conf.Validate 会在启动时拒绝该配置；这里再做一次 fail-closed，避免
	// 直接构造中间件的调用方（测试、未来接入方）复现漏洞。
	if allowAllOrigins && allowCredentials {
		allowAllOrigins = false
		specificOrigins = make(map[string]bool)
	}

	allowMethodsStr := strings.Join(allowMethods, ", ")
	allowHeadersStr := strings.Join(allowHeaders, ", ")
	exposeHeadersStr := strings.Join(exposeHeaders, ", ")

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// 如果没有 Origin 头，跳过 CORS 处理
		if origin == "" {
			c.Next()
			return
		}

		// 检查是否允许该源
		allowed := allowAllOrigins || specificOrigins[origin]

		// 如果不允许该源，跳过 CORS 头设置
		if !allowed {
			c.Next()
			return
		}

		// 携带凭据时规范禁止 Access-Control-Allow-Origin 使用通配符。
		if allowAllOrigins && !allowCredentials {
			c.Header("Access-Control-Allow-Origin", "*")
		} else {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		}

		if len(allowMethodsStr) > 0 {
			c.Header("Access-Control-Allow-Methods", allowMethodsStr)
		}

		if len(allowHeadersStr) > 0 {
			c.Header("Access-Control-Allow-Headers", allowHeadersStr)
		}

		if len(exposeHeadersStr) > 0 {
			c.Header("Access-Control-Expose-Headers", exposeHeadersStr)
		}

		if allowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// 处理预检请求
		if c.Request.Method == http.MethodOptions {
			c.Header("Access-Control-Max-Age", "86400")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
