package middleware

import (
	"log/slog"
	"net"
	"strings"

	"github.com/gin-gonic/gin"

	"grain/pkg/errorx"
)

type hostRule struct {
	pattern string
	port    string
	hasPort bool
}

func parseHostPortRule(raw string) (host string, port string, hasPort bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if h, p, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(h, "[]"), p, true
	}
	return strings.Trim(raw, "[]"), "", false
}

func matchHostRule(rule hostRule, reqHost, reqPort string) bool {
	if rule.hasPort && rule.port != reqPort {
		return false
	}

	if rule.pattern == "*" {
		return true
	}

	if strings.HasPrefix(rule.pattern, "*.") {
		base := rule.pattern[2:]
		return reqHost == base || strings.HasSuffix(reqHost, "."+base)
	}

	return reqHost == rule.pattern
}

// HostGuard 中间件用于检查请求的 Host 头是否被允许
func HostGuard(logger *slog.Logger, allowedHosts ...string) gin.HandlerFunc {
	rules := make([]hostRule, 0, len(allowedHosts))
	for _, host := range allowedHosts {
		pattern, port, hasPort := parseHostPortRule(host)
		if pattern != "" {
			rules = append(rules, hostRule{
				pattern: pattern,
				port:    port,
				hasPort: hasPort,
			})
		}
	}

	return func(c *gin.Context) {
		rawHost := c.Request.Host
		if rawHost == "" {
			logger.WarnContext(
				c.Request.Context(),
				"请求缺少 Host 头",
				slog.String("remote_ip", c.ClientIP()),
				slog.String("method", c.Request.Method),
				slog.String("path", c.Request.URL.Path),
			)
			rErr := errorx.CodeHostHeaderInvalid.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		reqHost, reqPort, _ := parseHostPortRule(rawHost)
		matched := false
		for _, rule := range rules {
			if matchHostRule(rule, reqHost, reqPort) {
				matched = true
				break
			}
		}

		if !matched {
			logger.WarnContext(
				c.Request.Context(),
				"请求头不被允许",
				slog.String("host", rawHost),
				slog.String("remote_ip", c.ClientIP()),
				slog.String("method", c.Request.Method),
				slog.String("path", c.Request.URL.Path),
			)
			rErr := errorx.CodeHostHeaderInvalid.Error()
			errorx.RespondWithError(c, rErr)
			return
		}
		c.Next()
	}
}
