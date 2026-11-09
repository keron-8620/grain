package middleware

import (
	"log/slog"
	"strings"

	"emperror.dev/errors"
	"github.com/casbin/casbin/v3"
	"github.com/gin-gonic/gin"

	"grain/pkg/auth"
	"grain/pkg/errorx"
	"grain/pkg/logx"
)

// extractToken 从不同位置提取 token
func extractToken(c *gin.Context) string {
	// 1. 从 Authorization 头提取：必须严格是 Bearer
	auth := c.GetHeader("Authorization")
	if token := strictBearerExtract(auth); token != "" {
		return token
	}

	// 2. WebSocket 场景：Authorization 头宽松匹配，再回退到子协议
	if strings.EqualFold(c.GetHeader("Upgrade"), "websocket") {
		if token := looseTokenExtract(auth); token != "" {
			return token
		}
		protocols := strings.Split(c.GetHeader("Sec-WebSocket-Protocol"), ",")
		if len(protocols) > 0 {
			first := strings.TrimSpace(protocols[0])
			if token := looseTokenExtract(first); token != "" {
				return token
			}
		}
	}
	return ""
}

// strictBearerExtract 仅用于标准头：非 Bearer 一律视为无效
func strictBearerExtract(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	fields := strings.Fields(value)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "Bearer") {
		return fields[1]
	}
	return ""
}

// looseTokenExtract 用于 WebSocket 回退：支持 Bearer，也支持纯 token
func looseTokenExtract(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	fields := strings.Fields(value)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "Bearer") {
		return fields[1] // 带了 Bearer 前缀，取后面的
	}
	return value // 没有 Bearer 前缀，把整个字符串当作 token
}

func JWTAuthMiddleware(logger *slog.Logger, au *auth.Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头获取token
		token := extractToken(c)
		if token == "" {
			rErr := errorx.CodeMissingAuth.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		ctx := c.Request.Context()

		if au == nil {
			logger.ErrorContext(ctx, "authenticator is not configured")
			rErr := errorx.CodeConfigError.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		// 身份认证
		claims, err := au.ParseAndVerifyTokenContext(ctx, token)
		if err != nil {
			logger.ErrorContext(ctx, err.Error(), slog.Any("error", err))
			rErr := errorx.CodeTokenInvalid.Error()
			if errors.Is(err, auth.ErrTokenExpired) {
				rErr = errorx.CodeTokenExpired.Error()
			} else if errors.Is(err, auth.ErrTokenTypeMismatch) {
				rErr = errorx.CodeTokenTypeMismatch.Error()
			} else if errors.Is(err, auth.ErrTokenEmpty) {
				rErr = errorx.CodeMissingAuth.Error()
			}
			errorx.RespondWithError(c, rErr)
			return
		}

		// 实时 Token 版本与吊销校验（Fail-Closed 原则）
		if err := au.VerifyTokenVersion(ctx, claims); err != nil {
			logger.ErrorContext(ctx, "token revocation check failed", slog.Any("error", err))
			rErr := errorx.CodeTokenInvalid.Error()
			switch {
			case errors.Is(err, auth.ErrTokenRevoked):
				rErr = errorx.CodeTokenInvalid.Error()
			case errors.Is(err, auth.ErrTokenVersionNotFound):
				rErr = errorx.CodeTokenInvalid.Error()
			case errors.Is(err, auth.ErrAuthConfigInvalid):
				rErr = errorx.CodeConfigError.Error()
			case auth.IsTokenVersionUnavailable(err):
				rErr = errorx.CodeCacheError.Error()
			}
			errorx.RespondWithError(c, rErr)
			return
		}

		newCtx := auth.SetJwtClaims(ctx, claims)
		newCtx = logx.ContextWithAttrs(newCtx, slog.Uint64("user_id", claims.UserID))
		c.Request = c.Request.WithContext(newCtx)
		c.Next()
	}
}

func CasbinAuthMiddleware(logger *slog.Logger, enforcer *casbin.SyncedEnforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		if enforcer == nil {
			logger.ErrorContext(ctx, "casbin enforcer is not configured")
			rErr := errorx.CodeConfigError.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		fullPath := c.FullPath()
		if fullPath == "" {
			logger.WarnContext(ctx, "route full path is empty (unmatched route)",
				slog.String("path", c.Request.URL.Path),
				slog.String("method", c.Request.Method),
			)
			rErr := errorx.CodeResourceNotFound.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		claims, err := auth.GetJwtClaims(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "获取JWT claims失败", slog.Any("error", err))
			rErr := errorx.CodeAuthFailed.Error()
			errorx.RespondWithError(c, rErr)
			return
		}

		role := auth.RoleToSubject(claims.RoleID)

		// 访问鉴权
		hasPerm, err := enforcer.Enforce(role, fullPath, c.Request.Method)
		if err != nil {
			logger.ErrorContext(ctx,
				"权限校验失败",
				slog.Any("error", err),
				slog.String("sub", role),
				slog.String("obj", fullPath),
				slog.String("act", c.Request.Method),
			)
			rErr := errorx.CodeUnknown.Error()
			errorx.RespondWithError(c, rErr)
			return
		}
		if !hasPerm {
			logger.ErrorContext(ctx,
				"权限被拒绝",
				slog.String("sub", role),
				slog.String("obj", fullPath),
				slog.String("act", c.Request.Method),
			)
			rErr := errorx.CodeForbidden.Error()
			errorx.RespondWithError(c, rErr)
			return
		}
		c.Next()
	}
}
