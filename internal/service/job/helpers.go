package job

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"grain/pkg/auth"
	"grain/pkg/errorx"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// currentUsername resolves the authenticated username from the request context.
func currentUsername(ctx context.Context) (string, error) {
	claims, err := auth.GetJwtClaims(ctx)
	if err != nil {
		return "", errorx.CodeAuthFailed.Error("无法获取当前登录用户")
	}
	username := strings.TrimSpace(claims.Username)
	if username == "" {
		return "", errorx.CodeAuthFailed.Error("当前登录用户缺少用户名")
	}
	return username, nil
}

// validateEnvVars ensures the client-provided env_vars value is a flat JSON
// object with POSIX-compatible variable names. Local executions do not go
// through the remote command builder, so this check must happen here.
func validateEnvVars(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var env map[string]string
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return errorx.CodeInvalidParam.Error("env_vars 必须是字符串键值对 JSON 对象")
	}
	for name := range env {
		if !envNamePattern.MatchString(name) {
			return errorx.CodeInvalidParam.Error("env_vars 包含非法变量名: " + name)
		}
	}
	return nil
}
