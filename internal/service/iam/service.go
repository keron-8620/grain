package iam

import (
	"log/slog"

	biz "grain/internal/biz/iam"
	"grain/internal/service/common"
)

// Service 提供 IAM 模块的所有 HTTP 处理器实现
type Service struct {
	biz    *biz.Biz
	logger *slog.Logger
}

// NewService 创建 IAM 服务处理器实例
func NewService(b *biz.Biz, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		biz:    b,
		logger: logger,
	}
}

// Biz 返回注入的业务逻辑容器
func (s *Service) Biz() *biz.Biz {
	return s.biz
}

// 通用 HTTP 响应与参数解析工具委托自 common 包
var (
	Success         = common.Success
	SuccessMsg      = common.SuccessMsg
	Failure         = common.Failure
	parseUintID     = common.ParseUintID
	parsePagination = common.ParsePagination
)

