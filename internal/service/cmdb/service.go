package cmdb

import (
	"log/slog"

	biz "grain/internal/biz/cmdb"
)

// Service exposes the CMDB host use cases over HTTP.
type Service struct {
	host   *biz.HostUseCase
	logger *slog.Logger
}

// NewService creates a CMDB HTTP service.
func NewService(host *biz.HostUseCase, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{host: host, logger: logger}
}

// Host returns the underlying host use case (used by wiring and tests).
func (s *Service) Host() *biz.HostUseCase {
	return s.host
}
