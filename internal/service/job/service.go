package job

import (
	"log/slog"

	biz "grain/internal/biz/job"
)

// Service exposes script, schedule and execution-record use cases over HTTP.
type Service struct {
	scripts   *biz.ScriptUseCase
	schedules *biz.ScheduleUseCase
	records   *biz.ScriptRecordUseCache
	logger    *slog.Logger
	runSlots  chan struct{}
}

// NewService creates the job HTTP service.
func NewService(
	scripts *biz.ScriptUseCase,
	schedules *biz.ScheduleUseCase,
	records *biz.ScriptRecordUseCache,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		scripts:   scripts,
		schedules: schedules,
		records:   records,
		logger:    logger,
		runSlots:  make(chan struct{}, 20),
	}
}

// Scripts returns the script use case.
func (s *Service) Scripts() *biz.ScriptUseCase { return s.scripts }

// Schedules returns the schedule use case.
func (s *Service) Schedules() *biz.ScheduleUseCase { return s.schedules }

// Records returns the execution-record use case.
func (s *Service) Records() *biz.ScriptRecordUseCache { return s.records }
