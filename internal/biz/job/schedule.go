package job

import (
	"context"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"

	"grain/pkg/db"
)

// Schedule is the schedule domain model (Domain Object - DO).
type Schedule struct {
	ID            uint64
	Name          string
	Specification string
	IsEnabled     bool
	EnvVars       string
	ScriptArgs    string
	WorkDir       string
	Timeout       int
	IsRetry       bool
	RetryInterval int
	MaxRetries    int
	Username      string
	ScriptID      uint64
	Script        *Script
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ScheduleRepo is the schedule repository interface contract.
type ScheduleRepo interface {
	Create(ctx context.Context, schedule *Schedule) (*Schedule, error)
	Creates(ctx context.Context, schedules []Schedule) ([]Schedule, error)
	Update(ctx context.Context, schedule *Schedule) (*Schedule, error)
	// Updates(ctx context.Context, schedule []Schedule) ([]Schedule, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64) (*Schedule, error)
	FindByIDs(ctx context.Context, ids []uint64) ([]Schedule, error)
	List(ctx context.Context, opts db.ListOptions) ([]Schedule, int64, error)
}

type ScheduleUseCase struct {
	scheduleRepo ScheduleRepo
	scriptRepo   ScriptRepo
	recordUC     *ScriptRecordUseCache
	logger       *slog.Logger
	crontab      *cron.Cron
	entryMap     map[uint64]cron.EntryID
	// mutex        sync.RWMutex
}

func MewScheduleUseCase(
	scheduleRepo ScheduleRepo,
	scriptRepo ScriptRepo,
	recordUC *ScriptRecordUseCache,
	logger *slog.Logger,
	crontab *cron.Cron,
) *ScheduleUseCase {
	return &ScheduleUseCase{
		scheduleRepo: scheduleRepo,
		scriptRepo:   scriptRepo,
		recordUC:     recordUC,
		logger:       logger,
		crontab:      crontab,
		entryMap:     make(map[uint64]cron.EntryID),
	}
}
