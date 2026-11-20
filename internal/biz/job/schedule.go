package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"grain/pkg/db"
	"grain/pkg/errorx"
)

const (
	defaultScheduleRetryInterval = 60 // seconds between retries when unset
	defaultScheduleMaxRetries    = 3  // retries after the first attempt when enabled but unset
	defaultScheduleUsername      = "scheduler"
	scheduleLoadPageSize         = 100
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
	HostID        uint64
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
	Updates(ctx context.Context, schedule []Schedule) ([]Schedule, error)
	Delete(ctx context.Context, id uint64) error
	DeleteByIDS(ctx context.Context, ids []uint64) error
	FindByID(ctx context.Context, id uint64) (*Schedule, error)
	FindByIDs(ctx context.Context, ids []uint64) ([]Schedule, error)
	List(ctx context.Context, opts db.ListOptions) ([]Schedule, int64, error)
}

// ScheduleUseCase manages schedule metadata and keeps the cron registry in
// sync with enabled schedules.
type ScheduleUseCase struct {
	scheduleRepo ScheduleRepo
	scriptRepo   ScriptRepo
	recordUC     *ScriptRecordUseCache
	logger       *slog.Logger
	crontab      *cron.Cron

	mutex    sync.Mutex // guards entryMap and cron add/remove
	entryMap map[uint64]cron.EntryID

	runMu   sync.Mutex
	running map[uint64]struct{}
}

// NewScheduleUseCase creates a ScheduleUseCase.
func NewScheduleUseCase(
	scheduleRepo ScheduleRepo,
	scriptRepo ScriptRepo,
	recordUC *ScriptRecordUseCache,
	logger *slog.Logger,
	crontab *cron.Cron,
) *ScheduleUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	return &ScheduleUseCase{
		scheduleRepo: scheduleRepo,
		scriptRepo:   scriptRepo,
		recordUC:     recordUC,
		logger:       logger,
		crontab:      crontab,
		entryMap:     make(map[uint64]cron.EntryID),
		running:      make(map[uint64]struct{}),
	}
}

// MewScheduleUseCase is kept for backward compatibility with the original
// constructor name. Deprecated: use NewScheduleUseCase.
func MewScheduleUseCase(
	scheduleRepo ScheduleRepo,
	scriptRepo ScriptRepo,
	recordUC *ScriptRecordUseCache,
	logger *slog.Logger,
	crontab *cron.Cron,
) *ScheduleUseCase {
	return NewScheduleUseCase(scheduleRepo, scriptRepo, recordUC, logger, crontab)
}

// Create validates and persists a schedule, registering it with cron when it is
// enabled.
func (uc *ScheduleUseCase) Create(ctx context.Context, schedule *Schedule) (*Schedule, error) {
	if err := uc.validateSchedule(ctx, schedule); err != nil {
		return nil, err
	}
	if schedule.IsEnabled {
		if err := uc.schedulerRequired(); err != nil {
			return nil, err
		}
	}

	created, err := uc.scheduleRepo.Create(ctx, schedule)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	if err := uc.register(created); err != nil {
		// Do not leave an enabled schedule persisted without a cron entry.
		if delErr := uc.scheduleRepo.Delete(ctx, created.ID); delErr != nil {
			uc.log().ErrorContext(ctx, "计划任务:注册失败后回滚记录失败",
				slog.Any("error", delErr),
				slog.Uint64("schedule_id", created.ID),
			)
		}
		return nil, err
	}
	return created, nil
}

// Creates validates and bulk-inserts schedules, registering the enabled ones.
func (uc *ScheduleUseCase) Creates(ctx context.Context, schedules []Schedule) ([]Schedule, error) {
	if len(schedules) == 0 {
		return nil, nil
	}
	for i := range schedules {
		if err := uc.validateSchedule(ctx, &schedules[i]); err != nil {
			return nil, fmt.Errorf("第%d条计划任务无效: %w", i+1, err)
		}
		if schedules[i].IsEnabled {
			if err := uc.schedulerRequired(); err != nil {
				return nil, err
			}
		}
	}

	created, err := uc.scheduleRepo.Creates(ctx, schedules)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	for i := range created {
		if err := uc.register(&created[i]); err != nil {
			return nil, err
		}
	}
	return created, nil
}

// Update replaces an existing schedule and re-registers it when its definition
// or enabled state changed.
func (uc *ScheduleUseCase) Update(ctx context.Context, schedule *Schedule) (*Schedule, error) {
	if schedule == nil || schedule.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的计划任务ID")
	}
	if err := uc.validateSchedule(ctx, schedule); err != nil {
		return nil, err
	}
	if schedule.IsEnabled {
		if err := uc.schedulerRequired(); err != nil {
			return nil, err
		}
	}

	existing, err := uc.scheduleRepo.FindByID(ctx, schedule.ID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if existing == nil {
		return nil, errorx.CodeRecordNotFound.Error("计划任务不存在")
	}

	updated, err := uc.scheduleRepo.Update(ctx, schedule)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if err := uc.register(updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// Updates validates and batch-updates schedules in a single transaction,
// re-registering each enabled entry with cron.
func (uc *ScheduleUseCase) Updates(ctx context.Context, schedules []Schedule) ([]Schedule, error) {
	if len(schedules) == 0 {
		return nil, nil
	}
	for i := range schedules {
		if schedules[i].ID == 0 {
			return nil, fmt.Errorf("第%d条计划任务无效: %w", i+1,
				errorx.CodeInvalidParam.Error("无效的计划任务ID"))
		}
		if err := uc.validateSchedule(ctx, &schedules[i]); err != nil {
			return nil, fmt.Errorf("第%d条计划任务无效: %w", i+1, err)
		}
		if schedules[i].IsEnabled {
			if err := uc.schedulerRequired(); err != nil {
				return nil, err
			}
		}
	}

	updated, err := uc.scheduleRepo.Updates(ctx, schedules)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	for i := range updated {
		if err := uc.register(&updated[i]); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// Delete removes a schedule and its cron entry.
func (uc *ScheduleUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的计划任务ID")
	}

	schedule, err := uc.scheduleRepo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if schedule == nil {
		return errorx.CodeRecordNotFound.Error("计划任务不存在")
	}

	if err := uc.scheduleRepo.Delete(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}
	uc.unregister(id)
	return nil
}

// Deletes removes multiple schedules and their cron entries in one batch.
func (uc *ScheduleUseCase) DeleteByIDS(ctx context.Context, ids []uint64) error {
	if len(ids) == 0 {
		return nil
	}

	uniqueIDs := make([]uint64, 0, len(ids))
	seen := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		if id == 0 {
			return errorx.CodeInvalidParam.Error("无效的计划任务ID")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}

	if err := uc.scheduleRepo.DeleteByIDS(ctx, uniqueIDs); err != nil {
		return errorx.FromDBError(err)
	}
	for _, id := range uniqueIDs {
		uc.unregister(id)
	}
	return nil
}

// Get returns a schedule by ID.
func (uc *ScheduleUseCase) Get(ctx context.Context, id uint64) (*Schedule, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的计划任务ID")
	}

	schedule, err := uc.scheduleRepo.FindByID(ctx, id)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if schedule == nil {
		return nil, errorx.CodeRecordNotFound.Error("计划任务不存在")
	}
	return schedule, nil
}

// GetByIDs returns schedules for the given IDs.
func (uc *ScheduleUseCase) GetByIDs(ctx context.Context, ids []uint64) ([]Schedule, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	schedules, err := uc.scheduleRepo.FindByIDs(ctx, ids)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return schedules, nil
}

// List lists schedules with pagination, filters, and ordering.
func (uc *ScheduleUseCase) List(ctx context.Context, opts db.ListOptions) ([]Schedule, int64, error) {
	schedules, total, err := uc.scheduleRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return schedules, total, nil
}

// SetEnabled toggles a schedule and keeps the cron registry consistent.
func (uc *ScheduleUseCase) SetEnabled(ctx context.Context, id uint64, enabled bool) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的计划任务ID")
	}
	if enabled {
		if err := uc.schedulerRequired(); err != nil {
			return err
		}
	}

	schedule, err := uc.scheduleRepo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if schedule == nil {
		return errorx.CodeRecordNotFound.Error("计划任务不存在")
	}

	if schedule.IsEnabled != enabled {
		schedule.IsEnabled = enabled
		updated, upErr := uc.scheduleRepo.Update(ctx, schedule)
		if upErr != nil {
			return errorx.FromDBError(upErr)
		}
		schedule = updated
	}
	return uc.register(schedule)
}

// Enable enables a schedule.
func (uc *ScheduleUseCase) Enable(ctx context.Context, id uint64) error {
	return uc.SetEnabled(ctx, id, true)
}

// Disable disables a schedule.
func (uc *ScheduleUseCase) Disable(ctx context.Context, id uint64) error {
	return uc.SetEnabled(ctx, id, false)
}

// Start loads all enabled schedules into cron and starts the scheduler. It is
// safe to call Start more than once.
func (uc *ScheduleUseCase) Start(ctx context.Context) error {
	return uc.Reload(ctx)
}

// Stop removes all cron entries and stops the scheduler.
func (uc *ScheduleUseCase) Stop() {
	uc.unregisterAll()
	if uc.crontab != nil {
		uc.crontab.Stop()
	}
}

// Reload clears the cron registry and re-registers every enabled schedule.
func (uc *ScheduleUseCase) Reload(ctx context.Context) error {
	if err := uc.schedulerRequired(); err != nil {
		return err
	}

	schedules, err := uc.loadEnabledSchedules(ctx)
	if err != nil {
		return err
	}

	// Keep the previous registry if loading from the database failed.
	uc.unregisterAll()

	var errs []error
	for i := range schedules {
		if !schedules[i].IsEnabled {
			continue
		}
		if regErr := uc.register(&schedules[i]); regErr != nil {
			errs = append(errs, fmt.Errorf("计划任务 %d(%s): %w",
				schedules[i].ID, schedules[i].Name, regErr))
		}
	}

	uc.crontab.Start()
	return errors.Join(errs...)
}

// Run executes a schedule immediately, including its retry policy. It is used
// by manual triggers and by the cron callback.
func (uc *ScheduleUseCase) Run(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的计划任务ID")
	}
	if uc.scheduleRepo == nil {
		return errorx.CodeConfigError.Error("计划任务仓储未初始化")
	}

	schedule, err := uc.scheduleRepo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if schedule == nil {
		return errorx.CodeRecordNotFound.Error("计划任务不存在")
	}
	if !uc.beginRun(id) {
		return errorx.CodeRateLimitExceeded.Error("计划任务正在执行中，请稍后重试")
	}
	defer uc.endRun(id)
	return uc.executeSchedule(ctx, schedule)
}

// beginRun prevents the same schedule from running twice at once (cron overlap
// or a manual trigger racing a cron tick).
func (uc *ScheduleUseCase) beginRun(id uint64) bool {
	uc.runMu.Lock()
	defer uc.runMu.Unlock()
	if _, exists := uc.running[id]; exists {
		return false
	}
	uc.running[id] = struct{}{}
	return true
}

func (uc *ScheduleUseCase) endRun(id uint64) {
	uc.runMu.Lock()
	delete(uc.running, id)
	uc.runMu.Unlock()
}

// RunNow is an alias for Run.
func (uc *ScheduleUseCase) RunNow(ctx context.Context, id uint64) error {
	return uc.Run(ctx, id)
}

// ==================== internals ====================

func (uc *ScheduleUseCase) log() *slog.Logger {
	if uc.logger == nil {
		return slog.Default()
	}
	return uc.logger
}

func (uc *ScheduleUseCase) validateSchedule(ctx context.Context, schedule *Schedule) error {
	if schedule == nil {
		return errorx.CodeInvalidParam.Error("计划任务不能为空")
	}

	schedule.Name = strings.TrimSpace(schedule.Name)
	schedule.Specification = strings.TrimSpace(schedule.Specification)
	schedule.Username = strings.TrimSpace(schedule.Username)

	if schedule.Name == "" {
		return errorx.CodeMissingParam.Error("计划任务名称不能为空")
	}
	if schedule.Specification == "" {
		return errorx.CodeMissingParam.Error("cron表达式不能为空")
	}
	if _, err := cron.ParseStandard(schedule.Specification); err != nil {
		return errorx.CodeInvalidParam.Errorf("cron表达式无效: %v", err)
	}

	if schedule.ScriptID == 0 && schedule.Script != nil {
		schedule.ScriptID = schedule.Script.ID
	}
	if schedule.ScriptID == 0 {
		return errorx.CodeMissingParam.Error("计划任务必须指定执行脚本")
	}
	if schedule.Username == "" {
		schedule.Username = defaultScheduleUsername
	}
	if schedule.Timeout <= 0 {
		schedule.Timeout = defaultExecScriptTimeoutSec
	}
	if schedule.RetryInterval <= 0 {
		schedule.RetryInterval = defaultScheduleRetryInterval
	}
	if schedule.MaxRetries < 0 {
		schedule.MaxRetries = 0
	}
	if schedule.IsRetry && schedule.MaxRetries == 0 {
		schedule.MaxRetries = defaultScheduleMaxRetries
	}
	if err := validateScheduleEnvVars(schedule.EnvVars); err != nil {
		return err
	}

	return uc.ensureScriptAvailable(ctx, schedule.ScriptID)
}

func validateScheduleEnvVars(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var envVars map[string]string
	if err := json.Unmarshal([]byte(raw), &envVars); err != nil {
		return errorx.CodeInvalidParam.Errorf("环境变量必须是JSON对象: %v", err)
	}
	return nil
}

// ensureScriptAvailable rejects schedules pointing at missing or disabled
// scripts. A nil scriptRepo skips the check (useful for lightweight tests).
func (uc *ScheduleUseCase) ensureScriptAvailable(ctx context.Context, scriptID uint64) error {
	if uc.scriptRepo == nil {
		return nil
	}

	script, err := uc.scriptRepo.FindByID(ctx, scriptID)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if script == nil {
		return errorx.CodeRecordNotFound.Error("关联脚本不存在")
	}
	if !script.Status {
		return errorx.CodeMissingParam.Error("该脚本已被禁用")
	}
	return nil
}

func (uc *ScheduleUseCase) schedulerRequired() error {
	if uc.crontab == nil {
		return errorx.CodeConfigError.Error("定时任务调度器未初始化")
	}
	if uc.scheduleRepo == nil {
		return errorx.CodeConfigError.Error("计划任务仓储未初始化")
	}
	return nil
}

// loadEnabledSchedules pages through the repository so startup is not limited
// by a single page.
func (uc *ScheduleUseCase) loadEnabledSchedules(ctx context.Context) ([]Schedule, error) {
	var schedules []Schedule
	for offset := 0; ; offset += scheduleLoadPageSize {
		batch, total, err := uc.scheduleRepo.List(ctx, db.ListOptions{
			Offset:   offset,
			PageSize: scheduleLoadPageSize,
			Filters: []db.ListFilter{
				{Field: "is_enabled", Op: db.ListFilterEquals, Value: true},
			},
		})
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		schedules = append(schedules, batch...)
		if len(batch) == 0 || int64(offset+len(batch)) >= total {
			break
		}
	}
	return schedules, nil
}

// register adds (or replaces) the cron entry for a schedule. Disabled schedules
// are unregistered.
func (uc *ScheduleUseCase) register(schedule *Schedule) error {
	if schedule == nil || schedule.ID == 0 {
		return errorx.CodeInvalidParam.Error("无效的计划任务")
	}
	if !schedule.IsEnabled {
		uc.unregister(schedule.ID)
		return nil
	}
	if uc.crontab == nil {
		return errorx.CodeConfigError.Error("定时任务调度器未初始化")
	}

	spec := strings.TrimSpace(schedule.Specification)
	if spec == "" {
		return errorx.CodeMissingParam.Error("cron表达式不能为空")
	}
	if _, err := cron.ParseStandard(spec); err != nil {
		return errorx.CodeInvalidParam.Errorf("cron表达式无效: %v", err)
	}

	id := schedule.ID
	uc.mutex.Lock()
	defer uc.mutex.Unlock()

	if uc.entryMap == nil {
		uc.entryMap = make(map[uint64]cron.EntryID)
	}
	if entryID, ok := uc.entryMap[id]; ok {
		uc.crontab.Remove(entryID)
		delete(uc.entryMap, id)
	}

	entryID, err := uc.crontab.AddFunc(spec, func() { uc.runScheduled(id) })
	if err != nil {
		return errorx.CodeInvalidParam.Errorf("注册计划任务失败: %v", err)
	}
	uc.entryMap[id] = entryID
	return nil
}

func (uc *ScheduleUseCase) unregister(id uint64) {
	uc.mutex.Lock()
	defer uc.mutex.Unlock()

	if uc.entryMap == nil {
		return
	}
	entryID, ok := uc.entryMap[id]
	if !ok {
		return
	}
	if uc.crontab != nil {
		uc.crontab.Remove(entryID)
	}
	delete(uc.entryMap, id)
}

func (uc *ScheduleUseCase) unregisterAll() {
	uc.mutex.Lock()
	defer uc.mutex.Unlock()

	if uc.entryMap == nil {
		return
	}
	for id, entryID := range uc.entryMap {
		if uc.crontab != nil {
			uc.crontab.Remove(entryID)
		}
		delete(uc.entryMap, id)
	}
}

// runScheduled is the cron callback. It reloads the schedule so deleted or
// disabled schedules do not run, then executes with retry handling.
func (uc *ScheduleUseCase) runScheduled(id uint64) {
	ctx := context.Background()
	defer func() {
		if recovered := recover(); recovered != nil {
			uc.log().ErrorContext(ctx, "计划任务:执行时发生panic",
				slog.Any("panic", recovered),
				slog.Uint64("schedule_id", id),
			)
		}
	}()

	if uc.scheduleRepo == nil {
		return
	}
	schedule, err := uc.scheduleRepo.FindByID(ctx, id)
	if err != nil {
		uc.log().ErrorContext(ctx, "计划任务:加载失败",
			slog.Any("error", err),
			slog.Uint64("schedule_id", id),
		)
		return
	}
	if schedule == nil || !schedule.IsEnabled {
		return
	}
	if !uc.beginRun(id) {
		uc.log().WarnContext(ctx, "计划任务:上一次执行尚未结束，跳过本次调度",
			slog.Uint64("schedule_id", id),
			slog.String("schedule_name", schedule.Name),
		)
		return
	}
	defer uc.endRun(id)

	if err := uc.executeSchedule(ctx, schedule); err != nil {
		uc.log().ErrorContext(ctx, "计划任务:执行失败",
			slog.Any("error", err),
			slog.Uint64("schedule_id", id),
			slog.String("schedule_name", schedule.Name),
		)
	}
}

// executeSchedule creates one execution record per attempt and retries failed
// attempts according to the schedule's retry policy.
func (uc *ScheduleUseCase) executeSchedule(ctx context.Context, schedule *Schedule) error {
	if schedule == nil {
		return errorx.CodeInvalidParam.Error("计划任务不能为空")
	}
	if uc.recordUC == nil {
		return errorx.CodeConfigError.Error("脚本执行记录服务未初始化")
	}

	attempts := 1
	if schedule.IsRetry && schedule.MaxRetries > 0 {
		attempts += schedule.MaxRetries
	}
	retryInterval := time.Duration(schedule.RetryInterval) * time.Second
	if retryInterval < 0 {
		retryInterval = 0
	}

	username := schedule.Username
	if username == "" {
		username = defaultScheduleUsername
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		execInfo := &ExecuteInfo{
			TriggerType: TriggerTypeCron,
			ScriptID:    schedule.ScriptID,
			ScriptArgs:  schedule.ScriptArgs,
			EnvVars:     schedule.EnvVars,
			Timeout:     schedule.Timeout,
			WorkDir:     schedule.WorkDir,
			Username:    username,
			HostID:      schedule.HostID,
		}

		record, err := uc.recordUC.Create(ctx, execInfo)
		if err == nil && record == nil {
			err = errorx.CodeRecordNotFound.Error("创建脚本执行记录失败")
		}
		if err == nil {
			_, err = uc.recordUC.Execute(ctx, record)
		}

		if err == nil {
			uc.log().InfoContext(ctx, "计划任务:执行成功",
				slog.Uint64("schedule_id", schedule.ID),
				slog.String("schedule_name", schedule.Name),
				slog.Int("attempt", attempt),
			)
			return nil
		}

		lastErr = err
		uc.log().ErrorContext(ctx, "计划任务:执行失败",
			slog.Any("error", err),
			slog.Uint64("schedule_id", schedule.ID),
			slog.String("schedule_name", schedule.Name),
			slog.Int("attempt", attempt),
			slog.Int("max_attempts", attempts),
		)

		if attempt >= attempts {
			break
		}
		if retryInterval > 0 {
			timer := time.NewTimer(retryInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return lastErr
}
