package job

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/internal/conf"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// scheduleUseCaseTestRepo is an in-memory ScheduleRepo for schedule use-case
// tests. It supports the is_enabled filter and offset/page-size pagination.
type scheduleUseCaseTestRepo struct {
	mu         sync.Mutex
	items      map[uint64]*Schedule
	nextID     uint64
	createErr  error
	createsErr error
	updateErr  error
	deleteErr  error
	findErr    error
	listErr    error
}

func newScheduleUseCaseTestRepo() *scheduleUseCaseTestRepo {
	return &scheduleUseCaseTestRepo{
		items:  make(map[uint64]*Schedule),
		nextID: 1,
	}
}

func (r *scheduleUseCaseTestRepo) Create(_ context.Context, schedule *Schedule) (*Schedule, error) {
	if r.createErr != nil {
		return nil, r.createErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := *schedule
	if cp.ID == 0 {
		cp.ID = r.nextID
		r.nextID++
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = time.Now()
	r.items[cp.ID] = &cp
	return r.copyLocked(cp.ID), nil
}

func (r *scheduleUseCaseTestRepo) Creates(_ context.Context, schedules []Schedule) ([]Schedule, error) {
	if r.createsErr != nil {
		return nil, r.createsErr
	}
	result := make([]Schedule, 0, len(schedules))
	for i := range schedules {
		created, err := r.Create(context.Background(), &schedules[i])
		if err != nil {
			return nil, err
		}
		result = append(result, *created)
	}
	return result, nil
}

func (r *scheduleUseCaseTestRepo) Update(_ context.Context, schedule *Schedule) (*Schedule, error) {
	if r.updateErr != nil {
		return nil, r.updateErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.items[schedule.ID]; !ok {
		return nil, errorx.CodeRecordNotFound.Error("record not found")
	}
	cp := *schedule
	cp.CreatedAt = r.items[schedule.ID].CreatedAt
	cp.UpdatedAt = time.Now()
	r.items[cp.ID] = &cp
	return r.copyLocked(cp.ID), nil
}

func (r *scheduleUseCaseTestRepo) Updates(_ context.Context, schedules []Schedule) ([]Schedule, error) {
	if r.updateErr != nil {
		return nil, r.updateErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range schedules {
		if _, ok := r.items[schedules[i].ID]; !ok {
			return nil, errorx.CodeRecordNotFound.Error("record not found")
		}
	}
	now := time.Now()
	result := make([]Schedule, 0, len(schedules))
	for i := range schedules {
		cp := schedules[i]
		cp.CreatedAt = r.items[cp.ID].CreatedAt
		cp.UpdatedAt = now
		r.items[cp.ID] = &cp
		result = append(result, cp)
	}
	return result, nil
}

func (r *scheduleUseCaseTestRepo) Delete(ctx context.Context, id uint64) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.items[id]; !ok {
		return errorx.CodeRecordNotFound.Error("record not found")
	}

	delete(r.items, id)
	return nil
}

func (r *scheduleUseCaseTestRepo) DeleteByIDS(_ context.Context, ids []uint64) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, id := range ids {
		if _, ok := r.items[id]; !ok {
			return errorx.CodeRecordNotFound.Error("record not found")
		}
	}
	for _, id := range ids {
		delete(r.items, id)
	}
	return nil
}

func (r *scheduleUseCaseTestRepo) FindByID(_ context.Context, id uint64) (*Schedule, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.copyLocked(id), nil
}

func (r *scheduleUseCaseTestRepo) FindByIDs(_ context.Context, ids []uint64) ([]Schedule, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]Schedule, 0, len(ids))
	for _, id := range ids {
		if schedule := r.copyLocked(id); schedule != nil {
			result = append(result, *schedule)
		}
	}
	return result, nil
}

func (r *scheduleUseCaseTestRepo) List(_ context.Context, opts db.ListOptions) ([]Schedule, int64, error) {
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	all := make([]Schedule, 0, len(r.items))
	for _, item := range r.items {
		if !matchScheduleTestFilters(item, opts.Filters) {
			continue
		}
		all = append(all, *item)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	total := int64(len(all))
	start := opts.Offset
	if start > len(all) {
		start = len(all)
	}
	end := start + opts.PageSize
	if opts.PageSize <= 0 || end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

func (r *scheduleUseCaseTestRepo) copyLocked(id uint64) *Schedule {
	item, ok := r.items[id]
	if !ok {
		return nil
	}
	cp := *item
	return &cp
}

func matchScheduleTestFilters(schedule *Schedule, filters []db.ListFilter) bool {
	for _, filter := range filters {
		if filter.Field != "is_enabled" {
			continue
		}
		want, ok := filter.Value.(bool)
		if ok && schedule.IsEnabled != want {
			return false
		}
	}
	return true
}

func newScheduleUseCaseTestFixture(t *testing.T) (*ScheduleUseCase, *scheduleUseCaseTestRepo, *mockScriptRepo, *Script, *cron.Cron) {
	t.Helper()

	scriptRepo := newMockScriptRepo()
	script, err := scriptRepo.Create(context.Background(), &Script{
		Project: "demo", Label: "ops", Name: "hello", Language: "sh", Status: true,
	})
	require.NoError(t, err)

	scheduleRepo := newScheduleUseCaseTestRepo()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scheduler := cron.New(cron.WithLogger(cron.DiscardLogger))
	recordUC := NewScriptRecordUseCache(scriptRepo, newMockScriptRecordRepo(), logger, 2)
	uc := NewScheduleUseCase(scheduleRepo, scriptRepo, recordUC, logger, scheduler)
	t.Cleanup(uc.Stop)

	return uc, scheduleRepo, scriptRepo, script, scheduler
}

func TestScheduleUseCaseBehavior_CRUD(t *testing.T) {
	uc, repo, _, script, scheduler := newScheduleUseCaseTestFixture(t)
	ctx := context.Background()

	created, err := uc.Create(ctx, &Schedule{
		Name:          "  nightly  ",
		Specification: "0 2 * * *",
		IsEnabled:     true,
		ScriptID:      script.ID,
		Username:      " admin ",
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)
	assert.Equal(t, "nightly", created.Name)
	assert.Equal(t, "admin", created.Username)
	assert.Equal(t, defaultExecScriptTimeoutSec, created.Timeout)
	assert.Len(t, scheduler.Entries(), 1)
	assert.Len(t, uc.entryMap, 1)

	got, err := uc.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)

	byIDs, err := uc.GetByIDs(ctx, []uint64{created.ID})
	require.NoError(t, err)
	assert.Len(t, byIDs, 1)

	list, total, err := uc.List(ctx, db.ListOptions{PageSize: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)

	created.Name = "nightly-updated"
	created.IsEnabled = false
	updated, err := uc.Update(ctx, created)
	require.NoError(t, err)
	assert.Equal(t, "nightly-updated", updated.Name)
	assert.False(t, updated.IsEnabled)
	assert.Empty(t, scheduler.Entries())

	require.NoError(t, uc.Enable(ctx, created.ID))
	assert.Len(t, scheduler.Entries(), 1)

	require.NoError(t, uc.Disable(ctx, created.ID))
	assert.Empty(t, scheduler.Entries())

	require.NoError(t, uc.Delete(ctx, created.ID))
	assert.Empty(t, scheduler.Entries())

	_, err = uc.Get(ctx, created.ID)
	assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

	err = uc.Delete(ctx, created.ID)
	assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

	assert.Empty(t, repo.items)
}

func TestScheduleUseCaseBehavior_BulkOperations(t *testing.T) {
	uc, _, _, script, scheduler := newScheduleUseCaseTestFixture(t)
	ctx := context.Background()

	first, err := uc.Create(ctx, &Schedule{
		Name: "bulk-1", Specification: "0 1 * * *", IsEnabled: true,
		ScriptID: script.ID, Username: "admin",
	})
	require.NoError(t, err)
	second, err := uc.Create(ctx, &Schedule{
		Name: "bulk-2", Specification: "0 2 * * *", IsEnabled: true,
		ScriptID: script.ID, Username: "admin",
	})
	require.NoError(t, err)
	assert.Len(t, scheduler.Entries(), 2)

	first.Name = "bulk-1-updated"
	first.IsEnabled = false
	second.Name = "bulk-2-updated"
	second.Specification = "0 3 * * *"
	second.IsRetry = true
	second.MaxRetries = 5

	updated, err := uc.Updates(ctx, []Schedule{*first, *second})
	require.NoError(t, err)
	require.Len(t, updated, 2)
	assert.Equal(t, "bulk-1-updated", updated[0].Name)
	assert.False(t, updated[0].IsEnabled)
	assert.Equal(t, "bulk-2-updated", updated[1].Name)
	assert.Equal(t, 5, updated[1].MaxRetries)
	assert.Len(t, scheduler.Entries(), 1)

	storedFirst, err := uc.Get(ctx, first.ID)
	require.NoError(t, err)
	assert.Equal(t, "bulk-1-updated", storedFirst.Name)
	assert.False(t, storedFirst.IsEnabled)

	emptyUpdates, err := uc.Updates(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, emptyUpdates)

	_, err = uc.Updates(ctx, []Schedule{{
		ID: first.ID, Name: "invalid", Specification: "not a cron", ScriptID: script.ID,
	}})
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

	_, err = uc.Updates(ctx, []Schedule{{
		ID: 9999, Name: "missing", Specification: "0 * * * *", ScriptID: script.ID,
	}})
	assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
}

func TestScheduleUseCaseBehavior_Validation(t *testing.T) {
	uc, repo, scriptRepo, script, _ := newScheduleUseCaseTestFixture(t)
	ctx := context.Background()

	_, err := uc.Create(ctx, nil)
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

	_, err = uc.Create(ctx, &Schedule{Specification: "0 * * * *", ScriptID: script.ID})
	assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

	_, err = uc.Create(ctx, &Schedule{Name: "bad-spec", Specification: "not a cron", ScriptID: script.ID})
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

	_, err = uc.Create(ctx, &Schedule{Name: "no-script", Specification: "0 * * * *"})
	assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

	_, err = uc.Create(ctx, &Schedule{
		Name: "bad-env", Specification: "0 * * * *", ScriptID: script.ID, EnvVars: "{bad",
	})
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

	disabled, err := scriptRepo.Create(ctx, &Script{
		Project: "demo", Label: "ops", Name: "disabled", Language: "sh", Status: false,
	})
	require.NoError(t, err)
	_, err = uc.Create(ctx, &Schedule{
		Name: "disabled-script", Specification: "0 * * * *", ScriptID: disabled.ID,
	})
	assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

	_, err = uc.Update(ctx, &Schedule{ID: 999, Name: "missing", Specification: "0 * * * *", ScriptID: script.ID})
	assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

	err = uc.SetEnabled(ctx, 999, true)
	assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

	_, err = uc.Get(ctx, 0)
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

	err = uc.Run(ctx, 0)
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

	// Enabled schedules require a configured scheduler.
	noCron := NewScheduleUseCase(repo, scriptRepo, nil, nil, nil)
	_, err = noCron.Create(ctx, &Schedule{
		Name: "needs-cron", Specification: "0 * * * *", ScriptID: script.ID, IsEnabled: true,
	})
	assert.True(t, errorx.IsCode(err, errorx.CodeConfigError))
}

func TestScheduleUseCaseBehavior_Reload(t *testing.T) {
	uc, repo, _, script, scheduler := newScheduleUseCaseTestFixture(t)
	ctx := context.Background()

	repo.items[1] = &Schedule{
		ID: 1, Name: "enabled", Specification: "0 0 1 1 *", IsEnabled: true,
		ScriptID: script.ID, Username: "admin",
	}
	repo.items[2] = &Schedule{
		ID: 2, Name: "disabled", Specification: "0 0 1 1 *", IsEnabled: false,
		ScriptID: script.ID, Username: "admin",
	}

	require.NoError(t, uc.Start(ctx))
	assert.Len(t, scheduler.Entries(), 1)

	repo.items[3] = &Schedule{
		ID: 3, Name: "enabled-2", Specification: "0 0 2 1 *", IsEnabled: true,
		ScriptID: script.ID, Username: "admin",
	}
	require.NoError(t, uc.Reload(ctx))
	assert.Len(t, scheduler.Entries(), 2)

	uc.Stop()
	assert.Empty(t, scheduler.Entries())

	require.NoError(t, uc.Start(ctx))
	assert.Len(t, scheduler.Entries(), 2)

	// An invalid stored specification is reported but does not prevent the
	// remaining schedules from being registered.
	repo.items[4] = &Schedule{
		ID: 4, Name: "invalid", Specification: "bad spec", IsEnabled: true,
		ScriptID: script.ID, Username: "admin",
	}
	err := uc.Reload(ctx)
	require.Error(t, err)
	assert.Len(t, scheduler.Entries(), 2)
}

func TestScheduleUseCaseBehavior_RunSuccess(t *testing.T) {
	uc, recordRepo := newScheduleRunFixture(t, "exit 0\n", false, 0)
	ctx := context.Background()

	require.NoError(t, uc.Run(ctx, 1))

	records := recordRepo.snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, ScriptRecordStatusSuccess, records[0].Status)
	assert.Equal(t, 0, records[0].ExitCode)
	assert.Equal(t, TriggerTypeCron, records[0].TriggerType)
}

func TestScheduleUseCaseBehavior_RunRetry(t *testing.T) {
	uc, recordRepo := newScheduleRunFixture(t, "exit 7\n", true, 2)
	ctx := context.Background()

	err := uc.Run(ctx, 1)
	require.Error(t, err)

	records := recordRepo.snapshot()
	require.Len(t, records, 3)
	for _, record := range records {
		assert.Equal(t, ScriptRecordStatusFailed, record.Status)
		assert.Equal(t, 7, record.ExitCode)
	}
}

func TestScheduleUseCaseBehavior_RunMissing(t *testing.T) {
	uc, _, _, _, _ := newScheduleUseCaseTestFixture(t)

	_, err := uc.Get(context.Background(), 0)
	assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

	err = uc.Run(context.Background(), 999)
	assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
}

// scheduleRunRecordRepo attaches the script to new records so the execution
// path can resolve the script file, mirroring the real repository preload.
type scheduleRunRecordRepo struct {
	*mockScriptRecordRepo
	scripts map[uint64]*Script
}

func (r *scheduleRunRecordRepo) Create(ctx context.Context, record *ScriptRecord) (*ScriptRecord, error) {
	if record.Script == nil {
		if script := r.scripts[record.ScriptID]; script != nil {
			cp := *record
			cp.Script = script
			record = &cp
		}
	}
	return r.mockScriptRecordRepo.Create(ctx, record)
}

func (r *scheduleRunRecordRepo) snapshot() []ScriptRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ScriptRecord, 0, len(r.records))
	for _, record := range r.records {
		result = append(result, *record)
	}
	return result
}

func newScheduleRunFixture(
	t *testing.T,
	scriptBody string,
	enableRetry bool,
	maxRetries int,
) (*ScheduleUseCase, *scheduleRunRecordRepo) {
	t.Helper()

	oldStorageDir := conf.StorageDir
	oldBaseDir := conf.BaseDir
	conf.StorageDir = t.TempDir()
	conf.BaseDir = conf.StorageDir
	t.Cleanup(func() {
		conf.StorageDir = oldStorageDir
		conf.BaseDir = oldBaseDir
	})

	scriptRepo := newMockScriptRepo()
	script, err := scriptRepo.Create(context.Background(), &Script{
		Project: "demo", Label: "ops", Name: "scheduled", Language: "sh", Status: true,
	})
	require.NoError(t, err)

	scriptPath, err := scriptDiskPath(script)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(scriptPath), 0o750))
	require.NoError(t, os.WriteFile(scriptPath, []byte("#!/bin/sh\n"+scriptBody), 0o700))

	recordRepo := &scheduleRunRecordRepo{
		mockScriptRecordRepo: newMockScriptRecordRepo(),
		scripts:              map[uint64]*Script{script.ID: script},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	recordUC := NewScriptRecordUseCache(scriptRepo, recordRepo, logger, 2)

	scheduleRepo := newScheduleUseCaseTestRepo()
	schedule := &Schedule{
		ID:            1,
		Name:          "run-now",
		Specification: "0 0 1 1 *",
		IsEnabled:     true,
		ScriptID:      script.ID,
		Username:      "tester",
		Timeout:       5,
		IsRetry:       enableRetry,
		MaxRetries:    maxRetries,
		RetryInterval: 0,
	}
	scheduleRepo.items[schedule.ID] = schedule

	uc := NewScheduleUseCase(scheduleRepo, scriptRepo, recordUC, logger, cron.New(cron.WithLogger(cron.DiscardLogger)))
	t.Cleanup(uc.Stop)
	return uc, recordRepo
}
