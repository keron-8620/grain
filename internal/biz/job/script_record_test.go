package job

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/internal/conf"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// mockScriptRecordRepo is an in-memory ScriptRecordRepo for testing.
type mockScriptRecordRepo struct {
	mu         sync.RWMutex
	records    map[uint64]*ScriptRecord
	nextID     uint64
	createErr  error
	updateErr  error
	findErr    error
	listErr    error
	panicOnUpd bool
}

func newMockScriptRecordRepo() *mockScriptRecordRepo {
	return &mockScriptRecordRepo{
		records: make(map[uint64]*ScriptRecord),
		nextID:  1,
	}
}

func (m *mockScriptRecordRepo) Create(_ context.Context, sr *ScriptRecord) (*ScriptRecord, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *sr
	cp.ID = m.nextID
	cp.CreatedAt = time.Now()
	cp.UpdatedAt = cp.CreatedAt
	m.nextID++
	m.records[cp.ID] = &cp
	return &cp, nil
}

func (m *mockScriptRecordRepo) Update(_ context.Context, id uint64, status, code int, msg string) error {
	if m.panicOnUpd {
		m.panicOnUpd = false
		panic("mock database connection panic")
	}
	if m.updateErr != nil {
		return m.updateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.records[id]; ok {
		r.Status = ScriptRecordStatus(status)
		r.ExitCode = code
		r.ErrorMessage = msg
		r.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockScriptRecordRepo) FindByID(_ context.Context, id uint64) (*ScriptRecord, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.records[id]
	if !ok {
		return nil, nil
	}
	return r, nil
}

func (m *mockScriptRecordRepo) FindByIDs(_ context.Context, ids []uint64) ([]ScriptRecord, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]ScriptRecord, 0, len(ids))
	for _, id := range ids {
		if r, ok := m.records[id]; ok {
			res = append(res, *r)
		}
	}
	return res, nil
}

func (m *mockScriptRecordRepo) List(_ context.Context, _ db.ListOptions) ([]ScriptRecord, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]ScriptRecord, 0, len(m.records))
	for _, r := range m.records {
		res = append(res, *r)
	}
	return res, int64(len(res)), nil
}

func newScriptRecordFixture(t *testing.T, maxConcurrent int) (*mockScriptRepo, *mockScriptRecordRepo, *ScriptRecordUseCache, string) {
	t.Helper()
	tmpDir := t.TempDir()

	oldStorageDir := conf.StorageDir
	oldBaseDir := conf.BaseDir
	conf.StorageDir = tmpDir
	conf.BaseDir = tmpDir
	t.Cleanup(func() {
		conf.StorageDir = oldStorageDir
		conf.BaseDir = oldBaseDir
	})

	sRepo := newMockScriptRepo() // 直接复用 script_test.go 中的 mockScriptRepo
	rRepo := newMockScriptRecordRepo()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	uc := NewScriptRecordUseCache(sRepo, rRepo, logger, maxConcurrent)

	return sRepo, rRepo, uc, tmpDir
}

func writeExecShellScript(t *testing.T, script *Script, body string) string {
	t.Helper()
	scriptPath, err := scriptDiskPath(script)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(scriptPath), 0750))
	content := "#!/bin/sh\n" + body + "\n"
	require.NoError(t, os.WriteFile(scriptPath, []byte(content), 0750))
	return scriptPath
}

func TestScriptRecordUseCache_Execute_Success(t *testing.T) {
	_, rRepo, uc, tmpDir := newScriptRecordFixture(t, 2)
	ctx := context.Background()

	script := &Script{
		ID:       100,
		Project:  "demo",
		Label:    "ops",
		Name:     "hello",
		Language: "shell",
		Status:   true,
	}
	writeExecShellScript(t, script, `
echo "ARG1=$1 ARG2=$2"
echo "CUSTOM_ENV=$CUSTOM_ENV"
echo "JOB_RECORD_ID=$JOB_RECORD_ID"
echo "PWD=$(pwd)"
exit 0
`)

	workDir := filepath.Join(tmpDir, "custom_workdir")
	rec, err := rRepo.Create(ctx, &ScriptRecord{
		TriggerType: TriggerTypeAPI,
		Status:      ScriptRecordStatusPending,
		ExitCode:    -1,
		ScriptID:    script.ID,
		Script:      script,
		ScriptArgs:  "hello world",
		EnvVars:     `{"CUSTOM_ENV":"secret_val"}`,
		WorkDir:     workDir,
		LogName:     "success.log",
		Timeout:     10,
	})
	require.NoError(t, err)

	got, execErr := uc.Execute(ctx, rec)
	require.NoError(t, execErr)
	assert.Equal(t, ScriptRecordStatusSuccess, got.Status)
	assert.Equal(t, 0, got.ExitCode)
	assert.Nil(t, uc.GetCancel(got.ID))

	// 验证日志文件落盘内容
	logBytes, err := os.ReadFile(GenerateScriptLogPath(got.CreatedAt, got.LogName))
	require.NoError(t, err)
	logStr := string(logBytes)

	assert.Contains(t, logStr, "ARG1=hello ARG2=world")
	assert.Contains(t, logStr, "CUSTOM_ENV=secret_val")
	assert.Contains(t, logStr, fmt.Sprintf("JOB_RECORD_ID=%d", got.ID))
	assert.Contains(t, logStr, "PWD="+workDir)
	assert.Contains(t, logStr, "脚本执行成功")
}

func TestScriptRecordUseCache_Execute_FailedExitCode(t *testing.T) {
	_, rRepo, uc, _ := newScriptRecordFixture(t, 2)
	ctx := context.Background()

	script := &Script{
		ID:       101,
		Project:  "demo",
		Label:    "ops",
		Name:     "fail_script",
		Language: "sh",
		Status:   true,
	}
	writeExecShellScript(t, script, `
echo "something went wrong" >&2
exit 42
`)

	rec, err := rRepo.Create(ctx, &ScriptRecord{
		Status:   ScriptRecordStatusPending,
		ExitCode: -1,
		ScriptID: script.ID,
		Script:   script,
		LogName:  "failed.log",
		Timeout:  10,
	})
	require.NoError(t, err)

	got, execErr := uc.Execute(ctx, rec)
	require.Error(t, execErr)
	assert.Equal(t, ScriptRecordStatusFailed, got.Status)
	assert.Equal(t, 42, got.ExitCode)
	assert.NotEmpty(t, got.ErrorMessage)
}

func TestScriptRecordUseCache_Execute_Timeout(t *testing.T) {
	_, rRepo, uc, _ := newScriptRecordFixture(t, 2)
	ctx := context.Background()

	script := &Script{
		ID:       102,
		Project:  "demo",
		Label:    "ops",
		Name:     "timeout_script",
		Language: "bash",
		Status:   true,
	}
	writeExecShellScript(t, script, `
trap 'exit 0' TERM
sleep 10
`)

	rec, err := rRepo.Create(ctx, &ScriptRecord{
		Status:   ScriptRecordStatusPending,
		ExitCode: -1,
		ScriptID: script.ID,
		Script:   script,
		LogName:  "timeout.log",
		Timeout:  1,
	})
	require.NoError(t, err)

	start := time.Now()
	got, execErr := uc.Execute(ctx, rec)
	require.Error(t, execErr)
	assert.Equal(t, ScriptRecordStatusTimeout, got.Status)
	assert.Less(t, time.Since(start), 6*time.Second)

	dbRec, err := rRepo.FindByID(ctx, got.ID)
	require.NoError(t, err)
	assert.Equal(t, ScriptRecordStatusTimeout, dbRec.Status)
}

func TestScriptRecordUseCache_Execute_ManualCancel(t *testing.T) {
	_, rRepo, uc, _ := newScriptRecordFixture(t, 2)
	ctx := context.Background()

	script := &Script{
		ID:       103,
		Project:  "demo",
		Label:    "ops",
		Name:     "cancel_script",
		Language: "sh",
		Status:   true,
	}
	writeExecShellScript(t, script, `
trap 'exit 0' TERM
sleep 30
`)

	rec, err := rRepo.Create(ctx, &ScriptRecord{
		Status:   ScriptRecordStatusPending,
		ExitCode: -1,
		ScriptID: script.ID,
		Script:   script,
		LogName:  "cancel.log",
		Timeout:  60,
	})
	require.NoError(t, err)

	done := make(chan struct{})
	var got *ScriptRecord
	go func() {
		defer close(done)
		got, _ = uc.Execute(ctx, rec)
	}()

	require.Eventually(t, func() bool {
		return uc.GetCancel(rec.ID) != nil
	}, 2*time.Second, 20*time.Millisecond)
	time.Sleep(100 * time.Millisecond)

	uc.Cancel(ctx, rec.ID)
	<-done

	assert.Equal(t, ScriptRecordStatusCancel, got.Status)
	dbRec, err := rRepo.FindByID(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, ScriptRecordStatusCancel, dbRec.Status)
}

func TestScriptRecordUseCache_Execute_CancelWhileWaitingSemaphore(t *testing.T) {
	_, rRepo, uc, _ := newScriptRecordFixture(t, 1)
	ctx := context.Background()

	script := &Script{
		ID:       104,
		Project:  "demo",
		Label:    "ops",
		Name:     "sem_script",
		Language: "sh",
		Status:   true,
	}
	writeExecShellScript(t, script, `sleep 2`)

	rec1, err := rRepo.Create(ctx, &ScriptRecord{ScriptID: script.ID, Script: script, LogName: "sem1.log", Timeout: 10})
	require.NoError(t, err)
	rec2, err := rRepo.Create(ctx, &ScriptRecord{ScriptID: script.ID, Script: script, LogName: "sem2.log", Timeout: 10})
	require.NoError(t, err)

	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		_, _ = uc.Execute(ctx, rec1)
	}()
	time.Sleep(100 * time.Millisecond)

	done2 := make(chan struct{})
	var got2 *ScriptRecord
	go func() {
		defer close(done2)
		got2, _ = uc.Execute(ctx, rec2)
	}()

	time.Sleep(100 * time.Millisecond)
	uc.Cancel(ctx, rec2.ID)
	<-done2
	<-done1

	assert.Equal(t, ScriptRecordStatusCancel, got2.Status)
	assert.Contains(t, got2.ErrorMessage, "等待执行并发额度时任务已取消")
}

func TestScriptRecordUseCache_Execute_EdgeCasesAndPanic(t *testing.T) {
	_, rRepo, uc, _ := newScriptRecordFixture(t, 2)
	ctx := context.Background()

	t.Run("nil record", func(t *testing.T) {
		got, err := uc.Execute(ctx, nil)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("invalid script path", func(t *testing.T) {
		badScript := &Script{ID: 998, Project: "../escape", Label: "ops", Name: "bad", Status: true}
		rec, err := rRepo.Create(ctx, &ScriptRecord{ScriptID: badScript.ID, Script: badScript, LogName: "bad.log", Timeout: 10})
		require.NoError(t, err)

		got, err := uc.Execute(ctx, rec)
		require.Error(t, err)
		assert.Equal(t, ScriptRecordStatusCrashed, got.Status)
	})

	t.Run("script file not exist", func(t *testing.T) {
		missing := &Script{ID: 999, Project: "demo", Label: "ops", Name: "missing", Language: "sh", Status: true}
		rec, err := rRepo.Create(ctx, &ScriptRecord{ScriptID: missing.ID, Script: missing, LogName: "missing.log", Timeout: 10})
		require.NoError(t, err)

		got, err := uc.Execute(ctx, rec)
		require.Error(t, err)
		assert.Equal(t, ScriptRecordStatusCrashed, got.Status)
	})

	t.Run("panic recovery", func(t *testing.T) {
		script := &Script{ID: 105, Project: "demo", Label: "ops", Name: "panic_script", Language: "sh", Status: true}
		writeExecShellScript(t, script, `exit 0`)

		rec, err := rRepo.Create(ctx, &ScriptRecord{ScriptID: script.ID, Script: script, LogName: "panic.log", Timeout: 10})
		require.NoError(t, err)

		rRepo.panicOnUpd = true
		t.Cleanup(func() { rRepo.panicOnUpd = false })

		got, err := uc.Execute(ctx, rec)
		require.Error(t, err)
		require.NotNil(t, got)
		assert.Equal(t, ScriptRecordStatusCrashed, got.Status)
		assert.Contains(t, got.ErrorMessage, "mock database connection panic")
		assert.Nil(t, uc.GetCancel(rec.ID))
	})
}

func TestScriptRecordUseCache_CRUD(t *testing.T) {
	sRepo, _, uc, _ := newScriptRecordFixture(t, 2)
	ctx := context.Background()

	s1, err := sRepo.Create(ctx, &Script{Project: "demo", Label: "ops", Name: "s1", Status: true})
	require.NoError(t, err)
	s2, err := sRepo.Create(ctx, &Script{Project: "demo", Label: "ops", Name: "s2", Status: false})
	require.NoError(t, err)

	t.Run("validation", func(t *testing.T) {
		_, err := uc.Create(ctx, nil)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Create(ctx, &ExecuteInfo{ScriptID: s1.ID})
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &ExecuteInfo{Username: "admin"})
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &ExecuteInfo{Username: "admin", ScriptID: 9999})
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

		_, err = uc.Create(ctx, &ExecuteInfo{Username: "admin", ScriptID: s2.ID})
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("create and query", func(t *testing.T) {
		created, err := uc.Create(ctx, &ExecuteInfo{
			TriggerType: TriggerTypeCron,
			ScriptID:    s1.ID,
			Username:    "admin",
			Timeout:     0,
		})
		require.NoError(t, err)
		assert.Equal(t, defaultExecScriptTimeoutSec, created.Timeout)
		assert.Equal(t, ScriptRecordStatusPending, created.Status)

		got, err := uc.Get(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, got.ID)

		_, err = uc.Get(ctx, 0)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Get(ctx, 9999)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

		batch, err := uc.GetByIDs(ctx, []uint64{created.ID})
		require.NoError(t, err)
		assert.Len(t, batch, 1)

		list, total, err := uc.List(ctx, db.ListOptions{})
		require.NoError(t, err)
		assert.EqualValues(t, 1, total)
		assert.Len(t, list, 1)
	})
}
