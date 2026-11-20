package job

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	bizjob "grain/internal/biz/job"
	"grain/internal/conf"
	datajob "grain/internal/data/job"
	"grain/pkg/db"
)

func setupJobTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	c := &db.DBConf{
		Type:         "sqlite",
		Dsn:          fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString()),
		MaxIdleConns: 1,
		MaxOpenConns: 1,
	}
	gormDB, err := db.NewGormDB(c, db.NewGormConfig(nil))
	require.NoError(t, err)
	require.NoError(t, datajob.AutoMigrate(gormDB))
	return gormDB
}

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()

	root := t.TempDir()
	store, err := datajob.NewLocalScriptStore(root)
	require.NoError(t, err)

	originalStorage := conf.StorageDir
	conf.StorageDir = t.TempDir()
	t.Cleanup(func() { conf.StorageDir = originalStorage })

	gin.SetMode(gin.TestMode)
	srv, err := New(Options{
		GormDB:      setupJobTestDB(t),
		Bootstrap:   &conf.Bootstrap{},
		Crontab:     cron.New(),
		ScriptStore: store,
		ScriptRoot:  root,
	})
	require.NoError(t, err)
	return srv, root
}

func TestServer_New_RequiresDB(t *testing.T) {
	_, err := New(Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gorm DB is required")
}

func TestServer_RegistersJobRoutes(t *testing.T) {
	srv, _ := newTestServer(t)
	engine := gin.New()
	srv.RegisterRoutes(engine)

	routes := make(map[string]struct{}, len(engine.Routes()))
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}

	expected := []string{
		"POST /api/v1/scripts",
		"GET /api/v1/scripts/:id/content",
		"POST /api/v1/schedules/:id/run",
		"GET /api/v1/script-records",
		"POST /api/v1/script-records/:id/cancel",
		"GET /api/v1/script-records/:id/log",
	}
	for _, route := range expected {
		_, ok := routes[route]
		assert.True(t, ok, "route %q must be registered", route)
	}
}

func TestServer_LocalScriptExecution(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	script, err := srv.Scripts.Create(ctx, &bizjob.Script{
		Name:     "hello",
		Project:  "test",
		Label:    "demo",
		Language: "shell",
		Status:   true,
		Username: "tester",
	}, []byte("#!/bin/sh\necho hello-from-script\n"))
	require.NoError(t, err)

	record, err := srv.Records.Create(ctx, &bizjob.ExecuteInfo{
		TriggerType: bizjob.TriggerTypeAPI,
		ScriptID:    script.ID,
		Username:    "tester",
		Timeout:     30,
	})
	require.NoError(t, err)
	require.NotNil(t, record.Script, "Create must attach script metadata for execution")

	executed, err := srv.Records.Execute(ctx, record)
	require.NoError(t, err)
	assert.Equal(t, bizjob.ScriptRecordStatusSuccess, executed.Status)
	assert.Equal(t, 0, executed.ExitCode)

	logPath := bizjob.GenerateScriptLogPath(executed.CreatedAt, executed.LogName)
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(logData), "hello-from-script")
}

func TestServer_StartStopScheduler(t *testing.T) {
	srv, _ := newTestServer(t)

	require.NoError(t, srv.Start(context.Background()))
	srv.Stop()
}

func TestServer_ScriptUpdatePreservesContent(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	script, err := srv.Scripts.Create(ctx, &bizjob.Script{
		Name:     "keep",
		Project:  "test",
		Label:    "demo",
		Language: "shell",
		Status:   true,
		Username: "tester",
	}, []byte("#!/bin/sh\necho v1\n"))
	require.NoError(t, err)

	_, err = srv.Scripts.Update(ctx, &bizjob.Script{
		ID:       script.ID,
		Name:     "keep",
		Project:  "test",
		Label:    "demo",
		Language: "shell",
		Status:   true,
		Username: "tester",
	}, nil)
	require.NoError(t, err)

	content, err := srv.Scripts.GetContent(ctx, script.ID)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(content), "echo v1"))
}

func TestServer_RecoveryMarksInterruptedRecords(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	script, err := srv.Scripts.Create(ctx, &bizjob.Script{
		Name:     "recover",
		Project:  "test",
		Label:    "demo",
		Language: "shell",
		Status:   true,
		Username: "tester",
	}, []byte("#!/bin/sh\necho recover\n"))
	require.NoError(t, err)

	record, err := srv.Records.Create(ctx, &bizjob.ExecuteInfo{
		TriggerType: bizjob.TriggerTypeAPI,
		ScriptID:    script.ID,
		Username:    "tester",
	})
	require.NoError(t, err)
	require.Equal(t, bizjob.ScriptRecordStatusPending, record.Status)

	require.NoError(t, srv.Start(ctx))

	got, err := srv.Records.Get(ctx, record.ID)
	require.NoError(t, err)
	assert.Equal(t, bizjob.ScriptRecordStatusCrashed, got.Status)
	assert.Contains(t, got.ErrorMessage, "重启")

	srv.Stop()
}

func TestServer_StopRejectsNewExecutions(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.Stop()

	err := srv.Records.ExecuteAsync(context.Background(), &bizjob.ScriptRecord{
		ID:       999,
		Status:   bizjob.ScriptRecordStatusPending,
		ExitCode: -1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "关闭")
}

func TestServer_StopCancelsRunningExecution(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	script, err := srv.Scripts.Create(ctx, &bizjob.Script{
		Name:     "slow",
		Project:  "test",
		Label:    "demo",
		Language: "shell",
		Status:   true,
		Username: "tester",
	}, []byte("#!/bin/sh\nsleep 30\n"))
	require.NoError(t, err)

	record, err := srv.Records.Create(ctx, &bizjob.ExecuteInfo{
		TriggerType: bizjob.TriggerTypeAPI,
		ScriptID:    script.ID,
		Username:    "tester",
		Timeout:     60,
	})
	require.NoError(t, err)
	require.NoError(t, srv.Records.ExecuteAsync(ctx, record))

	deadline := time.Now().Add(3 * time.Second)
	for {
		got, getErr := srv.Records.Get(ctx, record.ID)
		require.NoError(t, getErr)
		if got.Status == bizjob.ScriptRecordStatusRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("execution did not start, status=%d", got.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Records.Stop(stopCtx)

	got, err := srv.Records.Get(ctx, record.ID)
	require.NoError(t, err)
	assert.Equal(t, bizjob.ScriptRecordStatusCancel, got.Status)
}
