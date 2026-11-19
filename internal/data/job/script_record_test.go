package job

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	biz "grain/internal/biz/job"
	"grain/pkg/db"
)

func TestScriptRecordRepo_CRUD(t *testing.T) {
	data := setupTestData(t)
	scriptRepo := NewScriptRepo(data, slog.Default())
	repo := NewScriptRecordRepo(data, slog.Default())
	ctx := context.Background()

	script, err := scriptRepo.Create(ctx, &biz.Script{Name: "deploy", Project: "web", Label: "release"})
	require.NoError(t, err)

	// 1. Create, resolving IDs from the nested objects.
	created, err := repo.Create(ctx, &biz.ScriptRecord{
		TriggerType: "api",
		Status:      1,
		EnvVars:     `{"ENV":"prod"}`,
		ScriptArgs:  `["--force"]`,
		WorkDir:     "/opt/app",
		Timeout:     120,
		Username:    "alice",
		Script:      script,
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)
	assert.Equal(t, script.ID, created.ScriptID)

	// 2. FindByID preloads Script.
	found, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	require.NotNil(t, found.Script)
	assert.Equal(t, "deploy", found.Script.Name)

	// 3. Update
	err = repo.Update(ctx, created.ID, 2, 0, "")
	require.NoError(t, err)

	// 4. FindByIDs
	byIDs, err := repo.FindByIDs(ctx, []uint64{created.ID})
	require.NoError(t, err)
	require.Len(t, byIDs, 1)
	require.NotNil(t, byIDs[0].Script)

	// 5. List with filter and preloads
	second, err := repo.Create(ctx, &biz.ScriptRecord{
		TriggerType: "cron",
		Status:      3,
		ScriptID:    script.ID,
	})
	require.NoError(t, err)

	list, total, err := repo.List(ctx, db.ListOptions{
		PageSize: 10,
		Filters: []db.ListFilter{
			{Field: "script_id", Op: db.ListFilterEquals, Value: script.ID},
			{Field: "status", Op: db.ListFilterEquals, Value: 2},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)
	assert.Equal(t, created.ID, list[0].ID)
	require.NotNil(t, list[0].Script)

	all, total, err := repo.List(ctx, db.ListOptions{PageSize: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, all, 2)
	// Default ordering is newest first.
	assert.Equal(t, second.ID, all[0].ID)

	// 6. Not found / invalid update
	notFound, err := repo.FindByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, notFound)

	err = repo.Update(ctx, 99999, 2, 0, "")
	require.Error(t, err)
}

func TestScriptRecordRepo_Validation(t *testing.T) {
	repo := NewScriptRecordRepo(setupTestData(t), slog.Default())
	ctx := context.Background()

	_, err := repo.Create(ctx, nil)
	require.Error(t, err)
}
