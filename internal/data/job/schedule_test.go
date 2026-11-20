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

func TestScheduleRepo_CRUD(t *testing.T) {
	data := setupTestData(t)
	scriptRepo := NewScriptRepo(data, slog.Default())
	repo := NewScheduleRepo(data, slog.Default())
	ctx := context.Background()

	script, err := scriptRepo.Create(ctx, &biz.Script{Name: "deploy", Project: "web", Label: "release"})
	require.NoError(t, err)

	// 1. Create with nested objects; IDs should be resolved.
	created, err := repo.Create(ctx, &biz.Schedule{
		Name:          "nightly-deploy",
		Specification: "0 2 * * *",
		IsEnabled:     true,
		Timeout:       300,
		Script:        script,
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
	assert.Equal(t, "nightly-deploy", found.Name)
	assert.Equal(t, "deploy", found.Script.Name)

	// 3. Bulk Creates
	bulk, err := repo.Creates(ctx, []biz.Schedule{
		{Name: "weekly-report", Specification: "0 6 * * 1", ScriptID: script.ID},
		{Name: "hourly-check", Specification: "0 * * * *", IsEnabled: true, ScriptID: script.ID},
	})
	require.NoError(t, err)
	require.Len(t, bulk, 2)
	assert.NotZero(t, bulk[0].ID)
	assert.NotZero(t, bulk[1].ID)
	assert.NotEqual(t, bulk[0].ID, bulk[1].ID)

	empty, err := repo.Creates(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, empty)

	// 4. Update
	created.IsEnabled = false
	created.MaxRetries = 5
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.False(t, updated.IsEnabled)
	assert.Equal(t, 5, updated.MaxRetries)

	// 4.1 Batch update
	bulk[0].MaxRetries = 1
	bulk[0].IsRetry = true
	bulk[1].MaxRetries = 2
	bulk[1].IsRetry = true
	batchUpdated, err := repo.Updates(ctx, bulk)
	require.NoError(t, err)
	require.Len(t, batchUpdated, 2)
	assert.Equal(t, bulk[0].ID, batchUpdated[0].ID)
	assert.Equal(t, 1, batchUpdated[0].MaxRetries)
	assert.True(t, batchUpdated[0].IsRetry)
	assert.Equal(t, bulk[1].ID, batchUpdated[1].ID)
	assert.Equal(t, 2, batchUpdated[1].MaxRetries)
	assert.True(t, batchUpdated[1].IsRetry)

	emptyUpdates, err := repo.Updates(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, emptyUpdates)

	// 5. List with filter
	list, total, err := repo.List(ctx, db.ListOptions{
		PageSize: 10,
		Filters: []db.ListFilter{
			{Field: "is_enabled", Op: db.ListFilterEquals, Value: true},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)
	assert.Equal(t, bulk[1].ID, list[0].ID)
	require.NotNil(t, list[0].Script)

	// 6. FindByIDs
	byIDs, err := repo.FindByIDs(ctx, []uint64{created.ID, bulk[0].ID})
	require.NoError(t, err)
	assert.Len(t, byIDs, 2)

	// 7. Duplicate name is rejected by the unique index.
	_, err = repo.Create(ctx, &biz.Schedule{Name: "nightly-deploy", ScriptID: script.ID})
	require.Error(t, err)

	// 8. Delete one by ID
	err = repo.Delete(ctx, created.ID)
	require.NoError(t, err)

	deleted, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Nil(t, deleted)

	err = repo.Delete(ctx, created.ID)
	require.Error(t, err)

	// 8.1 Batch update is atomic: a missing record rolls back every update.
	bulk[0].Name = "must-not-apply"
	_, err = repo.Updates(ctx, []biz.Schedule{
		bulk[0],
		{ID: 9999, Name: "missing", Specification: "0 * * * *", ScriptID: script.ID},
	})
	require.Error(t, err)
	unchanged, err := repo.FindByID(ctx, bulk[0].ID)
	require.NoError(t, err)
	require.NotNil(t, unchanged)
	assert.NotEqual(t, "must-not-apply", unchanged.Name)

	// 9. Batch delete the remaining records
	err = repo.DeleteByIDS(ctx, []uint64{bulk[0].ID, 9999})
	require.Error(t, err)
	stillPresent, err := repo.FindByID(ctx, bulk[0].ID)
	require.NoError(t, err)
	require.NotNil(t, stillPresent, "a failed batch delete must not remove existing rows")

	err = repo.DeleteByIDS(ctx, []uint64{bulk[0].ID, bulk[1].ID})
	require.NoError(t, err)

	for _, id := range []uint64{bulk[0].ID, bulk[1].ID} {
		deleted, findErr := repo.FindByID(ctx, id)
		require.NoError(t, findErr)
		assert.Nil(t, deleted)
	}

	emptyDelete, err := repo.FindByIDs(ctx, []uint64{bulk[0].ID, bulk[1].ID})
	require.NoError(t, err)
	assert.Empty(t, emptyDelete)

	err = repo.DeleteByIDS(ctx, []uint64{bulk[0].ID})
	require.Error(t, err)
}

func TestScheduleRepo_Validation(t *testing.T) {
	repo := NewScheduleRepo(setupTestData(t), slog.Default())
	ctx := context.Background()

	_, err := repo.Create(ctx, nil)
	require.Error(t, err)

	_, err = repo.Create(ctx, &biz.Schedule{})
	require.Error(t, err)

	_, err = repo.Update(ctx, &biz.Schedule{Name: "no-id"})
	require.Error(t, err)

	_, err = repo.Creates(ctx, []biz.Schedule{{Specification: "0 * * * *"}})
	require.Error(t, err)

	_, err = repo.Updates(ctx, []biz.Schedule{{Name: "no-id"}})
	require.Error(t, err)

	_, err = repo.Updates(ctx, []biz.Schedule{{ID: 9999, Name: "missing"}})
	require.Error(t, err)

	err = repo.DeleteByIDS(ctx, nil)
	require.NoError(t, err)

	err = repo.DeleteByIDS(ctx, []uint64{0})
	require.Error(t, err)

	err = repo.DeleteByIDS(ctx, []uint64{9999})
	require.Error(t, err)
}
