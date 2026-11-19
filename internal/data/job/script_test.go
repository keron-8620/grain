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

func TestScriptRepo_CRUD(t *testing.T) {
	data := setupTestData(t)
	repo := NewScriptRepo(data, slog.Default())
	ctx := context.Background()

	// 1. Create
	created, err := repo.Create(ctx, &biz.Script{
		Name:      "deploy",
		Descr:     "deploy application",
		ParamDesc: "target env",
		Project:   "web",
		Label:     "release",
		Language:  "python",
		Status:    true,
		Username:  "alice",
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)

	// 2. FindByID / FindByIDs / FindByProjectLableName
	found, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "release", found.Label)

	byIDs, err := repo.FindByIDs(ctx, []uint64{created.ID})
	require.NoError(t, err)
	assert.Len(t, byIDs, 1)

	byKey, err := repo.FindByProjectLableName(ctx, "web", "release", "deploy")
	require.NoError(t, err)
	require.NotNil(t, byKey)
	assert.Equal(t, created.ID, byKey.ID)

	missing, err := repo.FindByProjectLableName(ctx, "web", "release", "missing")
	require.NoError(t, err)
	assert.Nil(t, missing)

	// 3. Update
	created.Descr = "deploy application v2"
	created.Status = false
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "deploy application v2", updated.Descr)
	assert.False(t, updated.Status)

	// 4. List filter
	_, err = repo.Create(ctx, &biz.Script{
		Name:    "cleanup",
		Project: "web",
		Label:   "maintenance",
		Status:  true,
	})
	require.NoError(t, err)

	list, total, err := repo.List(ctx, db.ListOptions{
		PageSize: 10,
		Filters: []db.ListFilter{
			{Field: "project", Op: db.ListFilterEquals, Value: "web"},
			{Field: "status", Op: db.ListFilterEquals, Value: false},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)
	assert.Equal(t, created.ID, list[0].ID)

	// 5. Soft delete
	err = repo.Delete(ctx, created.ID)
	require.NoError(t, err)

	deleted, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestScriptRepo_Validation(t *testing.T) {
	repo := NewScriptRepo(setupTestData(t), slog.Default())
	ctx := context.Background()

	_, err := repo.Create(ctx, nil)
	require.Error(t, err)

	_, err = repo.Create(ctx, &biz.Script{})
	require.Error(t, err)

	_, err = repo.Update(ctx, &biz.Script{Name: "no-id"})
	require.Error(t, err)

	_, err = repo.FindByProjectLableName(ctx, "p", "l", "")
	require.NoError(t, err)
}
