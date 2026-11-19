package cmdb

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	biz "grain/internal/biz/cmdb"
	"grain/pkg/db"
)

func TestHostRepo_CRUD(t *testing.T) {
	data := setupTestData(t)
	repo := NewHostRepo(data, slog.Default())
	ctx := context.Background()

	// 1. Create
	created, err := repo.Create(ctx, &biz.Host{
		Name:     "web-01",
		Label:    "production",
		HostIP:   "10.0.0.1",
		HostPort: 22,
		HostUser: "root",
		Protocol: "ssh",
		OSType:   "linux",
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)
	assert.Equal(t, "web-01", created.Name)
	assert.False(t, created.CreatedAt.IsZero())

	// 2. FindByID & FindByIDs
	found, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "10.0.0.1", found.HostIP)

	byIDs, err := repo.FindByIDs(ctx, []uint64{created.ID})
	require.NoError(t, err)
	assert.Len(t, byIDs, 1)

	empty, err := repo.FindByIDs(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, empty)

	// 3. ExistsByHostIPPortUser
	exists, err := repo.ExistsByHostIPPortUser(ctx, "10.0.0.1", 22, "root", nil)
	require.NoError(t, err)
	assert.True(t, exists)

	// Excluding the record itself yields no match.
	exists, err = repo.ExistsByHostIPPortUser(ctx, "10.0.0.1", 22, "root", []db.ListFilter{
		{Field: "id", Op: db.ListFilterNotEquals, Value: created.ID},
	})
	require.NoError(t, err)
	assert.False(t, exists)

	// 4. Update
	created.Remark = "updated remark"
	created.HostPort = 2222
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "updated remark", updated.Remark)
	assert.Equal(t, uint16(2222), updated.HostPort)

	// 5. List with filter and invalid order
	other, err := repo.Create(ctx, &biz.Host{
		Name:     "db-01",
		HostIP:   "10.0.0.2",
		HostPort: 22,
		HostUser: "root",
		Protocol: "ssh",
	})
	require.NoError(t, err)

	list, total, err := repo.List(ctx, db.ListOptions{
		PageSize: 10,
		Filters: []db.ListFilter{
			{Field: "name", Op: db.ListFilterContains, Value: "web"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)
	assert.Equal(t, created.ID, list[0].ID)

	_, _, err = repo.List(ctx, db.ListOptions{OrderBy: "id; DROP TABLE job_host"})
	require.Error(t, err)
	assert.ErrorIs(t, err, db.ErrInvalidListOption)

	// 6. Soft delete
	err = repo.Delete(ctx, created.ID)
	require.NoError(t, err)

	deleted, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Nil(t, deleted)

	list, total, err = repo.List(ctx, db.ListOptions{PageSize: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, other.ID, list[0].ID)

	// Deleted connection tuples are no longer considered in use.
	exists, err = repo.ExistsByHostIPPortUser(ctx, "10.0.0.1", 2222, "root", nil)
	require.NoError(t, err)
	assert.False(t, exists)

	// Deleting again reports not found.
	err = repo.Delete(ctx, created.ID)
	require.Error(t, err)
}

func TestHostRepo_Validation(t *testing.T) {
	repo := NewHostRepo(setupTestData(t), slog.Default())
	ctx := context.Background()

	_, err := repo.Create(ctx, nil)
	require.Error(t, err)

	_, err = repo.Create(ctx, &biz.Host{})
	require.Error(t, err)

	_, err = repo.Update(ctx, nil)
	require.Error(t, err)

	_, err = repo.Update(ctx, &biz.Host{Name: "missing-id"})
	require.Error(t, err)

	_, err = repo.ExistsByHostIPPortUser(ctx, "", 22, "root", nil)
	require.Error(t, err)
}
