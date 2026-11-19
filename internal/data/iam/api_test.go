package iam

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	biz "grain/internal/biz/iam"
	"grain/pkg/auth"
	"grain/pkg/db"
	"grain/pkg/db/filter"
)

func TestApiRepo_Validation(t *testing.T) {
	ctx := context.Background()
	repo := NewApiRepo(&Data{}, slog.Default())

	t.Run("Create validation", func(t *testing.T) {
		_, err := repo.Create(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "model cannot be nil")

		_, err = repo.Create(ctx, &biz.Api{URL: ""})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "url and method cannot be empty")

		_, err = repo.Create(ctx, &biz.Api{URL: "/test", Method: ""})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "url and method cannot be empty")
	})

	t.Run("Update validation", func(t *testing.T) {
		_, err := repo.Update(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")

		_, err = repo.Update(ctx, &biz.Api{ID: 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")

		_, err = repo.Update(ctx, &biz.Api{ID: 1, URL: ""})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "url and method cannot be empty")
	})

	t.Run("Delete validation", func(t *testing.T) {
		err := repo.Delete(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID cannot be 0")
	})

	t.Run("FindByID validation", func(t *testing.T) {
		_, err := repo.FindByID(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID cannot be 0")
	})

	t.Run("FindByURLAndMethod validation", func(t *testing.T) {
		_, err := repo.FindByURLAndMethod(ctx, "", "GET")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL and method cannot be empty")

		_, err = repo.FindByURLAndMethod(ctx, "/api/v1/users", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL and method cannot be empty")
	})

	t.Run("AddPolicy validation", func(t *testing.T) {
		require.Error(t, repo.AddPolicy(ctx, nil))
		require.Error(t, repo.AddPolicy(ctx, &biz.Api{ID: 0}))
		require.Error(t, repo.AddPolicy(ctx, &biz.Api{ID: 1, URL: ""}))
		require.Error(t, repo.AddPolicy(ctx, &biz.Api{ID: 1, URL: "/api", Method: ""}))
	})

	t.Run("UpdatePolicy validation", func(t *testing.T) {
		apiValid := &biz.Api{ID: 1, URL: "/api", Method: "GET"}
		require.Error(t, repo.UpdatePolicy(ctx, nil, apiValid))
		require.Error(t, repo.UpdatePolicy(ctx, apiValid, nil))
		require.Error(t, repo.UpdatePolicy(ctx, &biz.Api{ID: 0, URL: "/api", Method: "GET"}, apiValid))
		require.Error(t, repo.UpdatePolicy(ctx, apiValid, &biz.Api{ID: 1, URL: "", Method: "GET"}))
	})

	t.Run("RemovePolicy validation", func(t *testing.T) {
		require.Error(t, repo.RemovePolicy(ctx, nil, false))
		require.Error(t, repo.RemovePolicy(ctx, &biz.Api{ID: 0}, false))
		require.Error(t, repo.RemovePolicy(ctx, &biz.Api{ID: 1, URL: ""}, false))
		require.Error(t, repo.RemovePolicy(ctx, &biz.Api{ID: 1, URL: "/api", Method: ""}, false))
	})
}

func TestApiRepo_CRUD(t *testing.T) {
	data, _, _, _ := setupTestData(t)
	repo := NewApiRepo(data, slog.Default())
	ctx := context.Background()

	// 1. Create API
	apiIn := &biz.Api{
		URL:    "/api/v1/users",
		Method: "get",
		Label:  "Get Users",
		Descr:  "Query user list",
	}
	created, err := repo.Create(ctx, apiIn)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)
	assert.Equal(t, "/api/v1/users", created.URL)
	assert.Equal(t, "GET", created.Method) // Method normalized to uppercase
	assert.Equal(t, "Get Users", created.Label)

	// 2. FindByID
	found, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "Get Users", found.Label)

	// FindByID non-existent returns (nil, nil)
	notFound, err := repo.FindByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, notFound)

	// 3. FindByURLAndMethod
	byURL, err := repo.FindByURLAndMethod(ctx, "/api/v1/users", "GET")
	require.NoError(t, err)
	require.NotNil(t, byURL)
	assert.Equal(t, created.ID, byURL.ID)

	// 4. FindByIDs
	api2, err := repo.Create(ctx, &biz.Api{
		URL:    "/api/v1/users/:id",
		Method: "DELETE",
		Label:  "Delete User",
	})
	require.NoError(t, err)

	byIDs, err := repo.FindByIDs(ctx, []uint64{created.ID, api2.ID})
	require.NoError(t, err)
	assert.Len(t, byIDs, 2)

	emptyIDs, err := repo.FindByIDs(ctx, []uint64{})
	require.NoError(t, err)
	assert.Nil(t, emptyIDs)

	// 5. Update
	created.Label = "Get Users Updated"
	created.Descr = "Updated description"
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "Get Users Updated", updated.Label)
	assert.Equal(t, "Updated description", updated.Descr)

	// Update non-existent returns error
	_, err = repo.Update(ctx, &biz.Api{ID: 99999, URL: "/none", Method: "GET"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record not found")

	// 6. List
	list, total, err := repo.List(ctx, db.ListOptions{
		PageSize: 10,
		Filters: []filter.ListFilter{
			{Field: "label", Op: filter.ListFilterContains, Value: "Updated"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)
	assert.Equal(t, created.ID, list[0].ID)

	// 7. SyncRoutes
	routes := []biz.ApiRoute{
		{URL: "/api/v1/roles", Method: "POST", Label: "Create Role"},
		{URL: "/api/v1/roles", Method: "POST", Label: "Duplicate"}, // Duplicate in input
		{URL: "/api/v1/users", Method: "GET", Label: "Existing"},   // Conflict in DB
	}
	synced, err := repo.SyncRoutes(ctx, routes)
	require.NoError(t, err)
	assert.Equal(t, 1, synced) // Only /api/v1/roles should be inserted

	// 7.1 FindByRoutes
	foundRoutes, err := repo.FindByRoutes(ctx, routes)
	require.NoError(t, err)
	assert.Len(t, foundRoutes, 2) // users and roles

	emptyRoutes, err := repo.FindByRoutes(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, emptyRoutes)

	// Empty sync routes short-circuit
	synced, err = repo.SyncRoutes(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, synced)

	// 8. Delete
	err = repo.Delete(ctx, created.ID)
	require.NoError(t, err)

	deleted, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Nil(t, deleted)

	// Delete non-existent returns error
	err = repo.Delete(ctx, 99999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record not found")
}

func TestApiRepo_CasbinPolicy(t *testing.T) {
	data, _, enf, _ := setupTestData(t)
	repo := NewApiRepo(data, slog.Default())
	ctx := context.Background()

	api := &biz.Api{
		ID:     10,
		URL:    "/api/v1/articles",
		Method: "GET",
	}

	// 1. AddPolicy
	err := repo.AddPolicy(ctx, api)
	require.NoError(t, err)

	sub := auth.ApiToSubject(api.ID)
	hasPolicy, err := enf.HasPolicy(sub, api.URL, api.Method)
	require.NoError(t, err)
	assert.True(t, hasPolicy)

	// 2. UpdatePolicy - no-op short-circuit
	err = repo.UpdatePolicy(ctx, api, api)
	require.NoError(t, err)

	// UpdatePolicy - actual change
	newApi := &biz.Api{
		ID:     10,
		URL:    "/api/v1/articles/all",
		Method: "POST",
	}
	err = repo.UpdatePolicy(ctx, api, newApi)
	require.NoError(t, err)

	hasOld, err := enf.HasPolicy(sub, api.URL, api.Method)
	require.NoError(t, err)
	assert.False(t, hasOld)

	hasNew, err := enf.HasPolicy(sub, newApi.URL, newApi.Method)
	require.NoError(t, err)
	assert.True(t, hasNew)

	// 3. RemovePolicy
	err = repo.RemovePolicy(ctx, newApi, true)
	require.NoError(t, err)

	hasNewAfterDel, err := enf.HasPolicy(sub, newApi.URL, newApi.Method)
	require.NoError(t, err)
	assert.False(t, hasNewAfterDel)

	// 4. AddPolicies batch
	batchApis := []biz.Api{
		{ID: 11, URL: "/api/v1/posts", Method: "GET"},
		{ID: 12, URL: "/api/v1/comments", Method: "POST"},
	}
	err = repo.AddPolicies(ctx, batchApis)
	require.NoError(t, err)

	hasBatch1, err := enf.HasPolicy(auth.ApiToSubject(11), "/api/v1/posts", "GET")
	require.NoError(t, err)
	assert.True(t, hasBatch1)

	hasBatch2, err := enf.HasPolicy(auth.ApiToSubject(12), "/api/v1/comments", "POST")
	require.NoError(t, err)
	assert.True(t, hasBatch2)

	// AddPolicies with empty list is no-op
	err = repo.AddPolicies(ctx, nil)
	require.NoError(t, err)
}
