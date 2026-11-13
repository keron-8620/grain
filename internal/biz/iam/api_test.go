package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/errorx"
)

func TestApiUseCase_Create(t *testing.T) {
	ctx := context.Background()
	repo := newMockApiRepo()
	uc := NewApiUseCase(repo, nil)

	t.Run("nil api", func(t *testing.T) {
		_, err := uc.Create(ctx, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("empty url or method", func(t *testing.T) {
		_, err := uc.Create(ctx, &Api{URL: "", Method: "GET"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Api{URL: "/api/v1/users", Method: ""})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("success", func(t *testing.T) {
		api, err := uc.Create(ctx, &Api{
			URL:    "/api/v1/users",
			Method: "get",
			Label:  "Get Users",
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), api.ID)
		assert.Equal(t, "GET", api.Method)
		assert.True(t, repo.addPolicyCalled)
	})

	t.Run("duplicate url and method", func(t *testing.T) {
		_, err := uc.Create(ctx, &Api{
			URL:    "/api/v1/users",
			Method: "GET",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("policy failure returns error", func(t *testing.T) {
		repo.addPolicyErr = errors.New("policy err")
		defer func() { repo.addPolicyErr = nil }()

		_, err := uc.Create(ctx, &Api{
			URL:    "/api/v1/roles-fail",
			Method: "POST",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify the record was rolled back (deleted)
		api, err := uc.GetByURLAndMethod(ctx, "/api/v1/roles-fail", "POST")
		require.Error(t, err)
		assert.Nil(t, api)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})
}

func TestApiUseCase_Update(t *testing.T) {
	ctx := context.Background()
	repo := newMockApiRepo()
	uc := NewApiUseCase(repo, nil)

	created, err := uc.Create(ctx, &Api{
		URL:    "/api/v1/menus",
		Method: "GET",
		Label:  "Menus",
	})
	require.NoError(t, err)

	t.Run("nil or invalid id", func(t *testing.T) {
		_, err := uc.Update(ctx, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Update(ctx, &Api{ID: 0, URL: "/test", Method: "GET"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("missing url or method", func(t *testing.T) {
		_, err := uc.Update(ctx, &Api{ID: created.ID, URL: "", Method: "GET"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("record not found", func(t *testing.T) {
		_, err := uc.Update(ctx, &Api{ID: 9999, URL: "/api/test", Method: "GET"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success", func(t *testing.T) {
		updated, err := uc.Update(ctx, &Api{
			ID:     created.ID,
			URL:    "/api/v1/menus/all",
			Method: "get",
			Label:  "All Menus",
		})
		require.NoError(t, err)
		assert.Equal(t, "/api/v1/menus/all", updated.URL)
		assert.Equal(t, "GET", updated.Method)
		assert.True(t, repo.updatePolicyCalled)
	})

	t.Run("conflict with another route", func(t *testing.T) {
		other, err := uc.Create(ctx, &Api{
			URL:    "/api/v1/other",
			Method: "POST",
		})
		require.NoError(t, err)

		_, err = uc.Update(ctx, &Api{
			ID:     other.ID,
			URL:    "/api/v1/menus/all",
			Method: "GET",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("update policy failure triggers rollback", func(t *testing.T) {
		target, err := uc.Create(ctx, &Api{
			URL:    "/api/v1/rollback-target",
			Method: "GET",
			Label:  "Target Before",
		})
		require.NoError(t, err)

		repo.updatePolicyErr = errors.New("policy update error")
		defer func() { repo.updatePolicyErr = nil }()

		_, err = uc.Update(ctx, &Api{
			ID:     target.ID,
			URL:    "/api/v1/rollback-target-changed",
			Method: "POST",
			Label:  "Target After",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify DB was rolled back to oldApi
		current, err := uc.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, "/api/v1/rollback-target", current.URL)
		assert.Equal(t, "GET", current.Method)
		assert.Equal(t, "Target Before", current.Label)
	})
}

func TestApiUseCase_Delete(t *testing.T) {
	ctx := context.Background()
	repo := newMockApiRepo()
	uc := NewApiUseCase(repo, nil)

	created, err := uc.Create(ctx, &Api{
		URL:    "/api/v1/delete",
		Method: "DELETE",
	})
	require.NoError(t, err)

	t.Run("invalid id", func(t *testing.T) {
		err := uc.Delete(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("not found", func(t *testing.T) {
		err := uc.Delete(ctx, 999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success", func(t *testing.T) {
		err := uc.Delete(ctx, created.ID)
		require.NoError(t, err)
		assert.True(t, repo.removePolicyCalled)

		_, err = uc.Get(ctx, created.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("remove policy failure returns error", func(t *testing.T) {
		toDel, err := uc.Create(ctx, &Api{
			URL:    "/api/v1/delete-fail",
			Method: "DELETE",
		})
		require.NoError(t, err)

		repo.removePolicyErr = errors.New("remove policy err")
		defer func() { repo.removePolicyErr = nil }()

		err = uc.Delete(ctx, toDel.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))
	})
}

func TestApiUseCase_GetAndList(t *testing.T) {
	ctx := context.Background()
	repo := newMockApiRepo()
	uc := NewApiUseCase(repo, nil)

	created, err := uc.Create(ctx, &Api{
		URL:    "/api/v1/find",
		Method: "GET",
		Label:  "Find API",
	})
	require.NoError(t, err)

	t.Run("get by id", func(t *testing.T) {
		api, err := uc.Get(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, api.ID)

		_, err = uc.Get(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Get(ctx, 8888)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("get by url and method", func(t *testing.T) {
		api, err := uc.GetByURLAndMethod(ctx, "/api/v1/find", "get")
		require.NoError(t, err)
		assert.Equal(t, created.ID, api.ID)

		_, err = uc.GetByURLAndMethod(ctx, "", "GET")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.GetByURLAndMethod(ctx, "/none", "GET")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("list", func(t *testing.T) {
		list, total, err := uc.List(ctx, ApiListOptions{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, list, 1)
	})
}

func TestApiUseCase_SyncRoutes(t *testing.T) {
	ctx := context.Background()
	repo := newMockApiRepo()
	uc := NewApiUseCase(repo, nil)

	routes := []ApiRoute{
		{URL: "/api/v1/users", Method: "GET", Label: "Users"},
		{URL: "/api/v1/roles", Method: "POST", Label: "Roles"},
	}

	count, err := uc.SyncRoutes(ctx, routes)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.True(t, repo.addPoliciesCalled)
	assert.Len(t, repo.lastPoliciesApis, 2)

	// Second sync has nothing new, early returns without calling AddPolicies
	repo.addPoliciesCalled = false
	count2, err := uc.SyncRoutes(ctx, routes)
	require.NoError(t, err)
	assert.Equal(t, 0, count2)
	assert.False(t, repo.addPoliciesCalled)

	// Empty routes
	emptyCount, err := uc.SyncRoutes(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, emptyCount)
}
