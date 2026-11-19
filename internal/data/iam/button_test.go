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

func TestButtonRepo_Validation(t *testing.T) {
	ctx := context.Background()
	repo := NewButtonRepo(&Data{}, slog.Default())

	t.Run("Create validation", func(t *testing.T) {
		_, err := repo.Create(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "model cannot be nil")
	})

	t.Run("Update validation", func(t *testing.T) {
		_, err := repo.Update(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")

		_, err = repo.Update(ctx, &biz.Button{ID: 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")
	})

	t.Run("Delete validation", func(t *testing.T) {
		err := repo.Delete(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID cannot be 0")
	})

	t.Run("FindByID validation", func(t *testing.T) {
		b, err := repo.FindByID(ctx, 0)
		require.NoError(t, err)
		assert.Nil(t, b)
	})

	t.Run("FindByIDs empty", func(t *testing.T) {
		bs, err := repo.FindByIDs(ctx, nil)
		require.NoError(t, err)
		assert.Nil(t, bs)
	})

	t.Run("AddGroupPolicy validation", func(t *testing.T) {
		require.Error(t, repo.AddGroupPolicy(ctx, nil))
		require.Error(t, repo.AddGroupPolicy(ctx, &biz.Button{ID: 0, MenuID: 1}))
		require.Error(t, repo.AddGroupPolicy(ctx, &biz.Button{ID: 1, MenuID: 0}))
	})

	t.Run("RemoveGroupPolicy validation", func(t *testing.T) {
		require.Error(t, repo.RemoveGroupPolicy(ctx, nil, false))
		require.Error(t, repo.RemoveGroupPolicy(ctx, &biz.Button{ID: 0}, false))
	})
}

func TestButtonRepo_CRUD(t *testing.T) {
	data, _, _, _ := setupTestData(t)
	repo := NewButtonRepo(data, slog.Default())
	menuRepo := NewMenuRepo(data, slog.Default())
	apiRepo := NewApiRepo(data, slog.Default())
	ctx := context.Background()

	// 0. Pre-create Menu and API
	menu, err := menuRepo.Create(ctx, &biz.Menu{
		Path:      "/users",
		Component: "users/index",
		Name:      "UserManage",
	})
	require.NoError(t, err)

	api, err := apiRepo.Create(ctx, &biz.Api{
		URL:    "/api/v1/users",
		Method: "POST",
		Label:  "Add User",
	})
	require.NoError(t, err)

	// 1. Create Button
	buttonIn := &biz.Button{
		Name:     "btn-user-add",
		Sort:     1,
		IsActive: true,
		Descr:    "Button to add user",
		MenuID:   menu.ID,
		ApiIDs:   []uint64{api.ID},
	}
	created, err := repo.Create(ctx, buttonIn)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)
	assert.Equal(t, "btn-user-add", created.Name)
	assert.Equal(t, menu.ID, created.MenuID)
	assert.Len(t, created.Apis, 1)

	// 2. FindByID
	found, err := repo.FindByID(ctx, created.ID, "Menu", "Apis")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.NotNil(t, found.Menu)
	assert.Equal(t, menu.ID, found.Menu.ID)

	notFound, err := repo.FindByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, notFound)

	// 3. FindByIDs
	btn2, err := repo.Create(ctx, &biz.Button{
		Name:   "btn-user-edit",
		MenuID: menu.ID,
	})
	require.NoError(t, err)

	byIDs, err := repo.FindByIDs(ctx, []uint64{created.ID, btn2.ID})
	require.NoError(t, err)
	assert.Len(t, byIDs, 2)

	// 4. FindByName
	byName, err := repo.FindByName(ctx, "btn-user-add")
	require.NoError(t, err)
	require.NotNil(t, byName)
	assert.Equal(t, created.ID, byName.ID)

	// 5. Update
	created.Name = "btn-user-add-updated"
	created.Apis = nil
	created.ApiIDs = []uint64{}
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "btn-user-add-updated", updated.Name)
	assert.Len(t, updated.Apis, 0)

	// 6. List
	list, total, err := repo.List(ctx, db.ListOptions{
		PageSize: 10,
		Filters: []filter.ListFilter{
			{Field: "name", Op: filter.ListFilterContains, Value: "btn-user"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, list, 2)

	// 7. ListAllWithApis
	allWithApis, err := repo.ListAllWithApis(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(allWithApis), 2)

	// 8. Delete
	err = repo.Delete(ctx, created.ID)
	require.NoError(t, err)

	deleted, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestButtonRepo_CasbinPolicy(t *testing.T) {
	data, _, enf, _ := setupTestData(t)
	repo := NewButtonRepo(data, slog.Default())
	ctx := context.Background()

	button := &biz.Button{
		ID:     50,
		MenuID: 20,
		ApiIDs: []uint64{201, 202},
	}

	// 1. AddGroupPolicy
	err := repo.AddGroupPolicy(ctx, button)
	require.NoError(t, err)

	sub := auth.ButtonToSubject(button.ID)
	menuSub := auth.MenuToSubject(button.MenuID)
	hasMenuInherit, err := enf.HasGroupingPolicy(sub, menuSub)
	require.NoError(t, err)
	assert.True(t, hasMenuInherit)

	hasApiInherit, err := enf.HasGroupingPolicy(sub, auth.ApiToSubject(201))
	require.NoError(t, err)
	assert.True(t, hasApiInherit)

	// 2. RemoveGroupPolicy
	err = repo.RemoveGroupPolicy(ctx, button, true)
	require.NoError(t, err)

	hasMenuAfter, err := enf.HasGroupingPolicy(sub, menuSub)
	require.NoError(t, err)
	assert.False(t, hasMenuAfter)

	hasApiAfter, err := enf.HasGroupingPolicy(sub, auth.ApiToSubject(201))
	require.NoError(t, err)
	assert.False(t, hasApiAfter)
}
