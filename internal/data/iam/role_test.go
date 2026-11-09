package iam

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	biz "grain/internal/biz/iam"
	"grain/pkg/auth"
	"grain/pkg/db/filter"
)

func TestRoleRepo_Validation(t *testing.T) {
	ctx := context.Background()
	repo := NewRoleRepo(&Data{}, slog.Default())

	t.Run("Create validation", func(t *testing.T) {
		_, err := repo.Create(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be nil")
	})

	t.Run("Update validation", func(t *testing.T) {
		_, err := repo.Update(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")

		_, err = repo.Update(ctx, &biz.Role{ID: 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")

		_, err = repo.Update(ctx, &biz.Role{ID: 1, Name: ""})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("Delete validation", func(t *testing.T) {
		err := repo.Delete(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID must not be 0")
	})

	t.Run("FindByID validation", func(t *testing.T) {
		r, err := repo.FindByID(ctx, 0)
		require.NoError(t, err)
		assert.Nil(t, r)
	})

	t.Run("AddGroupPolicy validation", func(t *testing.T) {
		require.Error(t, repo.AddGroupPolicy(ctx, nil))
		require.Error(t, repo.AddGroupPolicy(ctx, &biz.Role{ID: 0}))
	})

	t.Run("RemoveGroupPolicy validation", func(t *testing.T) {
		require.Error(t, repo.RemoveGroupPolicy(ctx, nil))
		require.Error(t, repo.RemoveGroupPolicy(ctx, &biz.Role{ID: 0}))
	})
}

func TestRoleRepo_CRUD(t *testing.T) {
	data, gormDB, _, _ := setupTestData(t)
	repo := NewRoleRepo(data, slog.Default())
	apiRepo := NewApiRepo(data, slog.Default())
	menuRepo := NewMenuRepo(data, slog.Default())
	buttonRepo := NewButtonRepo(data, slog.Default())
	ctx := context.Background()

	// 0. Pre-create Api, Menu, Button
	api, err := apiRepo.Create(ctx, &biz.Api{
		URL:    "/api/v1/roles",
		Method: "GET",
		Label:  "Get Roles",
	})
	require.NoError(t, err)

	menu, err := menuRepo.Create(ctx, &biz.Menu{
		Path:      "/roles",
		Component: "roles/index",
		Name:      "RoleManage",
	})
	require.NoError(t, err)

	btn, err := buttonRepo.Create(ctx, &biz.Button{
		Name:   "btn-role-create",
		MenuID: menu.ID,
	})
	require.NoError(t, err)

	// 1. Create Role with M2M relations
	roleIn := &biz.Role{
		Name:      "Admin",
		Descr:     "System Administrator",
		ApiIDs:    []uint64{api.ID},
		MenuIDs:   []uint64{menu.ID},
		ButtonIDs: []uint64{btn.ID},
	}
	created, err := repo.Create(ctx, roleIn)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)
	assert.Equal(t, "Admin", created.Name)
	assert.Len(t, created.Apis, 1)
	assert.Len(t, created.Menus, 1)
	assert.Len(t, created.Buttons, 1)

	// 2. FindByID & FindByName
	found, err := repo.FindByID(ctx, created.ID, "Apis", "Menus", "Buttons")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.Len(t, found.Apis, 1)

	notFound, err := repo.FindByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, notFound)

	byName, err := repo.FindByName(ctx, "Admin")
	require.NoError(t, err)
	require.NotNil(t, byName)
	assert.Equal(t, created.ID, byName.ID)

	// 3. Update
	created.Descr = "Updated Admin"
	created.Apis = nil
	created.ApiIDs = []uint64{}
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "Updated Admin", updated.Descr)
	assert.Len(t, updated.Apis, 0)

	// 4. List & ListAllWithRelations
	role2, err := repo.Create(ctx, &biz.Role{Name: "Editor", Descr: "Content Editor"})
	require.NoError(t, err)

	list, total, err := repo.List(ctx, biz.RoleListOptions{
		PageSize: 10,
		Filters: []filter.ListFilter{
			{Field: "name", Op: filter.ListFilterContains, Value: "Admin"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)

	allRelations, err := repo.ListAllWithRelations(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(allRelations), 2)

	// 5. CountUsersByRoleID & Delete Protection
	count, err := repo.CountUsersByRoleID(ctx, role2.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Attach a user to role2
	err = gormDB.Create(&userPO{
		Username: "editor_user",
		Password: "password_hash",
		RoleID:   role2.ID,
	}).Error
	require.NoError(t, err)

	count, err = repo.CountUsersByRoleID(ctx, role2.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Attempt to delete role2 with associated user -> MUST FAIL
	err = repo.Delete(ctx, role2.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role still has associated users and cannot be deleted")

	// Delete user then delete role2 -> MUST SUCCEED
	err = gormDB.Where("username = ?", "editor_user").Delete(&userPO{}).Error
	require.NoError(t, err)

	err = repo.Delete(ctx, role2.ID)
	require.NoError(t, err)

	// Delete non-existent role returns nil (idempotent)
	err = repo.Delete(ctx, 99999)
	require.NoError(t, err)
}

func TestRoleRepo_CasbinPolicy(t *testing.T) {
	data, _, enf, _ := setupTestData(t)
	repo := NewRoleRepo(data, slog.Default())
	ctx := context.Background()

	role := &biz.Role{
		ID:        8,
		ApiIDs:    []uint64{10, 11},
		MenuIDs:   []uint64{20},
		ButtonIDs: []uint64{30},
	}

	// 1. AddGroupPolicy
	err := repo.AddGroupPolicy(ctx, role)
	require.NoError(t, err)

	sub := auth.RoleToSubject(role.ID)
	hasApi, err := enf.HasGroupingPolicy(sub, auth.ApiToSubject(10))
	require.NoError(t, err)
	assert.True(t, hasApi)

	hasMenu, err := enf.HasGroupingPolicy(sub, auth.MenuToSubject(20))
	require.NoError(t, err)
	assert.True(t, hasMenu)

	hasBtn, err := enf.HasGroupingPolicy(sub, auth.ButtonToSubject(30))
	require.NoError(t, err)
	assert.True(t, hasBtn)

	// 2. RemoveGroupPolicy
	err = repo.RemoveGroupPolicy(ctx, role)
	require.NoError(t, err)

	hasApiAfter, err := enf.HasGroupingPolicy(sub, auth.ApiToSubject(10))
	require.NoError(t, err)
	assert.False(t, hasApiAfter)

	hasMenuAfter, err := enf.HasGroupingPolicy(sub, auth.MenuToSubject(20))
	require.NoError(t, err)
	assert.False(t, hasMenuAfter)
}
