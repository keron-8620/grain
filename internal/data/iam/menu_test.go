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

func TestMenuRepo_Validation(t *testing.T) {
	ctx := context.Background()
	repo := NewMenuRepo(&Data{}, slog.Default())

	t.Run("Create validation", func(t *testing.T) {
		_, err := repo.Create(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be nil")
	})

	t.Run("Update validation", func(t *testing.T) {
		_, err := repo.Update(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")

		_, err = repo.Update(ctx, &biz.Menu{ID: 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid argument")
	})

	t.Run("Delete validation", func(t *testing.T) {
		err := repo.Delete(ctx, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID must not be 0")
	})

	t.Run("FindByID validation", func(t *testing.T) {
		m, err := repo.FindByID(ctx, 0)
		require.NoError(t, err)
		assert.Nil(t, m)
	})

	t.Run("FindByIDs empty", func(t *testing.T) {
		ms, err := repo.FindByIDs(ctx, nil)
		require.NoError(t, err)
		assert.Nil(t, ms)
	})

	t.Run("AddGroupPolicy validation", func(t *testing.T) {
		require.Error(t, repo.AddGroupPolicy(ctx, nil))
		require.Error(t, repo.AddGroupPolicy(ctx, &biz.Menu{ID: 0}))
	})

	t.Run("RemoveGroupPolicy validation", func(t *testing.T) {
		require.Error(t, repo.RemoveGroupPolicy(ctx, nil, false))
		require.Error(t, repo.RemoveGroupPolicy(ctx, &biz.Menu{ID: 0}, false))
	})
}

func TestMenuRepo_CRUD(t *testing.T) {
	data, _, _, _ := setupTestData(t)
	repo := NewMenuRepo(data, slog.Default())
	apiRepo := NewApiRepo(data, slog.Default())
	ctx := context.Background()

	// 0. Pre-create an API
	api1, err := apiRepo.Create(ctx, &biz.Api{
		URL:    "/api/v1/system/menus",
		Method: "GET",
		Label:  "Get Menus",
	})
	require.NoError(t, err)

	// 1. Create parent menu
	parentIn := &biz.Menu{
		Path:      "/system",
		Component: "Layout",
		Name:      "SystemManage",
		Meta: biz.MenuMeta{
			Title: "系统管理",
			Icon:  "setting",
		},
		Sort:     1,
		IsActive: true,
	}
	parent, err := repo.Create(ctx, parentIn)
	require.NoError(t, err)
	require.NotNil(t, parent)
	assert.NotZero(t, parent.ID)
	assert.Equal(t, "SystemManage", parent.Name)

	// 2. Create child menu with parent and API relations
	childIn := &biz.Menu{
		Path:      "/system/menu",
		Component: "system/menu/index",
		Name:      "MenuManage",
		Meta: biz.MenuMeta{
			Title: "菜单管理",
			Icon:  "menu",
		},
		Sort:     10,
		IsActive: true,
		ParentID: &parent.ID,
		ApiIDs:   []uint64{api1.ID},
	}
	child, err := repo.Create(ctx, childIn)
	require.NoError(t, err)
	require.NotNil(t, child)
	assert.NotZero(t, child.ID)
	assert.Equal(t, parent.ID, *child.ParentID)
	assert.Len(t, child.Apis, 1)

	// 3. FindByID
	found, err := repo.FindByID(ctx, child.ID, "Parent", "Apis")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, child.ID, found.ID)
	assert.NotNil(t, found.Parent)
	assert.Equal(t, parent.ID, found.Parent.ID)

	notFound, err := repo.FindByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, notFound)

	// 4. FindByIDs
	byIDs, err := repo.FindByIDs(ctx, []uint64{parent.ID, child.ID})
	require.NoError(t, err)
	assert.Len(t, byIDs, 2)

	// 5. FindByName & FindByPath
	byName, err := repo.FindByName(ctx, "SystemManage")
	require.NoError(t, err)
	require.NotNil(t, byName)
	assert.Equal(t, parent.ID, byName.ID)

	byPath, err := repo.FindByPath(ctx, "/system/menu")
	require.NoError(t, err)
	require.NotNil(t, byPath)
	assert.Equal(t, child.ID, byPath.ID)

	// 6. Update
	child.Name = "MenuManageUpdated"
	child.Meta.Title = "菜单管理已更新"
	child.Apis = nil
	child.ApiIDs = []uint64{} // clear APIs
	updated, err := repo.Update(ctx, child)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "MenuManageUpdated", updated.Name)
	assert.Len(t, updated.Apis, 0)

	// 7. List
	list, total, err := repo.List(ctx, db.ListOptions{
		PageSize: 10,
		Filters: []filter.ListFilter{
			{Field: "name", Op: filter.ListFilterContains, Value: "Manage"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, list, 2)

	// 8. ListAllWithApis
	allWithApis, err := repo.ListAllWithApis(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(allWithApis), 2)

	// 8.1 CountChildren
	count, err := repo.CountChildren(ctx, parent.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	zeroCount, err := repo.CountChildren(ctx, child.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), zeroCount)

	// 9. Delete
	err = repo.Delete(ctx, child.ID)
	require.NoError(t, err)

	deleted, err := repo.FindByID(ctx, child.ID)
	require.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestMenuRepo_CasbinPolicy(t *testing.T) {
	data, _, enf, _ := setupTestData(t)
	repo := NewMenuRepo(data, slog.Default())
	ctx := context.Background()

	parentID := uint64(20)
	menu := &biz.Menu{
		ID:       21,
		ParentID: &parentID,
		ApiIDs:   []uint64{101, 102},
	}

	// 1. AddGroupPolicy
	err := repo.AddGroupPolicy(ctx, menu)
	require.NoError(t, err)

	sub := auth.MenuToSubject(menu.ID)
	parentSub := auth.MenuToSubject(parentID)
	hasParentInherit, err := enf.HasGroupingPolicy(sub, parentSub)
	require.NoError(t, err)
	assert.True(t, hasParentInherit)

	hasApiInherit, err := enf.HasGroupingPolicy(sub, auth.ApiToSubject(101))
	require.NoError(t, err)
	assert.True(t, hasApiInherit)

	// 2. RemoveGroupPolicy
	err = repo.RemoveGroupPolicy(ctx, menu, true)
	require.NoError(t, err)

	hasParentAfter, err := enf.HasGroupingPolicy(sub, parentSub)
	require.NoError(t, err)
	assert.False(t, hasParentAfter)

	hasApiAfter, err := enf.HasGroupingPolicy(sub, auth.ApiToSubject(101))
	require.NoError(t, err)
	assert.False(t, hasApiAfter)
}
