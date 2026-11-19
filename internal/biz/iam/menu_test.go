package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/db"
	"grain/pkg/errorx"
)

func TestMenuUseCase_Create(t *testing.T) {
	ctx := context.Background()
	menuRepo := newMockMenuRepo()
	btnRepo := newMockButtonRepo()
	uc := NewMenuUseCase(menuRepo, nil, btnRepo)

	t.Run("nil menu", func(t *testing.T) {
		_, err := uc.Create(ctx, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("missing name or path", func(t *testing.T) {
		_, err := uc.Create(ctx, &Menu{Name: "", Path: "/system"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Menu{Name: "System", Path: ""})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("parent not found", func(t *testing.T) {
		parentID := uint64(9999)
		_, err := uc.Create(ctx, &Menu{
			Name:     "SubMenu",
			Path:     "/system/sub",
			ParentID: &parentID,
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success root menu", func(t *testing.T) {
		menu, err := uc.Create(ctx, &Menu{
			Name: "System",
			Path: "/system",
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), menu.ID)
		assert.True(t, menuRepo.addGroupPolicyCalled)
	})

	t.Run("duplicate name or path", func(t *testing.T) {
		_, err := uc.Create(ctx, &Menu{
			Name: "System",
			Path: "/system/other",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))

		_, err = uc.Create(ctx, &Menu{
			Name: "SystemNew",
			Path: "/system",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("policy error returns system error and triggers rollback", func(t *testing.T) {
		menuRepo.addGroupPolicyErr = errors.New("policy err")
		defer func() { menuRepo.addGroupPolicyErr = nil }()

		_, err := uc.Create(ctx, &Menu{
			Name: "Monitoring",
			Path: "/monitor",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify menu was rolled back (deleted)
		m, err := uc.GetByName(ctx, "Monitoring")
		require.Error(t, err)
		assert.Nil(t, m)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})
}

func TestMenuUseCase_Update(t *testing.T) {
	ctx := context.Background()
	menuRepo := newMockMenuRepo()
	btnRepo := newMockButtonRepo()
	uc := NewMenuUseCase(menuRepo, nil, btnRepo)

	root, _ := uc.Create(ctx, &Menu{Name: "Dashboard", Path: "/dashboard"})
	rootID := root.ID
	child, _ := uc.Create(ctx, &Menu{Name: "Analysis", Path: "/dashboard/analysis", ParentID: &rootID})
	childID := child.ID
	subChild, _ := uc.Create(ctx, &Menu{Name: "DeepAnalysis", Path: "/dashboard/analysis/deep", ParentID: &childID})

	t.Run("nil or invalid id", func(t *testing.T) {
		_, err := uc.Update(ctx, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Update(ctx, &Menu{ID: 0, Name: "A", Path: "/a"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("not found", func(t *testing.T) {
		_, err := uc.Update(ctx, &Menu{ID: 9999, Name: "A", Path: "/a"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("cannot self parent", func(t *testing.T) {
		selfID := root.ID
		_, err := uc.Update(ctx, &Menu{
			ID:       root.ID,
			Name:     root.Name,
			Path:     root.Path,
			ParentID: &selfID,
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeOperationNotAllowed))
	})

	t.Run("cannot set child/descendant as parent", func(t *testing.T) {
		// Attempting to set root's parent to deepAnalysis (a descendant)
		deepID := subChild.ID
		_, err := uc.Update(ctx, &Menu{
			ID:       root.ID,
			Name:     root.Name,
			Path:     root.Path,
			ParentID: &deepID,
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeOperationNotAllowed))
	})

	t.Run("success update", func(t *testing.T) {
		updated, err := uc.Update(ctx, &Menu{
			ID:   root.ID,
			Name: "DashboardRenamed",
			Path: "/dashboard-v2",
		})
		require.NoError(t, err)
		assert.Equal(t, "DashboardRenamed", updated.Name)
		assert.Equal(t, "/dashboard-v2", updated.Path)
	})

	t.Run("update policy failure triggers rollback", func(t *testing.T) {
		target, err := uc.Create(ctx, &Menu{
			Name:   "TargetMenu",
			Path:   "/target-menu",
			ApiIDs: []uint64{301, 302},
		})
		require.NoError(t, err)

		menuRepo.addGroupPolicyErr = errors.New("policy err")
		defer func() { menuRepo.addGroupPolicyErr = nil }()

		_, err = uc.Update(ctx, &Menu{
			ID:     target.ID,
			Name:   "TargetMenuChanged",
			Path:   "/target-menu-changed",
			ApiIDs: []uint64{401},
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify DB was rolled back
		current, err := uc.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, "TargetMenu", current.Name)
		assert.Equal(t, "/target-menu", current.Path)

		// Verify rollback restored original associations to AddGroupPolicy
		require.NotNil(t, menuRepo.lastGroupPolicyMenu)
		assert.Equal(t, "TargetMenu", menuRepo.lastGroupPolicyMenu.Name)
		assert.Equal(t, []uint64{301, 302}, menuRepo.lastGroupPolicyMenu.ApiIDs)
	})
}

func TestMenuUseCase_Delete(t *testing.T) {
	ctx := context.Background()
	menuRepo := newMockMenuRepo()
	btnRepo := newMockButtonRepo()
	uc := NewMenuUseCase(menuRepo, nil, btnRepo)

	parent, _ := uc.Create(ctx, &Menu{Name: "ParentM", Path: "/parent"})
	parentID := parent.ID
	child, _ := uc.Create(ctx, &Menu{Name: "ChildM", Path: "/parent/child", ParentID: &parentID})

	t.Run("cannot delete menu with children", func(t *testing.T) {
		err := uc.Delete(ctx, parent.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeOperationNotAllowed))
	})

	t.Run("cannot delete menu with buttons", func(t *testing.T) {
		leaf, _ := uc.Create(ctx, &Menu{Name: "LeafM", Path: "/leaf"})
		_, _ = btnRepo.Create(ctx, &Button{Name: "LeafBtn", MenuID: leaf.ID})

		err := uc.Delete(ctx, leaf.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeOperationNotAllowed))
	})

	t.Run("success delete child", func(t *testing.T) {
		err := uc.Delete(ctx, child.ID)
		require.NoError(t, err)

		// Now parent can be deleted
		err = uc.Delete(ctx, parent.ID)
		require.NoError(t, err)
	})

	t.Run("remove policy failure returns error", func(t *testing.T) {
		menuToDel, _ := uc.Create(ctx, &Menu{Name: "DelFailMenu", Path: "/delfail"})
		menuRepo.removeGroupPolicyErr = errors.New("remove policy err")
		defer func() { menuRepo.removeGroupPolicyErr = nil }()

		err := uc.Delete(ctx, menuToDel.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))
	})
}

func TestMenuUseCase_ListTree(t *testing.T) {
	ctx := context.Background()
	menuRepo := newMockMenuRepo()
	uc := NewMenuUseCase(menuRepo, nil)

	p1, _ := uc.Create(ctx, &Menu{Name: "Parent1", Path: "/p1", Sort: 2, IsActive: true})
	p1ID := p1.ID
	p2, _ := uc.Create(ctx, &Menu{Name: "Parent0", Path: "/p0", Sort: 1, IsActive: true})
	c1, _ := uc.Create(ctx, &Menu{Name: "Child1", Path: "/p1/c1", ParentID: &p1ID, Sort: 2, IsActive: true})
	c2, _ := uc.Create(ctx, &Menu{Name: "Child0", Path: "/p1/c0", ParentID: &p1ID, Sort: 1, IsActive: true})
	_ = c1
	_ = c2
	_ = p2

	tree, err := uc.ListTree(ctx)
	require.NoError(t, err)
	require.Len(t, tree, 2)

	// p2 has Sort 1, so it comes first
	assert.Equal(t, "Parent0", tree[0].Name)
	assert.Equal(t, "Parent1", tree[1].Name)

	// p1 has 2 children, sorted by sort
	require.Len(t, tree[1].Children, 2)
	assert.Equal(t, "Child0", tree[1].Children[0].Name)
	assert.Equal(t, "Child1", tree[1].Children[1].Name)
}

func TestMenuUseCase_GetAndList(t *testing.T) {
	ctx := context.Background()
	menuRepo := newMockMenuRepo()
	uc := NewMenuUseCase(menuRepo, nil)

	menu, _ := uc.Create(ctx, &Menu{Name: "Reports", Path: "/reports"})

	t.Run("get by id", func(t *testing.T) {
		got, err := uc.Get(ctx, menu.ID)
		require.NoError(t, err)
		assert.Equal(t, menu.ID, got.ID)

		_, err = uc.Get(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Get(ctx, 9999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("get by name", func(t *testing.T) {
		got, err := uc.GetByName(ctx, "Reports")
		require.NoError(t, err)
		assert.Equal(t, menu.ID, got.ID)

		_, err = uc.GetByName(ctx, "")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.GetByName(ctx, "Unknown")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("get by path", func(t *testing.T) {
		got, err := uc.GetByPath(ctx, "/reports")
		require.NoError(t, err)
		assert.Equal(t, menu.ID, got.ID)

		_, err = uc.GetByPath(ctx, "")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.GetByPath(ctx, "/unknown")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("list and list all", func(t *testing.T) {
		list, total, err := uc.List(ctx, db.ListOptions{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, list, 1)

		all, err := uc.ListAllWithApis(ctx)
		require.NoError(t, err)
		assert.Len(t, all, 1)
	})
}
