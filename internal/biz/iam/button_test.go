package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/errorx"
)

func TestButtonUseCase_Create(t *testing.T) {
	ctx := context.Background()
	btnRepo := newMockButtonRepo()
	menuRepo := newMockMenuRepo()
	uc := NewButtonUseCase(btnRepo, menuRepo, nil)

	menu, err := menuRepo.Create(ctx, &Menu{Name: "UserMenu", Path: "/users"})
	require.NoError(t, err)

	t.Run("nil button", func(t *testing.T) {
		_, err := uc.Create(ctx, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("missing name or menu id", func(t *testing.T) {
		_, err := uc.Create(ctx, &Button{Name: "", MenuID: menu.ID})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Button{Name: "AddBtn", MenuID: 0})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("menu does not exist", func(t *testing.T) {
		_, err := uc.Create(ctx, &Button{Name: "AddBtn", MenuID: 9999})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success", func(t *testing.T) {
		btn, err := uc.Create(ctx, &Button{
			Name:   "AddBtn",
			MenuID: menu.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), btn.ID)
		assert.True(t, btnRepo.addGroupPolicyCalled)
	})

	t.Run("duplicate button name", func(t *testing.T) {
		_, err := uc.Create(ctx, &Button{
			Name:   "AddBtn",
			MenuID: menu.ID,
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("policy error returns system error and triggers rollback", func(t *testing.T) {
		btnRepo.addGroupPolicyErr = errors.New("group err")
		defer func() { btnRepo.addGroupPolicyErr = nil }()

		_, err := uc.Create(ctx, &Button{
			Name:   "EditBtn",
			MenuID: menu.ID,
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify button was rolled back (deleted)
		b, err := uc.GetByName(ctx, "EditBtn")
		require.Error(t, err)
		assert.Nil(t, b)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})
}

func TestButtonUseCase_Update(t *testing.T) {
	ctx := context.Background()
	btnRepo := newMockButtonRepo()
	menuRepo := newMockMenuRepo()
	uc := NewButtonUseCase(btnRepo, menuRepo, nil)

	menu, _ := menuRepo.Create(ctx, &Menu{Name: "UserMenu", Path: "/users"})
	menu2, _ := menuRepo.Create(ctx, &Menu{Name: "RoleMenu", Path: "/roles"})

	btn, err := uc.Create(ctx, &Button{
		Name:   "DelBtn",
		MenuID: menu.ID,
	})
	require.NoError(t, err)

	t.Run("invalid id", func(t *testing.T) {
		_, err := uc.Update(ctx, &Button{ID: 0, Name: "NewName", MenuID: menu.ID})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("not found", func(t *testing.T) {
		_, err := uc.Update(ctx, &Button{ID: 9999, Name: "Ghost", MenuID: menu.ID})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("menu not found", func(t *testing.T) {
		_, err := uc.Update(ctx, &Button{ID: btn.ID, Name: "DelBtn", MenuID: 9999})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success", func(t *testing.T) {
		updated, err := uc.Update(ctx, &Button{
			ID:     btn.ID,
			Name:   "DelBtnRenamed",
			MenuID: menu2.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, "DelBtnRenamed", updated.Name)
		assert.Equal(t, menu2.ID, updated.MenuID)
	})

	t.Run("duplicate name on update", func(t *testing.T) {
		other, _ := uc.Create(ctx, &Button{Name: "OtherBtn", MenuID: menu.ID})
		_, err := uc.Update(ctx, &Button{ID: other.ID, Name: "DelBtnRenamed", MenuID: menu.ID})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("update policy failure triggers rollback", func(t *testing.T) {
		target, err := uc.Create(ctx, &Button{
			Name:   "TargetBtn",
			MenuID: menu.ID,
			ApiIDs: []uint64{501, 502},
		})
		require.NoError(t, err)

		btnRepo.addGroupPolicyErr = errors.New("policy err")
		defer func() { btnRepo.addGroupPolicyErr = nil }()

		_, err = uc.Update(ctx, &Button{
			ID:     target.ID,
			Name:   "TargetBtnChanged",
			MenuID: menu.ID,
			ApiIDs: []uint64{601},
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify DB was rolled back
		current, err := uc.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, "TargetBtn", current.Name)

		// Verify rollback restored original associations to AddGroupPolicy
		require.NotNil(t, btnRepo.lastGroupPolicyButton)
		assert.Equal(t, "TargetBtn", btnRepo.lastGroupPolicyButton.Name)
		assert.Equal(t, []uint64{501, 502}, btnRepo.lastGroupPolicyButton.ApiIDs)
	})
}

func TestButtonUseCase_Delete(t *testing.T) {
	ctx := context.Background()
	btnRepo := newMockButtonRepo()
	menuRepo := newMockMenuRepo()
	uc := NewButtonUseCase(btnRepo, menuRepo, nil)

	menu, _ := menuRepo.Create(ctx, &Menu{Name: "UserMenu", Path: "/users"})
	btn, _ := uc.Create(ctx, &Button{Name: "ToDel", MenuID: menu.ID})

	t.Run("invalid id", func(t *testing.T) {
		err := uc.Delete(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("not found", func(t *testing.T) {
		err := uc.Delete(ctx, 9999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success", func(t *testing.T) {
		err := uc.Delete(ctx, btn.ID)
		require.NoError(t, err)
		assert.True(t, btnRepo.removeGroupPolicyCalled)
	})

	t.Run("remove policy failure returns error", func(t *testing.T) {
		btnToDel, _ := uc.Create(ctx, &Button{Name: "DelFailBtn", MenuID: menu.ID})
		btnRepo.removeGroupPolicyErr = errors.New("remove policy err")
		defer func() { btnRepo.removeGroupPolicyErr = nil }()

		err := uc.Delete(ctx, btnToDel.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))
	})
}

func TestButtonUseCase_GetAndList(t *testing.T) {
	ctx := context.Background()
	btnRepo := newMockButtonRepo()
	menuRepo := newMockMenuRepo()
	uc := NewButtonUseCase(btnRepo, menuRepo, nil)

	menu, _ := menuRepo.Create(ctx, &Menu{Name: "UserMenu", Path: "/users"})
	btn, _ := uc.Create(ctx, &Button{Name: "ViewBtn", MenuID: menu.ID})

	t.Run("get by id", func(t *testing.T) {
		got, err := uc.Get(ctx, btn.ID)
		require.NoError(t, err)
		assert.Equal(t, btn.ID, got.ID)

		_, err = uc.Get(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Get(ctx, 9999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("get by name", func(t *testing.T) {
		got, err := uc.GetByName(ctx, "ViewBtn")
		require.NoError(t, err)
		assert.Equal(t, btn.ID, got.ID)

		_, err = uc.GetByName(ctx, "")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.GetByName(ctx, "None")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("list and list all", func(t *testing.T) {
		list, total, err := uc.List(ctx, ButtonListOptions{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, list, 1)

		all, err := uc.ListAllWithApis(ctx)
		require.NoError(t, err)
		assert.Len(t, all, 1)
	})
}
