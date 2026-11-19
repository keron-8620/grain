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

func TestRoleUseCase_Create(t *testing.T) {
	ctx := context.Background()
	roleRepo := newMockRoleRepo()
	userRepo := newMockUserRepo()
	uc := NewRoleUseCase(roleRepo, userRepo, nil)

	t.Run("nil role", func(t *testing.T) {
		_, err := uc.Create(ctx, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("missing name", func(t *testing.T) {
		_, err := uc.Create(ctx, &Role{Name: ""})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("success", func(t *testing.T) {
		role, err := uc.Create(ctx, &Role{
			Name:  "Admin",
			Descr: "Administrator",
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), role.ID)
		assert.True(t, roleRepo.addGroupPolicyCalled)
	})

	t.Run("duplicate name", func(t *testing.T) {
		_, err := uc.Create(ctx, &Role{Name: "Admin"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("policy error returns system error and triggers rollback", func(t *testing.T) {
		roleRepo.addGroupPolicyErr = errors.New("policy err")
		defer func() { roleRepo.addGroupPolicyErr = nil }()

		_, err := uc.Create(ctx, &Role{Name: "Editor"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify role was rolled back (deleted)
		role, err := uc.GetByName(ctx, "Editor")
		require.Error(t, err)
		assert.Nil(t, role)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})
}

func TestRoleUseCase_Update(t *testing.T) {
	ctx := context.Background()
	roleRepo := newMockRoleRepo()
	userRepo := newMockUserRepo()
	uc := NewRoleUseCase(roleRepo, userRepo, nil)

	role, _ := uc.Create(ctx, &Role{Name: "Operator"})

	// Create a user assigned to this role
	_, _ = userRepo.Create(ctx, &User{Username: "u1", RoleID: role.ID})
	_, _ = userRepo.Create(ctx, &User{Username: "u2", RoleID: role.ID})

	t.Run("invalid id", func(t *testing.T) {
		_, err := uc.Update(ctx, &Role{ID: 0, Name: "A"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("not found", func(t *testing.T) {
		_, err := uc.Update(ctx, &Role{ID: 9999, Name: "Ghost"})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success update revokes users sessions under role", func(t *testing.T) {
		updated, err := uc.Update(ctx, &Role{
			ID:    role.ID,
			Name:  "SeniorOperator",
			Descr: "Updated operator",
		})
		require.NoError(t, err)
		assert.Equal(t, "SeniorOperator", updated.Name)

		// Check that user token versions were bumped
		assert.Contains(t, userRepo.incrementBatchCalled, uint64(1))
		assert.Contains(t, userRepo.incrementBatchCalled, uint64(2))
	})

	t.Run("update policy failure triggers rollback", func(t *testing.T) {
		target, err := uc.Create(ctx, &Role{
			Name:   "TargetBefore",
			ApiIDs: []uint64{101, 102},
		})
		require.NoError(t, err)

		roleRepo.addGroupPolicyErr = errors.New("policy err")
		defer func() { roleRepo.addGroupPolicyErr = nil }()

		_, err = uc.Update(ctx, &Role{
			ID:     target.ID,
			Name:   "TargetAfter",
			ApiIDs: []uint64{201},
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))

		// Verify DB was rolled back
		current, err := uc.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, "TargetBefore", current.Name)

		// Verify that rollback restored original permissions to AddGroupPolicy
		require.NotNil(t, roleRepo.lastGroupPolicyRole)
		assert.Equal(t, "TargetBefore", roleRepo.lastGroupPolicyRole.Name)
		assert.Equal(t, []uint64{101, 102}, roleRepo.lastGroupPolicyRole.ApiIDs)
	})
}

func TestRoleUseCase_Delete(t *testing.T) {
	ctx := context.Background()
	roleRepo := newMockRoleRepo()
	userRepo := newMockUserRepo()
	uc := NewRoleUseCase(roleRepo, userRepo, nil)

	r1, _ := uc.Create(ctx, &Role{Name: "HasUsers"})
	r2, _ := uc.Create(ctx, &Role{Name: "NoUsers"})

	roleRepo.userCounts[r1.ID] = 3

	t.Run("cannot delete role with assigned users", func(t *testing.T) {
		err := uc.Delete(ctx, r1.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeOperationNotAllowed))
	})

	t.Run("success delete empty role", func(t *testing.T) {
		err := uc.Delete(ctx, r2.ID)
		require.NoError(t, err)
		assert.True(t, roleRepo.removeGroupPolicyCalled)
	})

	t.Run("remove policy failure returns error", func(t *testing.T) {
		roleToDel, _ := uc.Create(ctx, &Role{Name: "DelFailRole"})
		roleRepo.removeGroupPolicyErr = errors.New("remove policy err")
		defer func() { roleRepo.removeGroupPolicyErr = nil }()

		err := uc.Delete(ctx, roleToDel.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeSystemError))
	})
}

func TestRoleUseCase_GetAndList(t *testing.T) {
	ctx := context.Background()
	roleRepo := newMockRoleRepo()
	uc := NewRoleUseCase(roleRepo, nil, nil)

	role, _ := uc.Create(ctx, &Role{Name: "Manager"})

	t.Run("get by id", func(t *testing.T) {
		got, err := uc.Get(ctx, role.ID)
		require.NoError(t, err)
		assert.Equal(t, role.ID, got.ID)

		_, err = uc.Get(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Get(ctx, 9999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("get by name", func(t *testing.T) {
		got, err := uc.GetByName(ctx, "Manager")
		require.NoError(t, err)
		assert.Equal(t, role.ID, got.ID)

		_, err = uc.GetByName(ctx, "")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.GetByName(ctx, "Ghost")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("list and list all", func(t *testing.T) {
		list, total, err := uc.List(ctx, db.ListOptions{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, list, 1)

		all, err := uc.ListAllWithRelations(ctx)
		require.NoError(t, err)
		assert.Len(t, all, 1)
	})
}
