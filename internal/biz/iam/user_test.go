package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/cryptoutil"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

func boolPtr(v bool) *bool {
	return &v
}

func TestUserUseCase_Create(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	uc := NewUserUseCase(userRepo, roleRepo, nil)

	role, _ := roleRepo.Create(ctx, &Role{Name: "GeneralUser"})

	t.Run("nil user", func(t *testing.T) {
		_, err := uc.Create(ctx, nil, "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("missing username", func(t *testing.T) {
		_, err := uc.Create(ctx, &User{Username: "", RoleID: role.ID}, "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("short password", func(t *testing.T) {
		_, err := uc.Create(ctx, &User{Username: "alice", RoleID: role.ID}, "12345")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))
	})

	t.Run("missing role id", func(t *testing.T) {
		_, err := uc.Create(ctx, &User{Username: "alice", RoleID: 0}, "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("role not found", func(t *testing.T) {
		_, err := uc.Create(ctx, &User{Username: "alice", RoleID: 9999}, "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("success", func(t *testing.T) {
		user, err := uc.Create(ctx, &User{
			Username: "alice",
			RoleID:   role.ID,
			IsActive: true,
		}, "secret123")
		require.NoError(t, err)
		assert.Equal(t, uint64(1), user.ID)
		assert.Empty(t, user.Password) // Sanitized!
		assert.Equal(t, "alice", user.Username)

		// Check stored password in repo is hashed
		rawUser := userRepo.users[user.ID]
		assert.NotEmpty(t, rawUser.Password)
		hasher := cryptoutil.NewBcryptHasher(0)
		valid, _ := hasher.VerifyString("secret123", rawUser.Password)
		assert.True(t, valid)
	})

	t.Run("duplicate username", func(t *testing.T) {
		_, err := uc.Create(ctx, &User{
			Username: "alice",
			RoleID:   role.ID,
		}, "anotherpass")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})
}

func TestUserUseCase_Update(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	uc := NewUserUseCase(userRepo, roleRepo, nil)

	r1, _ := roleRepo.Create(ctx, &Role{Name: "R1"})
	r2, _ := roleRepo.Create(ctx, &Role{Name: "R2"})

	user, err := uc.Create(ctx, &User{
		Username: "bob",
		RoleID:   r1.ID,
		IsActive: true,
	}, "password123")
	require.NoError(t, err)

	t.Run("update name and role revokes token", func(t *testing.T) {
		updated, err := uc.Update(ctx, UserUpdate{
			ID:       user.ID,
			Username: "bob_renamed",
			RoleID:   r2.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, "bob_renamed", updated.Username)
		assert.Equal(t, r2.ID, updated.RoleID)
		assert.Equal(t, 1, userRepo.incrementVersionCalled[user.ID])
	})

	t.Run("partial update username does not disable active user or revoke token", func(t *testing.T) {
		activeUser, err := uc.Create(ctx, &User{
			Username: "david",
			RoleID:   r1.ID,
			IsActive: true,
		}, "password123")
		require.NoError(t, err)

		// Only provide ID and Username, leaving IsActive nil (unchanged) and RoleID as 0
		updated, err := uc.Update(ctx, UserUpdate{
			ID:       activeUser.ID,
			Username: "david_renamed",
		})
		require.NoError(t, err)
		assert.Equal(t, "david_renamed", updated.Username)
		assert.True(t, updated.IsActive)
		assert.Equal(t, r1.ID, updated.RoleID)
		assert.Equal(t, 0, userRepo.incrementVersionCalled[activeUser.ID])
	})

	t.Run("disable user revokes token", func(t *testing.T) {
		updated, err := uc.Update(ctx, UserUpdate{
			ID:       user.ID,
			IsActive: boolPtr(false),
		})
		require.NoError(t, err)
		assert.False(t, updated.IsActive)
		assert.Equal(t, 2, userRepo.incrementVersionCalled[user.ID])
	})

	t.Run("password update revokes token and preserves active status", func(t *testing.T) {
		activeUser, err := uc.Create(ctx, &User{
			Username: "pwd_user",
			RoleID:   r1.ID,
			IsActive: true,
		}, "password123")
		require.NoError(t, err)

		updated, err := uc.Update(ctx, UserUpdate{
			ID:       activeUser.ID,
			Password: "newpassword123",
		})
		require.NoError(t, err)
		assert.True(t, updated.IsActive)
		assert.Equal(t, 1, userRepo.incrementVersionCalled[activeUser.ID])

		raw := userRepo.users[activeUser.ID]
		hasher := cryptoutil.NewBcryptHasher(0)
		valid, err := hasher.VerifyString("newpassword123", raw.Password)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("short password update is rejected", func(t *testing.T) {
		_, err := uc.Update(ctx, UserUpdate{
			ID:       user.ID,
			Password: "123",
		})
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))
	})
}

func TestUserUseCase_PasswordPolicy(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	uc := NewUserUseCase(userRepo, roleRepo, nil, PasswordPolicy{StrengthLevel: 2})

	role, _ := roleRepo.Create(ctx, &Role{Name: "PolicyRole"})

	t.Run("create enforces configured strength", func(t *testing.T) {
		_, err := uc.Create(ctx, &User{
			Username: "policy_user",
			RoleID:   role.ID,
			IsActive: true,
		}, "abcdefgh")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))

		created, err := uc.Create(ctx, &User{
			Username: "policy_user",
			RoleID:   role.ID,
			IsActive: true,
		}, "abcd1234")
		require.NoError(t, err)

		t.Run("change password enforces policy", func(t *testing.T) {
			err := uc.ChangePassword(ctx, created.ID, "abcd1234", "onlyletters")
			require.Error(t, err)
			assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))

			require.NoError(t, uc.ChangePassword(ctx, created.ID, "abcd1234", "newpass123"))
		})

		t.Run("reset password enforces policy", func(t *testing.T) {
			err := uc.ResetPassword(ctx, created.ID, "12345678")
			require.Error(t, err)
			assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))

			require.NoError(t, uc.ResetPassword(ctx, created.ID, "resetpass123"))
		})

		t.Run("admin update enforces policy", func(t *testing.T) {
			_, err := uc.Update(ctx, UserUpdate{ID: created.ID, Password: "short"})
			require.Error(t, err)
			assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))
		})
	})
}

func TestUserUseCase_PasswordLifecycle(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	uc := NewUserUseCase(userRepo, roleRepo, nil)

	r, _ := roleRepo.Create(ctx, &Role{Name: "UserRole"})
	user, err := uc.Create(ctx, &User{
		Username: "charlie",
		RoleID:   r.ID,
		IsActive: true,
	}, "oldpassword")
	require.NoError(t, err)

	t.Run("change password wrong old password", func(t *testing.T) {
		err := uc.ChangePassword(ctx, user.ID, "wrongpass", "newpassword123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeAuthFailed))
	})

	t.Run("change password short new password", func(t *testing.T) {
		err := uc.ChangePassword(ctx, user.ID, "oldpassword", "123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))
	})

	t.Run("change password success revokes sessions", func(t *testing.T) {
		err := uc.ChangePassword(ctx, user.ID, "oldpassword", "newpassword123")
		require.NoError(t, err)

		rawUser := userRepo.users[user.ID]
		hasher := cryptoutil.NewBcryptHasher(0)
		valid, _ := hasher.VerifyString("newpassword123", rawUser.Password)
		assert.True(t, valid)
		assert.Greater(t, userRepo.incrementVersionCalled[user.ID], 0)
	})

	t.Run("reset password", func(t *testing.T) {
		err := uc.ResetPassword(ctx, user.ID, "adminresetpass")
		require.NoError(t, err)

		rawUser := userRepo.users[user.ID]
		hasher := cryptoutil.NewBcryptHasher(0)
		valid, _ := hasher.VerifyString("adminresetpass", rawUser.Password)
		assert.True(t, valid)
	})
}

func TestUserUseCase_StatusAndRevocation(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	uc := NewUserUseCase(userRepo, roleRepo, nil)

	r, _ := roleRepo.Create(ctx, &Role{Name: "Role1"})
	u, _ := uc.Create(ctx, &User{Username: "dave", RoleID: r.ID, IsActive: true}, "pass123456")

	t.Run("update status inactive revokes", func(t *testing.T) {
		err := uc.UpdateStatus(ctx, u.ID, false)
		require.NoError(t, err)
		assert.False(t, userRepo.users[u.ID].IsActive)

		// unchanged status returns nil without action
		err = uc.UpdateStatus(ctx, u.ID, false)
		require.NoError(t, err)
	})

	t.Run("revoke sessions", func(t *testing.T) {
		err := uc.RevokeUserSessions(ctx, u.ID)
		require.NoError(t, err)

		err = uc.RevokeRoleSessions(ctx, r.ID)
		require.NoError(t, err)
	})
}

func TestUserUseCase_GetListAndDelete(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	uc := NewUserUseCase(userRepo, roleRepo, nil)

	r, _ := roleRepo.Create(ctx, &Role{Name: "General"})
	user, err := uc.Create(ctx, &User{Username: "helen", RoleID: r.ID, IsActive: true}, "password123")
	require.NoError(t, err)

	t.Run("get by id", func(t *testing.T) {
		got, err := uc.Get(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)
		assert.Empty(t, got.Password)

		_, err = uc.Get(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Get(ctx, 9999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("get by username", func(t *testing.T) {
		got, err := uc.GetByUsername(ctx, "helen")
		require.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)
		assert.Empty(t, got.Password)

		_, err = uc.GetByUsername(ctx, "")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.GetByUsername(ctx, "nonexistent")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("list", func(t *testing.T) {
		list, total, err := uc.List(ctx, db.ListOptions{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, list, 1)
		assert.Empty(t, list[0].Password)
	})

	t.Run("delete", func(t *testing.T) {
		err := uc.Delete(ctx, 0)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		err = uc.Delete(ctx, 9999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

		err = uc.Delete(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, 1, userRepo.incrementVersionCalled[user.ID])

		_, err = uc.Get(ctx, user.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))

		// Deleted usernames stay reserved and cannot be reused.
		_, err = uc.Create(ctx, &User{Username: "helen", RoleID: r.ID, IsActive: true}, "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})
}
