package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func seedAdminRole(t *testing.T, gormDB *gorm.DB) rolePO {
	t.Helper()
	role := rolePO{Name: "admin", Descr: "超级管理员"}
	require.NoError(t, gormDB.Create(&role).Error)
	return role
}

func TestLegacyDefaultAdminHash(t *testing.T) {
	// Guards against accidentally "fixing" the constant and re-introducing a
	// known credential somewhere else.
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(LegacyDefaultAdminPasswordHash), []byte("Admin@123456")))
	require.Error(t, bcrypt.CompareHashAndPassword([]byte(LegacyDefaultAdminPasswordHash), []byte("admin")))
}

func TestBootstrapAdmin(t *testing.T) {
	ctx := context.Background()

	t.Run("creates the initial admin", func(t *testing.T) {
		gormDB := setupTestDB(t)
		role := seedAdminRole(t, gormDB)

		action, err := BootstrapAdmin(ctx, gormDB, "admin", "new-hash")
		require.NoError(t, err)
		assert.Equal(t, BootstrapCreated, action)

		var user userPO
		require.NoError(t, gormDB.Where("username = ?", "admin").Take(&user).Error)
		assert.Equal(t, role.ID, user.RoleID)
		assert.True(t, user.IsActive)
		assert.Equal(t, "new-hash", user.Password)
		assert.Zero(t, user.TokenVersion)

		legacy, err := HasLegacyDefaultAdmin(ctx, gormDB)
		require.NoError(t, err)
		assert.False(t, legacy)
	})

	t.Run("refuses to overwrite a non-default password", func(t *testing.T) {
		gormDB := setupTestDB(t)
		role := seedAdminRole(t, gormDB)
		require.NoError(t, gormDB.Create(&userPO{
			Username: "admin", Password: "existing-hash", IsActive: true, RoleID: role.ID,
		}).Error)

		_, err := BootstrapAdmin(ctx, gormDB, "admin", "new-hash")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")

		var user userPO
		require.NoError(t, gormDB.Where("username = ?", "admin").Take(&user).Error)
		assert.Equal(t, "existing-hash", user.Password)
	})

	t.Run("resets an account that still uses the leaked default password", func(t *testing.T) {
		gormDB := setupTestDB(t)
		role := seedAdminRole(t, gormDB)
		require.NoError(t, gormDB.Create(&userPO{
			Username: "admin", Password: LegacyDefaultAdminPasswordHash, IsActive: true, RoleID: role.ID,
		}).Error)

		legacy, err := HasLegacyDefaultAdmin(ctx, gormDB)
		require.NoError(t, err)
		require.True(t, legacy)
		accounts, err := LegacyDefaultAdminAccounts(ctx, gormDB)
		require.NoError(t, err)
		assert.Equal(t, []string{"admin"}, accounts)

		action, err := BootstrapAdmin(ctx, gormDB, "admin", "rotated-hash")
		require.NoError(t, err)
		assert.Equal(t, BootstrapReset, action)

		var user userPO
		require.NoError(t, gormDB.Where("username = ?", "admin").Take(&user).Error)
		assert.Equal(t, "rotated-hash", user.Password)
		assert.EqualValues(t, 1, user.TokenVersion, "reset must invalidate existing sessions")

		legacy, err = HasLegacyDefaultAdmin(ctx, gormDB)
		require.NoError(t, err)
		assert.False(t, legacy)
	})

	t.Run("fails when the admin role is missing", func(t *testing.T) {
		gormDB := setupTestDB(t)

		_, err := BootstrapAdmin(ctx, gormDB, "admin", "new-hash")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admin")
	})

	t.Run("rejects empty input", func(t *testing.T) {
		gormDB := setupTestDB(t)
		_, err := BootstrapAdmin(ctx, gormDB, " ", "new-hash")
		require.Error(t, err)
		_, err = BootstrapAdmin(ctx, gormDB, "admin", " ")
		require.Error(t, err)
	})
}

func TestHasLegacyDefaultAdminWithoutTables(t *testing.T) {
	gormDB := setupTestDB(t)
	require.NoError(t, gormDB.Migrator().DropTable(&userPO{}))

	legacy, err := HasLegacyDefaultAdmin(context.Background(), gormDB)
	require.NoError(t, err)
	assert.False(t, legacy, "a database that has not been migrated yet is not a legacy admin")
}
