package iam

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	biz "grain/internal/biz/iam"
)

func TestUserRepo_RotateRefreshTokenFamily_FailClosed(t *testing.T) {
	ctx := context.Background()

	// When cache is nil, it must fail closed and return an error
	repo := &userRepo{
		data:   &Data{},
		cache:  nil,
		logger: slog.Default(),
	}

	res, err := repo.RotateRefreshTokenFamily(ctx, "fam-test", "jti-old", "jti-new", 100, time.Hour)
	assert.Equal(t, biz.RotateFamilyFailed, res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache is not initialized")
}

func TestUserRepo_GetTokenVersion_CacheFirst(t *testing.T) {
	ctx := context.Background()
	memCache := NewMemoryUserCache(0)

	// Inject cache with a pre-set token version
	err := memCache.SetTokenVersion(ctx, 101, 7, time.Hour)
	require.NoError(t, err)

	// Construct repo with nil gormdb to ensure that if DB is hit, it will fail/panic
	repo := &userRepo{
		data:       &Data{},
		cache:      memCache,
		logger:     slog.Default(),
		ttlSeconds: 3600,
	}

	// Should read directly from cache without hitting database
	ver, err := repo.GetTokenVersion(ctx, 101)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), ver)
}

func TestUserRepo_GetTokenVersion_Validation(t *testing.T) {
	ctx := context.Background()
	repo := &userRepo{logger: slog.Default()}

	_, err := repo.GetTokenVersion(ctx, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID must not be 0")
}

func TestUserRepo_Create_Validation(t *testing.T) {
	ctx := context.Background()
	repo := &userRepo{logger: slog.Default()}

	// nil model
	_, err := repo.Create(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model must not be nil")

	// empty username
	_, err = repo.Create(ctx, &biz.User{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username cannot be empty")
}

func TestUserRepo_FindByUsername_Empty(t *testing.T) {
	ctx := context.Background()
	repo := &userRepo{logger: slog.Default()}

	// empty username should short-circuit and return (nil, nil)
	u, err := repo.FindByUsername(ctx, "")
	require.NoError(t, err)
	assert.Nil(t, u)
}

func TestUserRepo_InvalidateTokenVersionCache(t *testing.T) {
	ctx := context.Background()
	memCache := NewMemoryUserCache(0)

	err := memCache.SetTokenVersion(ctx, 202, 5, time.Hour)
	require.NoError(t, err)

	repo := &userRepo{
		data:       &Data{},
		cache:      memCache,
		logger:     slog.Default(),
		ttlSeconds: 3600,
	}

	repo.invalidateTokenVersionCache(ctx, 202)

	_, err = memCache.GetTokenVersion(ctx, 202)
	require.ErrorIs(t, err, ErrCacheMiss)
}

func TestUserRepo_IncrementTokenVersionBatch_Empty(t *testing.T) {
	ctx := context.Background()
	repo := &userRepo{logger: slog.Default()}

	err := repo.IncrementTokenVersionBatch(ctx, nil)
	require.NoError(t, err)

	err = repo.IncrementTokenVersionBatch(ctx, []uint64{})
	require.NoError(t, err)
}

func TestUserRepo_CRUD(t *testing.T) {
	data, gormDB, _, memCache := setupTestData(t)
	repo := NewUserRepo(data, slog.Default(), time.Hour, memCache)
	roleRepo := NewRoleRepo(data, slog.Default())
	ctx := context.Background()

	// 0. Pre-create Role
	role, err := roleRepo.Create(ctx, &biz.Role{
		Name: "TestRole",
	})
	require.NoError(t, err)

	// 1. Create User
	userIn := &biz.User{
		Username: "alice",
		Password: "hashed_password",
		IsActive: true,
		RoleID:   role.ID,
	}
	created, err := repo.Create(ctx, userIn)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)
	assert.Equal(t, "alice", created.Username)
	assert.Equal(t, role.ID, created.RoleID)
	assert.NotNil(t, created.Role)
	assert.Equal(t, role.Name, created.Role.Name)

	// 2. FindByID & FindByUsername
	found, err := repo.FindByID(ctx, created.ID, "Role")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)

	notFound, err := repo.FindByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, notFound)

	byName, err := repo.FindByUsername(ctx, "alice", "Role")
	require.NoError(t, err)
	require.NotNil(t, byName)
	assert.Equal(t, created.ID, byName.ID)

	// 3. Update
	created.IsActive = false
	created.Password = "new_password"
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.False(t, updated.IsActive)

	// Update non-existent returns error
	_, err = repo.Update(ctx, &biz.User{ID: 99999, Username: "ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record not found")

	// 4. List & ListIDsByRole
	user2, err := repo.Create(ctx, &biz.User{
		Username: "bob",
		Password: "password_bob",
		IsActive: true,
		RoleID:   role.ID,
	})
	require.NoError(t, err)

	list, total, err := repo.List(ctx, biz.UserListOptions{
		PageSize: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, list, 2)

	roleUserIDs, err := repo.ListIDsByRole(ctx, role.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint64{created.ID, user2.ID}, roleUserIDs)

	emptyRoleIDs, err := repo.ListIDsByRole(ctx, 0)
	require.NoError(t, err)
	assert.Nil(t, emptyRoleIDs)

	// 5. IncrementTokenVersion & Outbox & Cache check
	err = repo.IncrementTokenVersion(ctx, created.ID)
	require.NoError(t, err)

	ver, err := repo.GetTokenVersion(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), ver)

	// Verify outbox entry created and synced
	var outbox TokenRevocationOutboxPO
	err = gormDB.Where("user_id = ? AND version = ?", created.ID, 1).First(&outbox).Error
	require.NoError(t, err)
	assert.Equal(t, "synced", outbox.Status)

	// Invalidate cache to verify GetTokenVersion falls back to DB
	_ = memCache.DeleteTokenVersion(ctx, created.ID)
	verFromDB, err := repo.GetTokenVersion(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), verFromDB)

	// 6. IncrementTokenVersionBatch
	err = repo.IncrementTokenVersionBatch(ctx, []uint64{created.ID, user2.ID})
	require.NoError(t, err)

	verAlice, err := repo.GetTokenVersion(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), verAlice)

	verBob, err := repo.GetTokenVersion(ctx, user2.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), verBob)

	// 7. Delete User (and verify cache eviction)
	err = repo.Delete(ctx, created.ID)
	require.NoError(t, err)

	deleted, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Nil(t, deleted)

	// Delete non-existent
	err = repo.Delete(ctx, 99999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record not found")
}
