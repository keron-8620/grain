package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryTokenVersionStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTokenVersionStore()

	t.Run("key not found returns ErrTokenVersionNotFound", func(t *testing.T) {
		ver, err := store.GetTokenVersion(ctx, 1001)
		assert.ErrorIs(t, err, ErrTokenVersionNotFound)
		assert.Equal(t, uint64(0), ver)
	})

	t.Run("set and get token version", func(t *testing.T) {
		err := store.SetTokenVersion(ctx, 1001, 10)
		require.NoError(t, err)

		ver, err := store.GetTokenVersion(ctx, 1001)
		require.NoError(t, err)
		assert.Equal(t, uint64(10), ver)
	})

	t.Run("update token version", func(t *testing.T) {
		err := store.SetTokenVersion(ctx, 1001, 11)
		require.NoError(t, err)

		ver, err := store.GetTokenVersion(ctx, 1001)
		require.NoError(t, err)
		assert.Equal(t, uint64(11), ver)
	})

	t.Run("delete token version", func(t *testing.T) {
		err := store.DeleteTokenVersion(ctx, 1001)
		require.NoError(t, err)

		ver, err := store.GetTokenVersion(ctx, 1001)
		assert.ErrorIs(t, err, ErrTokenVersionNotFound)
		assert.Equal(t, uint64(0), ver)
	})

	t.Run("session family revocation and ttl in memory", func(t *testing.T) {
		// Initially not revoked
		revoked, err := store.IsFamilyRevoked(ctx, "fam-1")
		require.NoError(t, err)
		assert.False(t, revoked)

		// Empty family ID returns false
		revoked, err = store.IsFamilyRevoked(ctx, "")
		require.NoError(t, err)
		assert.False(t, revoked)

		// Revoke with empty family ID errors
		err = store.RevokeFamily(ctx, "", 0)
		assert.Error(t, err)

		// Revoke indefinitely
		err = store.RevokeFamily(ctx, "fam-1", 0)
		require.NoError(t, err)

		revoked, err = store.IsFamilyRevoked(ctx, "fam-1")
		require.NoError(t, err)
		assert.True(t, revoked)

		// Revoke with short TTL
		err = store.RevokeFamily(ctx, "fam-expiring", 20*time.Millisecond)
		require.NoError(t, err)

		revoked, err = store.IsFamilyRevoked(ctx, "fam-expiring")
		require.NoError(t, err)
		assert.True(t, revoked)

		time.Sleep(30 * time.Millisecond)
		revoked, err = store.IsFamilyRevoked(ctx, "fam-expiring")
		require.NoError(t, err)
		assert.False(t, revoked)
		// Lazy eviction verified: entry was deleted from memory map
		assert.Equal(t, 1, store.RevokedFamiliesCount()) // only fam-1 remains

		// Delete family revocation
		err = store.DeleteFamilyRevocation(ctx, "fam-1")
		require.NoError(t, err)
		assert.Equal(t, 0, store.RevokedFamiliesCount())

		revoked, err = store.IsFamilyRevoked(ctx, "fam-1")
		require.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("batch token and family revocation check in memory", func(t *testing.T) {
		memStore := NewMemoryTokenVersionStore()
		// Key not found
		ver, revoked, err := memStore.GetTokenAndFamilyRevocation(ctx, 999, "fam-test")
		assert.ErrorIs(t, err, ErrTokenVersionNotFound)
		assert.Equal(t, uint64(0), ver)
		assert.False(t, revoked)

		// Set version
		require.NoError(t, memStore.SetTokenVersion(ctx, 999, 5))

		// Version exists, family not revoked
		ver, revoked, err = memStore.GetTokenAndFamilyRevocation(ctx, 999, "fam-test")
		require.NoError(t, err)
		assert.Equal(t, uint64(5), ver)
		assert.False(t, revoked)

		// Empty family
		ver, revoked, err = memStore.GetTokenAndFamilyRevocation(ctx, 999, "")
		require.NoError(t, err)
		assert.Equal(t, uint64(5), ver)
		assert.False(t, revoked)

		// Revoke family
		require.NoError(t, memStore.RevokeFamily(ctx, "fam-test", 0))
		ver, revoked, err = memStore.GetTokenAndFamilyRevocation(ctx, 999, "fam-test")
		require.NoError(t, err)
		assert.Equal(t, uint64(5), ver)
		assert.True(t, revoked)

		// Short TTL family
		require.NoError(t, memStore.RevokeFamily(ctx, "fam-ttl", 20*time.Millisecond))
		ver, revoked, err = memStore.GetTokenAndFamilyRevocation(ctx, 999, "fam-ttl")
		require.NoError(t, err)
		assert.True(t, revoked)
		time.Sleep(30 * time.Millisecond)
		ver, revoked, err = memStore.GetTokenAndFamilyRevocation(ctx, 999, "fam-ttl")
		require.NoError(t, err)
		assert.False(t, revoked)
	})
}

func TestRedisTokenVersionStore(t *testing.T) {
	ctx := context.Background()

	t.Run("nil redis client returns error", func(t *testing.T) {
		store := NewRedisTokenVersionStore(nil)

		ver, err := store.GetTokenVersion(ctx, 1)
		assert.Error(t, err)
		assert.Equal(t, uint64(0), ver)
		assert.Contains(t, err.Error(), "redis client is not configured")

		err = store.SetTokenVersion(ctx, 1, 5)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis client is not configured")

		err = store.DeleteTokenVersion(ctx, 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis client is not configured")

		_, err = store.IsFamilyRevoked(ctx, "fam-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis client is not configured")

		err = store.RevokeFamily(ctx, "fam-1", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis client is not configured")

		err = store.DeleteFamilyRevocation(ctx, "fam-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis client is not configured")
	})

	t.Run("set get and delete with mock redis", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		store := NewRedisTokenVersionStore(rdb)
		assert.Equal(t, time.Duration(0), store.TTL())

		// Key not found
		ver, err := store.GetTokenVersion(ctx, 2001)
		assert.ErrorIs(t, err, ErrTokenVersionNotFound)
		assert.Equal(t, uint64(0), ver)

		// Set
		err = store.SetTokenVersion(ctx, 2001, 42)
		require.NoError(t, err)

		// Get
		ver, err = store.GetTokenVersion(ctx, 2001)
		require.NoError(t, err)
		assert.Equal(t, uint64(42), ver)

		// Delete
		err = store.DeleteTokenVersion(ctx, 2001)
		require.NoError(t, err)

		// Get again
		ver, err = store.GetTokenVersion(ctx, 2001)
		assert.ErrorIs(t, err, ErrTokenVersionNotFound)
		assert.Equal(t, uint64(0), ver)
	})

	t.Run("configured with default TTL option", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		store := NewRedisTokenVersionStore(rdb, WithTokenVersionTTL(2*time.Hour))
		assert.Equal(t, 2*time.Hour, store.TTL())

		err := store.SetTokenVersion(ctx, 3001, 100)
		require.NoError(t, err)

		ver, err := store.GetTokenVersion(ctx, 3001)
		require.NoError(t, err)
		assert.Equal(t, uint64(100), ver)
	})

	t.Run("SetTokenVersionWithTTL overrides TTL", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		store := NewRedisTokenVersionStore(rdb, WithTokenVersionTTL(1*time.Hour))

		// Write with explicit custom TTL
		err := store.SetTokenVersionWithTTL(ctx, 3002, 105, 30*time.Minute)
		require.NoError(t, err)

		ver, err := store.GetTokenVersion(ctx, 3002)
		require.NoError(t, err)
		assert.Equal(t, uint64(105), ver)

		// Negative TTL normalizes to 0
		err = store.SetTokenVersionWithTTL(ctx, 3003, 106, -5*time.Second)
		require.NoError(t, err)

		ver, err = store.GetTokenVersion(ctx, 3003)
		require.NoError(t, err)
		assert.Equal(t, uint64(106), ver)
	})

	t.Run("session family revocation with mock redis", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		store := NewRedisTokenVersionStore(rdb)

		// Initially not revoked
		revoked, err := store.IsFamilyRevoked(ctx, "fam-redis-1")
		require.NoError(t, err)
		assert.False(t, revoked)

		// Empty family ID returns false
		revoked, err = store.IsFamilyRevoked(ctx, "  ")
		require.NoError(t, err)
		assert.False(t, revoked)

		// Revoke with empty family ID errors
		err = store.RevokeFamily(ctx, "", 0)
		assert.Error(t, err)

		// Revoke family
		err = store.RevokeFamily(ctx, "fam-redis-1", 1*time.Hour)
		require.NoError(t, err)

		revoked, err = store.IsFamilyRevoked(ctx, "fam-redis-1")
		require.NoError(t, err)
		assert.True(t, revoked)

		// Delete family revocation
		err = store.DeleteFamilyRevocation(ctx, "fam-redis-1")
		require.NoError(t, err)

		revoked, err = store.IsFamilyRevoked(ctx, "fam-redis-1")
		require.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("GetTokenAndFamilyRevocation with pipeline", func(t *testing.T) {
		// Nil client
		nilStore := NewRedisTokenVersionStore(nil)
		_, _, err := nilStore.GetTokenAndFamilyRevocation(ctx, 1, "fam-1")
		assert.Error(t, err)

		_, rdb := startMockRedis(t)
		redisStore := NewRedisTokenVersionStore(rdb)

		// Missing token version
		ver, revoked, err := redisStore.GetTokenAndFamilyRevocation(ctx, 5001, "fam-5001")
		assert.ErrorIs(t, err, ErrTokenVersionNotFound)
		assert.Equal(t, uint64(0), ver)
		assert.False(t, revoked)

		// Set token version
		require.NoError(t, redisStore.SetTokenVersion(ctx, 5001, 10))

		// Token version present, family not revoked
		ver, revoked, err = redisStore.GetTokenAndFamilyRevocation(ctx, 5001, "fam-5001")
		require.NoError(t, err)
		assert.Equal(t, uint64(10), ver)
		assert.False(t, revoked)

		// Empty familyID
		ver, revoked, err = redisStore.GetTokenAndFamilyRevocation(ctx, 5001, "")
		require.NoError(t, err)
		assert.Equal(t, uint64(10), ver)
		assert.False(t, revoked)

		// Revoke family
		require.NoError(t, redisStore.RevokeFamily(ctx, "fam-5001", 0))

		// Both version and revoked family returned in 1 call
		ver, revoked, err = redisStore.GetTokenAndFamilyRevocation(ctx, 5001, "fam-5001")
		require.NoError(t, err)
		assert.Equal(t, uint64(10), ver)
		assert.True(t, revoked)
	})
}

func TestMemoryTokenVersionStore_Eviction(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTokenVersionStore()

	// 1. Test CleanExpired
	require.NoError(t, store.RevokeFamily(ctx, "fam-exp1", 10*time.Millisecond))
	require.NoError(t, store.RevokeFamily(ctx, "fam-exp2", 10*time.Millisecond))
	require.NoError(t, store.RevokeFamily(ctx, "fam-perm", 0))

	assert.Equal(t, 3, store.RevokedFamiliesCount())
	time.Sleep(20 * time.Millisecond)

	cleaned := store.CleanExpired()
	assert.Equal(t, 2, cleaned)
	assert.Equal(t, 1, store.RevokedFamiliesCount())

	// 2. Test GetTokenAndFamilyRevocation lazy eviction
	require.NoError(t, store.SetTokenVersion(ctx, 100, 1))
	require.NoError(t, store.RevokeFamily(ctx, "fam-lazy", 10*time.Millisecond))
	assert.Equal(t, 2, store.RevokedFamiliesCount())

	time.Sleep(20 * time.Millisecond)
	ver, revoked, err := store.GetTokenAndFamilyRevocation(ctx, 100, "fam-lazy")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), ver)
	assert.False(t, revoked)
	// fam-lazy evicted lazily
	assert.Equal(t, 1, store.RevokedFamiliesCount())

	// 3. Test threshold cleanup on RevokeFamily (>32 items)
	bigStore := NewMemoryTokenVersionStore()
	for i := range 35 {
		require.NoError(t, bigStore.RevokeFamily(ctx, "expiring-"+string(rune('A'+i)), 10*time.Millisecond))
	}
	time.Sleep(20 * time.Millisecond)
	// Inserting one more item should trigger cleanExpiredFamiliesLocked
	require.NoError(t, bigStore.RevokeFamily(ctx, "new-item", 1*time.Hour))
	// All 35 expired items should have been cleaned up
	assert.Equal(t, 1, bigStore.RevokedFamiliesCount())
}
