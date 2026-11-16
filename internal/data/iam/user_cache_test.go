package iam

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	biz "grain/internal/biz/iam"
)

func TestMemoryUserCache_TokenVersion(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryUserCache(0) // disable background cleanup in unit test
	defer func() {
		if c, ok := cache.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}()

	t.Run("missing key returns ErrCacheMiss", func(t *testing.T) {
		ver, err := cache.GetTokenVersion(ctx, 101)
		assert.ErrorIs(t, err, ErrCacheMiss)
		assert.Equal(t, uint64(0), ver)
	})

	t.Run("set and get token version", func(t *testing.T) {
		err := cache.SetTokenVersion(ctx, 101, 5, time.Hour)
		require.NoError(t, err)

		ver, err := cache.GetTokenVersion(ctx, 101)
		require.NoError(t, err)
		assert.Equal(t, uint64(5), ver)
	})

	t.Run("monotonic update ignores lower or equal versions", func(t *testing.T) {
		// Set to lower version 3: should be ignored
		err := cache.SetTokenVersion(ctx, 101, 3, time.Hour)
		require.NoError(t, err)

		ver, err := cache.GetTokenVersion(ctx, 101)
		require.NoError(t, err)
		assert.Equal(t, uint64(5), ver)

		// Set to equal version 5: should be ignored
		err = cache.SetTokenVersion(ctx, 101, 5, time.Hour)
		require.NoError(t, err)

		ver, err = cache.GetTokenVersion(ctx, 101)
		require.NoError(t, err)
		assert.Equal(t, uint64(5), ver)

		// Set to higher version 8: should update
		err = cache.SetTokenVersion(ctx, 101, 8, time.Hour)
		require.NoError(t, err)

		ver, err = cache.GetTokenVersion(ctx, 101)
		require.NoError(t, err)
		assert.Equal(t, uint64(8), ver)
	})

	t.Run("delete token version", func(t *testing.T) {
		err := cache.DeleteTokenVersion(ctx, 101)
		require.NoError(t, err)

		ver, err := cache.GetTokenVersion(ctx, 101)
		assert.ErrorIs(t, err, ErrCacheMiss)
		assert.Equal(t, uint64(0), ver)
	})

	t.Run("token version TTL expiration", func(t *testing.T) {
		err := cache.SetTokenVersion(ctx, 202, 1, 30*time.Millisecond)
		require.NoError(t, err)

		ver, err := cache.GetTokenVersion(ctx, 202)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), ver)

		time.Sleep(50 * time.Millisecond)

		ver, err = cache.GetTokenVersion(ctx, 202)
		assert.ErrorIs(t, err, ErrCacheMiss)
		assert.Equal(t, uint64(0), ver)
	})
}

func TestMemoryUserCache_ConsumeRefreshToken(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryUserCache(0)
	defer func() {
		if c, ok := cache.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}()

	t.Run("first consume succeeds, second fails", func(t *testing.T) {
		ok, err := cache.ConsumeRefreshToken(ctx, "jti-test-1", time.Hour)
		require.NoError(t, err)
		assert.True(t, ok)

		// Second consume with same jti fails
		ok, err = cache.ConsumeRefreshToken(ctx, "jti-test-1", time.Hour)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("consume TTL expiration", func(t *testing.T) {
		ok, err := cache.ConsumeRefreshToken(ctx, "jti-test-expire", 30*time.Millisecond)
		require.NoError(t, err)
		assert.True(t, ok)

		time.Sleep(50 * time.Millisecond)

		// After expiration, should be consumable again
		ok, err = cache.ConsumeRefreshToken(ctx, "jti-test-expire", time.Hour)
		require.NoError(t, err)
		assert.True(t, ok)
	})
}

func TestMemoryUserCache_RotateRefreshTokenFamily(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryUserCache(0)
	defer func() {
		if c, ok := cache.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}()

	familyID := "fam-1"
	userID := uint64(10)
	ttl := time.Hour

	t.Run("initial rotation succeeds", func(t *testing.T) {
		res, err := cache.RotateRefreshTokenFamily(ctx, familyID, "token-1", "token-2", userID, ttl)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilySuccess, res)
	})

	t.Run("sequential normal rotation succeeds", func(t *testing.T) {
		res, err := cache.RotateRefreshTokenFamily(ctx, familyID, "token-2", "token-3", userID, ttl)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilySuccess, res)

		res, err = cache.RotateRefreshTokenFamily(ctx, familyID, "token-3", "token-4", userID, ttl)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilySuccess, res)
	})

	t.Run("replay attack with consumed token marks family compromised", func(t *testing.T) {
		// token-2 was already rotated in the step above
		res, err := cache.RotateRefreshTokenFamily(ctx, familyID, "token-2", "token-evil", userID, ttl)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilyCompromised, res)

		// Once compromised, even the previously valid current token is rejected
		res, err = cache.RotateRefreshTokenFamily(ctx, familyID, "token-4", "token-5", userID, ttl)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilyCompromised, res)
	})

	t.Run("replay attack with unknown old token marks family compromised", func(t *testing.T) {
		fam2 := "fam-2"
		res, err := cache.RotateRefreshTokenFamily(ctx, fam2, "tok-a", "tok-b", userID, ttl)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilySuccess, res)

		// Attempt rotation with mismatched old token (neither current nor in consumed)
		res, err = cache.RotateRefreshTokenFamily(ctx, fam2, "tok-unknown", "tok-c", userID, ttl)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilyCompromised, res)
	})
}

func TestMemoryUserCache_Cleanup(t *testing.T) {
	cache := NewMemoryUserCache(0).(*memoryUserCache)

	ctx := context.Background()
	_ = cache.SetTokenVersion(ctx, 1, 10, 20*time.Millisecond)
	_, _ = cache.ConsumeRefreshToken(ctx, "jti-cleanup", 20*time.Millisecond)
	_, _ = cache.RotateRefreshTokenFamily(ctx, "fam-cleanup", "t1", "t2", 1, 20*time.Millisecond)

	time.Sleep(40 * time.Millisecond)

	cache.cleanup()

	cache.mu.RLock()
	assert.Len(t, cache.tokenVersions, 0)
	assert.Len(t, cache.consumedTokens, 0)
	assert.Len(t, cache.families, 0)
	cache.mu.RUnlock()
}

func TestMemoryUserCache_ContextCancellation(t *testing.T) {
	cache := NewMemoryUserCache(0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := cache.GetTokenVersion(ctx, 1)
	assert.ErrorIs(t, err, context.Canceled)

	err = cache.SetTokenVersion(ctx, 1, 2, time.Hour)
	assert.ErrorIs(t, err, context.Canceled)

	err = cache.DeleteTokenVersion(ctx, 1)
	assert.ErrorIs(t, err, context.Canceled)

	_, err = cache.ConsumeRefreshToken(ctx, "jti", time.Hour)
	assert.ErrorIs(t, err, context.Canceled)

	_, err = cache.RotateRefreshTokenFamily(ctx, "fam", "old", "new", 1, time.Hour)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMemoryUserCache_Concurrency(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryUserCache(0)

	var wg sync.WaitGroup
	// Concurrently consume the same token 50 times; exactly one must return true
	successCount := 0
	var mu sync.Mutex
	token := "concurrent-jti"

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := cache.ConsumeRefreshToken(ctx, token, time.Hour)
			if err == nil && ok {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, 1, successCount, "exactly one concurrent consume must succeed")
}

func TestRedisUserCache_NilClient(t *testing.T) {
	ctx := context.Background()
	rc := NewRedisUserCache(nil)

	_, err := rc.GetTokenVersion(ctx, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")

	err = rc.SetTokenVersion(ctx, 1, 2, time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")

	err = rc.DeleteTokenVersion(ctx, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")

	_, err = rc.ConsumeRefreshToken(ctx, "jti", time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")

	res, err := rc.RotateRefreshTokenFamily(ctx, "fam", "old", "new", 1, time.Hour)
	assert.Equal(t, biz.RotateFamilyFailed, res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")

	_, err = rc.IncrementLoginFailure(ctx, "alice", time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")

	_, err = rc.GetLoginFailure(ctx, "alice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")

	err = rc.DeleteLoginFailure(ctx, "alice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is not configured")
}

func TestMemoryUserCache_LoginFailure(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryUserCache(0)

	count, err := cache.GetLoginFailure(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	for i := int64(1); i <= 3; i++ {
		count, err = cache.IncrementLoginFailure(ctx, "alice", time.Minute)
		require.NoError(t, err)
		assert.Equal(t, i, count)
	}

	require.NoError(t, cache.DeleteLoginFailure(ctx, "alice"))
	count, err = cache.GetLoginFailure(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	_, err = cache.IncrementLoginFailure(ctx, "bob", 5*time.Millisecond)
	require.NoError(t, err)
	time.Sleep(15 * time.Millisecond)
	count, err = cache.GetLoginFailure(ctx, "bob")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "expired counters must reset")
}

func TestUserRepo_CacheSelection(t *testing.T) {
	t.Run("defaults to memory cache when redis is nil", func(t *testing.T) {
		data := &Data{}
		repo := NewUserRepo(data, nil, time.Hour)
		ur, ok := repo.(*userRepo)
		require.True(t, ok)
		assert.NotNil(t, ur.cache)
		_, isMemory := ur.cache.(*memoryUserCache)
		assert.True(t, isMemory, "expected memoryUserCache when redis is nil")
	})

	t.Run("uses explicitly provided cache in constructor", func(t *testing.T) {
		customCache := NewMemoryUserCache(0)
		repo := NewUserRepo(&Data{}, nil, time.Hour, customCache)
		ur, ok := repo.(*userRepo)
		require.True(t, ok)
		assert.Equal(t, customCache, ur.cache)
	})

	t.Run("uses data.userCache when configured", func(t *testing.T) {
		customCache := NewMemoryUserCache(0)
		data := &Data{}
		data.SetUserCache(customCache)
		assert.Equal(t, customCache, data.UserCache())

		repo := NewUserRepo(data, nil, time.Hour)
		ur, ok := repo.(*userRepo)
		require.True(t, ok)
		assert.Equal(t, customCache, ur.cache)
	})
}

func TestUserRepo_CacheIntegration(t *testing.T) {
	ctx := context.Background()
	memCache := NewMemoryUserCache(0)
	repo := NewUserRepo(&Data{}, nil, time.Hour, memCache)

	t.Run("EnsureTokenVersionCache and ConsumeRefreshToken", func(t *testing.T) {
		err := repo.EnsureTokenVersionCache(ctx, 501, 3)
		require.NoError(t, err)

		ver, err := memCache.GetTokenVersion(ctx, 501)
		require.NoError(t, err)
		assert.Equal(t, uint64(3), ver)

		ok, err := repo.ConsumeRefreshToken(ctx, "jti-repo-test", time.Hour)
		require.NoError(t, err)
		assert.True(t, ok)

		// Second consume fails
		ok, err = repo.ConsumeRefreshToken(ctx, "jti-repo-test", time.Hour)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("RotateRefreshTokenFamily", func(t *testing.T) {
		res, err := repo.RotateRefreshTokenFamily(ctx, "fam-repo", "jti-1", "jti-2", 501, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilySuccess, res)

		res, err = repo.RotateRefreshTokenFamily(ctx, "fam-repo", "jti-2", "jti-3", 501, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilySuccess, res)

		// Replay
		res, err = repo.RotateRefreshTokenFamily(ctx, "fam-repo", "jti-2", "jti-evil", 501, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, biz.RotateFamilyCompromised, res)
	})
}
