package auth

import (
	"context"
	"testing"

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
	})

	t.Run("set get and delete with mock redis", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		store := NewRedisTokenVersionStore(rdb)

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
}
