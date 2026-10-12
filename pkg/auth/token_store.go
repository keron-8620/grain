package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
)

// ErrTokenVersionNotFound indicates that the token version baseline for a user cannot be found.
var ErrTokenVersionNotFound = errors.New("token version not found")

// TokenVersionStore defines the contract for querying and managing user token revocation versions.
type TokenVersionStore interface {
	GetTokenVersion(ctx context.Context, userID uint32) (uint64, error)
}

// MemoryTokenVersionStore is an in-memory, thread-safe implementation of TokenVersionStore.
// It is ideal for local development, standalone deployments, and fast unit tests.
type MemoryTokenVersionStore struct {
	mu       sync.RWMutex
	versions map[uint32]uint64
}

// NewMemoryTokenVersionStore creates a new MemoryTokenVersionStore instance.
func NewMemoryTokenVersionStore() *MemoryTokenVersionStore {
	return &MemoryTokenVersionStore{
		versions: make(map[uint32]uint64),
	}
}

// GetTokenVersion retrieves the token version for the given user from memory.
func (s *MemoryTokenVersionStore) GetTokenVersion(_ context.Context, userID uint32) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ver, exists := s.versions[userID]
	if !exists {
		return 0, ErrTokenVersionNotFound
	}
	return ver, nil
}

// SetTokenVersion stores or updates the token version for the given user in memory.
func (s *MemoryTokenVersionStore) SetTokenVersion(_ context.Context, userID uint32, version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.versions[userID] = version
	return nil
}

// DeleteTokenVersion removes the token version record for the given user from memory.
func (s *MemoryTokenVersionStore) DeleteTokenVersion(_ context.Context, userID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.versions, userID)
	return nil
}

// RedisTokenVersionStore is a Redis-backed implementation of TokenVersionStore.
type RedisTokenVersionStore struct {
	client redis.UniversalClient
}

// NewRedisTokenVersionStore creates a new RedisTokenVersionStore wrapping a Redis client.
func NewRedisTokenVersionStore(client redis.UniversalClient) *RedisTokenVersionStore {
	return &RedisTokenVersionStore{
		client: client,
	}
}

// GetTokenVersion retrieves the token version for the given user from Redis.
func (s *RedisTokenVersionStore) GetTokenVersion(ctx context.Context, userID uint32) (uint64, error) {
	if s.client == nil {
		return 0, fmt.Errorf("redis client is not configured")
	}

	key := UserTokenVersionKey(userID)
	ver, err := s.client.Get(ctx, key).Uint64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, ErrTokenVersionNotFound
		}
		return 0, err
	}
	return ver, nil
}

// SetTokenVersion stores or updates the token version for the given user in Redis.
func (s *RedisTokenVersionStore) SetTokenVersion(ctx context.Context, userID uint32, version uint64) error {
	if s.client == nil {
		return fmt.Errorf("redis client is not configured")
	}

	key := UserTokenVersionKey(userID)
	return s.client.Set(ctx, key, version, 0).Err()
}

// DeleteTokenVersion removes the token version record for the given user from Redis.
func (s *RedisTokenVersionStore) DeleteTokenVersion(ctx context.Context, userID uint32) error {
	if s.client == nil {
		return fmt.Errorf("redis client is not configured")
	}

	key := UserTokenVersionKey(userID)
	return s.client.Del(ctx, key).Err()
}
