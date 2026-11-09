package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/redis/go-redis/v9"
)

// ErrTokenVersionNotFound indicates that the token version baseline for a user cannot be found.
var ErrTokenVersionNotFound = errors.New("token version not found")

// TokenVersionStore defines the contract for querying and managing user token revocation versions.
type TokenVersionStore interface {
	GetTokenVersion(ctx context.Context, userID uint64) (uint64, error)
}

// FamilyRevocationStore defines the contract for querying and managing session family (fid) revocation.
type FamilyRevocationStore interface {
	// IsFamilyRevoked reports whether the session family has been revoked.
	IsFamilyRevoked(ctx context.Context, familyID string) (bool, error)
	// RevokeFamily marks a session family as revoked. ttl determines how long the revocation is tracked.
	// A duration <= 0 retains the revocation indefinitely until explicit deletion.
	RevokeFamily(ctx context.Context, familyID string, ttl time.Duration) error
	// DeleteFamilyRevocation removes the revocation record for the session family.
	DeleteFamilyRevocation(ctx context.Context, familyID string) error
}

// BatchRevocationStore allows querying user token version and session family revocation in a single round-trip.
type BatchRevocationStore interface {
	GetTokenAndFamilyRevocation(ctx context.Context, userID uint64, familyID string) (version uint64, familyRevoked bool, err error)
}

// BatchTokenRevocationStore is a type alias for BatchRevocationStore.
type BatchTokenRevocationStore = BatchRevocationStore

// TokenRevocationStore is a composite interface that satisfies user token version checking,
// session family revocation, and batch query optimizations.
type TokenRevocationStore interface {
	TokenVersionStore
	FamilyRevocationStore
	BatchRevocationStore
}

// MemoryTokenVersionStore is an in-memory, thread-safe implementation of TokenRevocationStore.
// It is ideal for local development, standalone deployments, and fast unit tests.
type MemoryTokenVersionStore struct {
	mu              sync.RWMutex
	versions        map[uint64]uint64
	revokedFamilies map[string]time.Time
}

// NewMemoryTokenVersionStore creates a new MemoryTokenVersionStore instance.
func NewMemoryTokenVersionStore() *MemoryTokenVersionStore {
	return &MemoryTokenVersionStore{
		versions:        make(map[uint64]uint64),
		revokedFamilies: make(map[string]time.Time),
	}
}

// GetTokenVersion retrieves the token version for the given user from memory.
func (s *MemoryTokenVersionStore) GetTokenVersion(_ context.Context, userID uint64) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ver, exists := s.versions[userID]
	if !exists {
		return 0, ErrTokenVersionNotFound
	}
	return ver, nil
}

// SetTokenVersion stores or updates the token version for the given user in memory.
func (s *MemoryTokenVersionStore) SetTokenVersion(_ context.Context, userID uint64, version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.versions[userID] = version
	return nil
}

// DeleteTokenVersion removes the token version record for the given user from memory.
func (s *MemoryTokenVersionStore) DeleteTokenVersion(_ context.Context, userID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.versions, userID)
	return nil
}

// lazyDeleteExpiredFamily removes an expired family revocation record under a write lock.
func (s *MemoryTokenVersionStore) lazyDeleteExpiredFamily(familyID string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, exists := s.revokedFamilies[familyID]; exists && !exp.IsZero() && now.After(exp) {
		delete(s.revokedFamilies, familyID)
	}
}

// cleanExpiredFamiliesLocked removes expired family revocation records. Must be called with s.mu write-locked.
func (s *MemoryTokenVersionStore) cleanExpiredFamiliesLocked(now time.Time) {
	for k, exp := range s.revokedFamilies {
		if !exp.IsZero() && now.After(exp) {
			delete(s.revokedFamilies, k)
		}
	}
}

// CleanExpired removes all expired session family revocation records from memory and returns the count.
func (s *MemoryTokenVersionStore) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for k, exp := range s.revokedFamilies {
		if !exp.IsZero() && now.After(exp) {
			delete(s.revokedFamilies, k)
			cleaned++
		}
	}
	return cleaned
}

// RevokedFamiliesCount returns the number of session family entries currently in memory.
func (s *MemoryTokenVersionStore) RevokedFamiliesCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.revokedFamilies)
}

// IsFamilyRevoked reports whether the given session family has been revoked in memory.
// If an expired entry is encountered, it is lazily evicted.
func (s *MemoryTokenVersionStore) IsFamilyRevoked(_ context.Context, familyID string) (bool, error) {
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return false, nil
	}
	s.mu.RLock()
	exp, exists := s.revokedFamilies[familyID]
	s.mu.RUnlock()

	if !exists {
		return false, nil
	}
	now := time.Now()
	if !exp.IsZero() && now.After(exp) {
		s.lazyDeleteExpiredFamily(familyID, now)
		return false, nil
	}
	return true, nil
}

// RevokeFamily marks a session family as revoked in memory with an expiration duration.
// A duration <= 0 disables expiration.
func (s *MemoryTokenVersionStore) RevokeFamily(_ context.Context, familyID string, ttl time.Duration) error {
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return errors.New("family ID must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if len(s.revokedFamilies) > 32 {
		s.cleanExpiredFamiliesLocked(now)
	}

	var exp time.Time
	if ttl > 0 {
		exp = now.Add(ttl)
	}
	s.revokedFamilies[familyID] = exp
	return nil
}

// DeleteFamilyRevocation removes the revocation record for the session family from memory.
func (s *MemoryTokenVersionStore) DeleteFamilyRevocation(_ context.Context, familyID string) error {
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.revokedFamilies, familyID)
	return nil
}

// GetTokenAndFamilyRevocation atomically retrieves the token version and checks family revocation status in memory.
// If an expired family revocation is encountered, it is lazily evicted.
func (s *MemoryTokenVersionStore) GetTokenAndFamilyRevocation(_ context.Context, userID uint64, familyID string) (uint64, bool, error) {
	s.mu.RLock()
	ver, exists := s.versions[userID]
	if !exists {
		s.mu.RUnlock()
		return 0, false, ErrTokenVersionNotFound
	}

	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		s.mu.RUnlock()
		return ver, false, nil
	}

	exp, fExists := s.revokedFamilies[familyID]
	s.mu.RUnlock()

	if !fExists {
		return ver, false, nil
	}
	now := time.Now()
	if !exp.IsZero() && now.After(exp) {
		s.lazyDeleteExpiredFamily(familyID, now)
		return ver, false, nil
	}
	return ver, true, nil
}

// RedisTokenVersionStore is a Redis-backed implementation of TokenVersionStore.
type RedisTokenVersionStore struct {
	client redis.UniversalClient
	ttl    time.Duration
}

// RedisTokenVersionStoreOption configures a RedisTokenVersionStore.
type RedisTokenVersionStoreOption func(*RedisTokenVersionStore)

// WithTokenVersionTTL configures the default TTL duration for user token version records in Redis.
// A duration <= 0 disables expiration (keys persist indefinitely until explicitly deleted or evicted).
func WithTokenVersionTTL(ttl time.Duration) RedisTokenVersionStoreOption {
	return func(s *RedisTokenVersionStore) {
		s.ttl = max(ttl, 0)
	}
}

// NewRedisTokenVersionStore creates a new RedisTokenVersionStore wrapping a Redis client.
func NewRedisTokenVersionStore(client redis.UniversalClient, opts ...RedisTokenVersionStoreOption) *RedisTokenVersionStore {
	store := &RedisTokenVersionStore{
		client: client,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(store)
		}
	}
	return store
}

// TTL returns the configured default TTL for token version records.
func (s *RedisTokenVersionStore) TTL() time.Duration {
	return s.ttl
}

// GetTokenVersion retrieves the token version for the given user from Redis.
func (s *RedisTokenVersionStore) GetTokenVersion(ctx context.Context, userID uint64) (uint64, error) {
	if s.client == nil {
		return 0, errors.New("redis client is not configured")
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

// SetTokenVersion stores or updates the token version for the given user in Redis using the configured default TTL.
func (s *RedisTokenVersionStore) SetTokenVersion(ctx context.Context, userID uint64, version uint64) error {
	return s.SetTokenVersionWithTTL(ctx, userID, version, s.ttl)
}

// SetTokenVersionWithTTL stores or updates the token version for the given user in Redis with an explicit TTL.
// A duration <= 0 disables expiration.
func (s *RedisTokenVersionStore) SetTokenVersionWithTTL(ctx context.Context, userID uint64, version uint64, ttl time.Duration) error {
	if s.client == nil {
		return errors.New("redis client is not configured")
	}
	ttl = max(ttl, 0)

	key := UserTokenVersionKey(userID)
	return s.client.Set(ctx, key, version, ttl).Err()
}

// DeleteTokenVersion removes the token version record for the given user from Redis.
func (s *RedisTokenVersionStore) DeleteTokenVersion(ctx context.Context, userID uint64) error {
	if s.client == nil {
		return errors.New("redis client is not configured")
	}

	key := UserTokenVersionKey(userID)
	return s.client.Del(ctx, key).Err()
}

// IsFamilyRevoked reports whether the session family is recorded as revoked in Redis.
func (s *RedisTokenVersionStore) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if s.client == nil {
		return false, errors.New("redis client is not configured")
	}
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return false, nil
	}

	key := FamilyRevocationKey(familyID)
	n, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RevokeFamily marks a session family as revoked in Redis with an explicit TTL.
// A duration <= 0 retains the revocation key indefinitely.
func (s *RedisTokenVersionStore) RevokeFamily(ctx context.Context, familyID string, ttl time.Duration) error {
	if s.client == nil {
		return errors.New("redis client is not configured")
	}
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return errors.New("family ID must not be empty")
	}

	ttl = max(ttl, 0)
	key := FamilyRevocationKey(familyID)
	return s.client.Set(ctx, key, "1", ttl).Err()
}

// DeleteFamilyRevocation removes the session family revocation record from Redis.
func (s *RedisTokenVersionStore) DeleteFamilyRevocation(ctx context.Context, familyID string) error {
	if s.client == nil {
		return errors.New("redis client is not configured")
	}
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return nil
	}

	key := FamilyRevocationKey(familyID)
	return s.client.Del(ctx, key).Err()
}

// GetTokenAndFamilyRevocation queries the user token version and session family revocation status
// using a Redis Pipeline in a single network round-trip.
func (s *RedisTokenVersionStore) GetTokenAndFamilyRevocation(ctx context.Context, userID uint64, familyID string) (uint64, bool, error) {
	if s.client == nil {
		return 0, false, errors.New("redis client is not configured")
	}

	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		ver, err := s.GetTokenVersion(ctx, userID)
		return ver, false, err
	}

	userKey := UserTokenVersionKey(userID)
	famKey := FamilyRevocationKey(familyID)

	pipe := s.client.Pipeline()
	verCmd := pipe.Get(ctx, userKey)
	famCmd := pipe.Exists(ctx, famKey)

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return 0, false, err
	}

	ver, vErr := verCmd.Uint64()
	if vErr != nil {
		if errors.Is(vErr, redis.Nil) {
			return 0, false, ErrTokenVersionNotFound
		}
		return 0, false, vErr
	}

	n, fErr := famCmd.Result()
	if fErr != nil {
		return 0, false, fErr
	}

	return ver, n > 0, nil
}
