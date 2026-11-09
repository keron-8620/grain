package iam

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	biz "grain/internal/biz/iam"
)

// ErrCacheMiss indicates that the requested key does not exist in the cache or has expired.
var ErrCacheMiss = errors.New("cache: key not found")

// UserCache defines the contract for caching user token versions and refresh token state.
type UserCache interface {
	// GetTokenVersion retrieves the cached token version for the user.
	// Returns ErrCacheMiss if the entry is missing or expired.
	GetTokenVersion(ctx context.Context, userID uint64) (uint64, error)

	// SetTokenVersion updates the cached token version for the user if the new version is greater,
	// with the specified TTL.
	SetTokenVersion(ctx context.Context, userID uint64, version uint64, ttl time.Duration) error

	// DeleteTokenVersion removes the cached token version for the user.
	DeleteTokenVersion(ctx context.Context, userID uint64) error

	// ConsumeRefreshToken attempts to mark a refresh token JTI as consumed with a TTL.
	// Returns (true, nil) if the token was not previously consumed and was successfully marked.
	// Returns (false, nil) if the token was already consumed.
	ConsumeRefreshToken(ctx context.Context, jti string, ttl time.Duration) (bool, error)

	// RotateRefreshTokenFamily performs atomic refresh token family rotation and replay detection.
	// Returns RotateFamilySuccess, RotateFamilyCompromised, or RotateFamilyFailed.
	RotateRefreshTokenFamily(ctx context.Context, familyID, oldJTI, newJTI string, userID uint64, ttl time.Duration) (biz.RotateFamilyResult, error)
}

func refreshFamilyKey(familyID string) string {
	return fmt.Sprintf("iam:refresh-family:%s", familyID)
}

func refreshTokenKey(jti string) string {
	return fmt.Sprintf("iam:refresh:%s", jti)
}

func tokenVersionKey(userID uint64) string {
	return fmt.Sprintf("iam:user-token-version:%d", userID)
}

// ==================== Redis Implementation ====================

var updateTokenVersionScript = redis.NewScript(`
	local cur = redis.call('GET', KEYS[1])
	local new_v = tonumber(ARGV[1])
	if not cur or tonumber(cur) < new_v then
		redis.call('SET', KEYS[1], new_v, 'EX', ARGV[2])
		return 1
	end
	return 0
`)

var rotateRefreshTokenFamilyScript = redis.NewScript(`
	-- KEYS[1]: iam:refresh-family:<family_id>
	-- KEYS[2]: iam:refresh-consumed:<old_jti>
	-- ARGV[1]: old_jti
	-- ARGV[2]: new_jti
	-- ARGV[3]: user_id
	-- ARGV[4]: ttl_seconds

	-- Check if old_jti was already consumed (definite replay)
	if redis.call('EXISTS', KEYS[2]) == 1 then
		redis.call('HSET', KEYS[1], 'compromised', '1')
		redis.call('EXPIRE', KEYS[1], ARGV[4])
		return 1
	end

	local cur_jti = redis.call('HGET', KEYS[1], 'current_jti')
	local compromised = redis.call('HGET', KEYS[1], 'compromised')

	if compromised == '1' then
		return 1
	end

	if not cur_jti then
		-- First rotation: initialize family
		redis.call('HSET', KEYS[1], 'current_jti', ARGV[2], 'user_id', ARGV[3], 'compromised', '0')
		redis.call('EXPIRE', KEYS[1], ARGV[4])
		redis.call('SET', KEYS[2], '1', 'EX', ARGV[4])
		return 0
	end

	if cur_jti ~= ARGV[1] then
		-- Replay detected: current valid token does not match old token being rotated
		redis.call('HSET', KEYS[1], 'compromised', '1')
		redis.call('EXPIRE', KEYS[1], ARGV[4])
		return 1
	end

	-- Normal rotation: advance current_jti and mark old_jti consumed
	redis.call('HSET', KEYS[1], 'current_jti', ARGV[2])
	redis.call('EXPIRE', KEYS[1], ARGV[4])
	redis.call('SET', KEYS[2], '1', 'EX', ARGV[4])
	return 0
`)

type redisUserCache struct {
	client redis.UniversalClient
}

// NewRedisUserCache creates a Redis-backed UserCache.
func NewRedisUserCache(client redis.UniversalClient) UserCache {
	return &redisUserCache{
		client: client,
	}
}

func (c *redisUserCache) GetTokenVersion(ctx context.Context, userID uint64) (uint64, error) {
	if c.client == nil {
		return 0, errors.New("redis client is not configured")
	}
	val, err := c.client.Get(ctx, tokenVersionKey(userID)).Uint64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, ErrCacheMiss
		}
		return 0, err
	}
	return val, nil
}

func (c *redisUserCache) SetTokenVersion(ctx context.Context, userID uint64, version uint64, ttl time.Duration) error {
	if c.client == nil {
		return errors.New("redis client is not configured")
	}
	ttlSeconds := int64(ttl / time.Second)
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	return updateTokenVersionScript.Run(ctx, c.client, []string{tokenVersionKey(userID)}, version, ttlSeconds).Err()
}

func (c *redisUserCache) DeleteTokenVersion(ctx context.Context, userID uint64) error {
	if c.client == nil {
		return errors.New("redis client is not configured")
	}
	return c.client.Del(ctx, tokenVersionKey(userID)).Err()
}

func (c *redisUserCache) ConsumeRefreshToken(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	if c.client == nil {
		return false, errors.New("redis client is not configured")
	}
	ok, err := c.client.SetNX(ctx, refreshTokenKey(jti), "used", ttl).Result()
	return ok, err
}

func (c *redisUserCache) RotateRefreshTokenFamily(ctx context.Context, familyID, oldJTI, newJTI string, userID uint64, ttl time.Duration) (biz.RotateFamilyResult, error) {
	if c.client == nil {
		return biz.RotateFamilyFailed, errors.New("redis client is not configured")
	}
	ttlSeconds := int64(ttl / time.Second)
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	keys := []string{
		refreshFamilyKey(familyID),
		refreshTokenKey(oldJTI),
	}
	res, err := rotateRefreshTokenFamilyScript.Run(ctx, c.client, keys, oldJTI, newJTI, userID, ttlSeconds).Int()
	if err != nil {
		return biz.RotateFamilyFailed, err
	}
	if res == 1 {
		return biz.RotateFamilyCompromised, nil
	}
	return biz.RotateFamilySuccess, nil
}

// ==================== Memory Implementation ====================

type tokenVersionItem struct {
	version  uint64
	expireAt time.Time
}

type refreshFamilyItem struct {
	currentJTI  string
	userID      uint64
	compromised bool
	expireAt    time.Time
}

type memoryUserCache struct {
	mu             sync.RWMutex
	tokenVersions  map[uint64]tokenVersionItem
	consumedTokens map[string]time.Time
	families       map[string]refreshFamilyItem
	stopCh         chan struct{}
	stopOnce       sync.Once
}

// NewMemoryUserCache creates an in-memory, thread-safe UserCache.
// An optional cleanupInterval can be passed; if positive, a background goroutine
// periodically removes expired entries. If interval <= 0, no background goroutine is started.
func NewMemoryUserCache(cleanupInterval ...time.Duration) UserCache {
	m := &memoryUserCache{
		tokenVersions:  make(map[uint64]tokenVersionItem),
		consumedTokens: make(map[string]time.Time),
		families:       make(map[string]refreshFamilyItem),
		stopCh:         make(chan struct{}),
	}

	interval := 5 * time.Minute
	if len(cleanupInterval) > 0 {
		interval = cleanupInterval[0]
	}

	if interval > 0 {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					m.cleanup()
				case <-m.stopCh:
					return
				}
			}
		}()
		runtime.SetFinalizer(m, func(c *memoryUserCache) {
			_ = c.Close()
		})
	}

	return m
}

// Close stops the periodic cleanup goroutine, if running.
func (m *memoryUserCache) Close() error {
	m.stopOnce.Do(func() {
		if m.stopCh != nil {
			close(m.stopCh)
		}
	})
	return nil
}

func (m *memoryUserCache) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for k, item := range m.tokenVersions {
		if !item.expireAt.IsZero() && now.After(item.expireAt) {
			delete(m.tokenVersions, k)
		}
	}
	for k, expireAt := range m.consumedTokens {
		if !expireAt.IsZero() && now.After(expireAt) {
			delete(m.consumedTokens, k)
		}
	}
	for k, fam := range m.families {
		if !fam.expireAt.IsZero() && now.After(fam.expireAt) {
			delete(m.families, k)
		}
	}
}

func (m *memoryUserCache) GetTokenVersion(ctx context.Context, userID uint64) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.tokenVersions[userID]
	if !exists {
		return 0, ErrCacheMiss
	}
	if !item.expireAt.IsZero() && time.Now().After(item.expireAt) {
		delete(m.tokenVersions, userID)
		return 0, ErrCacheMiss
	}
	return item.version, nil
}

func (m *memoryUserCache) SetTokenVersion(ctx context.Context, userID uint64, version uint64, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	item, exists := m.tokenVersions[userID]
	if exists && (item.expireAt.IsZero() || now.Before(item.expireAt)) {
		if item.version >= version {
			return nil
		}
	}

	if ttl <= 0 {
		ttl = 1 * time.Second
	}
	m.tokenVersions[userID] = tokenVersionItem{
		version:  version,
		expireAt: now.Add(ttl),
	}
	return nil
}

func (m *memoryUserCache) DeleteTokenVersion(ctx context.Context, userID uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.tokenVersions, userID)
	return nil
}

func (m *memoryUserCache) ConsumeRefreshToken(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if expireAt, exists := m.consumedTokens[jti]; exists {
		if expireAt.IsZero() || now.Before(expireAt) {
			return false, nil
		}
	}

	if ttl <= 0 {
		ttl = 1 * time.Second
	}
	m.consumedTokens[jti] = now.Add(ttl)
	return true, nil
}

func (m *memoryUserCache) RotateRefreshTokenFamily(ctx context.Context, familyID, oldJTI, newJTI string, userID uint64, ttl time.Duration) (biz.RotateFamilyResult, error) {
	if err := ctx.Err(); err != nil {
		return biz.RotateFamilyFailed, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if ttl <= 0 {
		ttl = 1 * time.Second
	}
	expireAt := now.Add(ttl)

	// 1. Check if old_jti was already consumed (definite replay)
	if consumedExpireAt, exists := m.consumedTokens[oldJTI]; exists {
		if consumedExpireAt.IsZero() || now.Before(consumedExpireAt) {
			fam, ok := m.families[familyID]
			if !ok {
				fam = refreshFamilyItem{
					currentJTI:  oldJTI,
					userID:      userID,
					compromised: true,
					expireAt:    expireAt,
				}
			} else {
				fam.compromised = true
				fam.expireAt = expireAt
			}
			m.families[familyID] = fam
			return biz.RotateFamilyCompromised, nil
		}
		delete(m.consumedTokens, oldJTI)
	}

	fam, exists := m.families[familyID]
	isExpired := exists && !fam.expireAt.IsZero() && now.After(fam.expireAt)

	if exists && !isExpired && fam.compromised {
		return biz.RotateFamilyCompromised, nil
	}

	if !exists || isExpired {
		// First rotation: initialize family
		m.families[familyID] = refreshFamilyItem{
			currentJTI:  newJTI,
			userID:      userID,
			compromised: false,
			expireAt:    expireAt,
		}
		m.consumedTokens[oldJTI] = expireAt
		return biz.RotateFamilySuccess, nil
	}

	if fam.currentJTI != oldJTI {
		// Replay detected: current valid token does not match old token being rotated
		fam.compromised = true
		fam.expireAt = expireAt
		m.families[familyID] = fam
		return biz.RotateFamilyCompromised, nil
	}

	// Normal rotation: advance current_jti and mark old_jti consumed
	fam.currentJTI = newJTI
	fam.expireAt = expireAt
	m.families[familyID] = fam
	m.consumedTokens[oldJTI] = expireAt
	return biz.RotateFamilySuccess, nil
}
