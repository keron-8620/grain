package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWKSRefresher_Validation(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cfg := NewJWTConfig("test-issuer", "test-audience", &rsaKey.PublicKey, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	t.Run("nil authenticator errors", func(t *testing.T) {
		_, err := NewJWKSRefresher(nil, KeyRefreshConfig{IAMBaseURL: "http://localhost:8080"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authenticator must not be nil")
	})

	t.Run("empty IAM base URL errors", func(t *testing.T) {
		_, err := NewJWKSRefresher(auth, KeyRefreshConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IAM base URL is required")
	})

	t.Run("default interval and cooldown", func(t *testing.T) {
		refresher, err := NewJWKSRefresher(auth, KeyRefreshConfig{
			IAMBaseURL: "http://localhost:8080",
		})
		require.NoError(t, err)
		assert.Equal(t, DefaultKeyRefreshInterval, refresher.cfg.Interval)
		assert.Equal(t, DefaultKeyRefreshCooldown, refresher.cfg.Cooldown)
		assert.Equal(t, refresher, auth.JWKSRefresher())
	})
}

func TestJWKSRefresher_FetchNow_And_BackgroundRefresh(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk1, err := PublicKeyToJWK(&key1.PublicKey, "", "RS256")
	require.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk2, err := PublicKeyToJWK(&key2.PublicKey, "", "RS256")
	require.NoError(t, err)

	var currentJWKS atomic.Pointer[JSONWebKeySet]
	currentJWKS.Store(&JSONWebKeySet{Keys: []JSONWebKey{*jwk1}})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(currentJWKS.Load())
	}))
	defer ts.Close()

	cfg := NewJWTConfig("test-issuer", "test-audience", nil, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	refresher, err := NewJWKSRefresher(auth, KeyRefreshConfig{
		IAMBaseURL: ts.URL,
		Interval:   50 * time.Millisecond,
		Cooldown:   10 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() {
		_ = refresher.Close()
	}()

	// Initial manual fetch
	ctx := context.Background()
	err = refresher.FetchNow(ctx)
	require.NoError(t, err)
	assert.Equal(t, jwk1.Kid, auth.ActiveKeyID())

	// Start background refresh
	err = refresher.Start(ctx)
	require.NoError(t, err)

	// Second start returns error
	assert.Error(t, refresher.Start(ctx))

	// Rotate key on server
	currentJWKS.Store(&JSONWebKeySet{Keys: []JSONWebKey{*jwk2}})

	// Wait for background ticker to refresh
	require.Eventually(t, func() bool {
		return auth.ActiveKeyID() == jwk2.Kid
	}, 1*time.Second, 20*time.Millisecond)
}

func TestJWKSRefresher_OnDemandRefresh_UnknownKid(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk1, err := PublicKeyToJWK(&key1.PublicKey, "", "RS256")
	require.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk2, err := PublicKeyToJWK(&key2.PublicKey, "", "RS256")
	require.NoError(t, err)

	bogusKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var requestCount atomic.Int64
	var currentJWKS atomic.Pointer[JSONWebKeySet]
	currentJWKS.Store(&JSONWebKeySet{Keys: []JSONWebKey{*jwk1}})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(currentJWKS.Load())
	}))
	defer ts.Close()

	cfg := NewJWTConfig("test-issuer", "test-audience", &key1.PublicKey, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	refresher, err := NewJWKSRefresher(auth, KeyRefreshConfig{
		IAMBaseURL: ts.URL,
		Cooldown:   300 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() {
		_ = refresher.Close()
	}()

	// Update server to have key2 (newly rotated key)
	currentJWKS.Store(&JSONWebKeySet{Keys: []JSONWebKey{*jwk2, *jwk1}})

	// Sign a token with key2
	claims := &JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-101",
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			Subject:   "101",
		},
		UserInfo: UserInfo{
			UserID:   101,
			Username: "alice",
		},
		Type: TokenTypeAccess,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = jwk2.Kid
	tokenStr, err := tok.SignedString(key2)
	require.NoError(t, err)

	// Verifying this token should trigger on-demand refresh and succeed!
	verifiedClaims, err := auth.ParseAndVerifyToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, uint64(101), verifiedClaims.UserID)
	assert.Equal(t, int64(1), requestCount.Load())
	assert.Equal(t, jwk2.Kid, auth.ActiveKeyID())

	// Testing Cooldown Rate Limiting:
	// A token signed with a bogus unknown key
	bogusTok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	bogusTok.Header["kid"] = "non-existent-kid"
	bogusTokenStr, err := bogusTok.SignedString(bogusKey)
	require.NoError(t, err)

	// Since cooldown is 300ms and last fetch was just now, this should NOT trigger an HTTP request!
	_, err = auth.ParseAndVerifyToken(bogusTokenStr)
	assert.Error(t, err)
	assert.Equal(t, int64(1), requestCount.Load(), "requestCount must remain 1 due to cooldown rate limiting")

	// Wait for cooldown to elapse
	time.Sleep(350 * time.Millisecond)

	// Now trying again should trigger exactly 1 more request
	_, err = auth.ParseAndVerifyToken(bogusTokenStr)
	assert.Error(t, err)
	assert.Equal(t, int64(2), requestCount.Load(), "requestCount should increment after cooldown has elapsed")
}

func TestJWKSRefresher_ConcurrentOnDemand(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk2, err := PublicKeyToJWK(&key2.PublicKey, "", "RS256")
	require.NoError(t, err)

	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(30 * time.Millisecond) // Simulate network latency
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&JSONWebKeySet{Keys: []JSONWebKey{*jwk2}})
	}))
	defer ts.Close()

	cfg := NewJWTConfig("test-issuer", "test-audience", &key1.PublicKey, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	refresher, err := NewJWKSRefresher(auth, KeyRefreshConfig{
		IAMBaseURL: ts.URL,
		Cooldown:   500 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() {
		_ = refresher.Close()
	}()

	claims := &JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-concurrent",
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			Subject:   "101",
		},
		UserInfo: UserInfo{
			UserID:   101,
			Username: "alice",
		},
		Type: TokenTypeAccess,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = jwk2.Kid
	tokenStr, err := tok.SignedString(key2)
	require.NoError(t, err)

	// 20 concurrent requests with rotated key
	const concurrency = 20
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = auth.ParseAndVerifyToken(tokenStr)
		}(i)
	}
	wg.Wait()

	for i := 0; i < concurrency; i++ {
		assert.NoError(t, errs[i])
	}
	// Verify that coalescing happened: requests did not hammer 20 times!
	assert.LessOrEqual(t, requestCount.Load(), int64(2))
}

func TestJWKSRefresher_StartJWKSAutoRefresh_And_Close(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := PublicKeyToJWK(&key.PublicKey, "", "RS256")
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&JSONWebKeySet{Keys: []JSONWebKey{*jwk}})
	}))
	defer ts.Close()

	cfg := NewJWTConfig("test-issuer", "test-audience", nil, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	ctx := context.Background()
	refresher, err := auth.StartJWKSAutoRefresh(ctx, KeyRefreshConfig{
		IAMBaseURL: ts.URL,
		Interval:   50 * time.Millisecond,
	})
	require.NoError(t, err)
	assert.Equal(t, jwk.Kid, auth.ActiveKeyID())

	// Close authenticator, which closes refresher
	err = auth.Close()
	require.NoError(t, err)

	// Repeated Close is idempotent
	assert.NoError(t, auth.Close())
	assert.NoError(t, refresher.Close())
}

func TestJWKSRefresher_BadSignatureOnKnownKey_DoesNotTriggerRefresh(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk1, err := PublicKeyToJWK(&key1.PublicKey, "", "RS256")
	require.NoError(t, err)

	bogusKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&JSONWebKeySet{Keys: []JSONWebKey{*jwk1}})
	}))
	defer ts.Close()

	cfg := NewJWTConfig("test-issuer", "test-audience", &key1.PublicKey, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	refresher, err := NewJWKSRefresher(auth, KeyRefreshConfig{
		IAMBaseURL: ts.URL,
		Cooldown:   10 * time.Second,
	})
	require.NoError(t, err)
	defer func() {
		_ = refresher.Close()
	}()

	claims := &JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-known-bad-sig",
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			Subject:   "101",
		},
		UserInfo: UserInfo{
			UserID:   101,
			Username: "alice",
		},
		Type: TokenTypeAccess,
	}

	// Sign with bogus key, but specify known kid in header
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = jwk1.Kid
	badSigTokenStr, err := tok.SignedString(bogusKey)
	require.NoError(t, err)

	// Verifying this token must fail with invalid signature
	_, err = auth.ParseAndVerifyToken(badSigTokenStr)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenSignatureInvalid))
	// Because kid was already known, no refresh must be triggered!
	assert.Equal(t, int64(0), requestCount.Load(), "known kid with bad signature must NOT trigger on-demand refresh")

	// In contrast: a token with an UNKNOWN kid DOES trigger refresh
	unknownTok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	unknownTok.Header["kid"] = "unknown-kid-xyz"
	unknownTokenStr, err := unknownTok.SignedString(bogusKey)
	require.NoError(t, err)

	_, err = auth.ParseAndVerifyToken(unknownTokenStr)
	assert.Error(t, err)
	assert.Equal(t, int64(1), requestCount.Load(), "unknown kid MUST trigger on-demand refresh")
}

func TestJWKSRefresher_LegacyTokenWithoutKid_TriggersRefresh(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk2, err := PublicKeyToJWK(&key2.PublicKey, "", "RS256")
	require.NoError(t, err)
	tVal := true
	jwk2.Active = &tVal

	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&JSONWebKeySet{Keys: []JSONWebKey{*jwk2}})
	}))
	defer ts.Close()

	// Authenticator initially knows only key1
	cfg := NewJWTConfig("test-issuer", "test-audience", &key1.PublicKey, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	refresher, err := NewJWKSRefresher(auth, KeyRefreshConfig{
		IAMBaseURL: ts.URL,
		Cooldown:   10 * time.Second,
	})
	require.NoError(t, err)
	defer func() {
		_ = refresher.Close()
	}()

	claims := &JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-legacy",
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			Subject:   "102",
		},
		UserInfo: UserInfo{
			UserID:   102,
			Username: "bob",
		},
		Type: TokenTypeAccess,
	}

	// Legacy token without "kid" header, signed with key2
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	delete(tok.Header, "kid")
	legacyTokenStr, err := tok.SignedString(key2)
	require.NoError(t, err)

	// Verifying should detect signature failure on key1, refresh JWKS to get key2, and succeed!
	verifiedClaims, err := auth.ParseAndVerifyToken(legacyTokenStr)
	require.NoError(t, err)
	assert.Equal(t, uint64(102), verifiedClaims.UserID)
	assert.Equal(t, int64(1), requestCount.Load(), "legacy token without kid must trigger refresh on key rotation")
	assert.Equal(t, jwk2.Kid, auth.ActiveKeyID())
}
