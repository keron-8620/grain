package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthenticator(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := NewJWTConfig("test-issuer", "test-audience", &rsaKey.PublicKey, jwt.SigningMethodRS256)
	logger := slog.New(slog.DiscardHandler)

	auth, err := NewAuthenticator(cfg, nil, logger)
	require.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, cfg, auth.jwtCfg)
	assert.Nil(t, auth.tokenStore)
	assert.Equal(t, logger, auth.logger)

	// Test NewAuthenticatorWithRedis
	memAuth, err := NewAuthenticatorWithRedis(cfg, nil, logger)
	require.NoError(t, err)
	assert.Nil(t, memAuth.tokenStore)
}

func TestParsePublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("invalid PEM data", func(t *testing.T) {
		key, err := parsePublicKey([]byte("not a pem"))
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "invalid PEM data")
	})

	t.Run("RSA PKCS1 public key", func(t *testing.T) {
		der := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: der,
		})

		key, err := parsePublicKey(pemBytes)
		require.NoError(t, err)
		rsaPub, ok := key.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, rsaKey.N, rsaPub.N)
	})

	t.Run("RSA PKCS1 invalid bytes", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: []byte("corrupted-bytes"),
		})

		key, err := parsePublicKey(pemBytes)
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("PKIX RSA public key", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})

		key, err := parsePublicKey(pemBytes)
		require.NoError(t, err)
		rsaPub, ok := key.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, rsaKey.N, rsaPub.N)
	})

	t.Run("PKIX ECDSA public key", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})

		key, err := parsePublicKey(pemBytes)
		require.NoError(t, err)
		ecdsaPub, ok := key.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.True(t, ecdsaKey.PublicKey.Equal(ecdsaPub))
	})

	t.Run("PKIX Ed25519 public key", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(ed25519Pub)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})

		key, err := parsePublicKey(pemBytes)
		require.NoError(t, err)
		edPub, ok := key.(ed25519.PublicKey)
		require.True(t, ok)
		assert.Equal(t, ed25519Pub, edPub)
	})

	t.Run("PKIX invalid bytes", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("corrupted-pkix-bytes"),
		})

		key, err := parsePublicKey(pemBytes)
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("fallback parse PKIX with custom type", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CUSTOM KEY TYPE",
			Bytes: der,
		})

		key, err := parsePublicKey(pemBytes)
		require.NoError(t, err)
		rsaPub, ok := key.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, rsaKey.N, rsaPub.N)
	})

	t.Run("fallback parse PKCS1 with custom type", func(t *testing.T) {
		der := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "UNKNOWN RSA KEY",
			Bytes: der,
		})

		key, err := parsePublicKey(pemBytes)
		require.NoError(t, err)
		rsaPub, ok := key.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, rsaKey.N, rsaPub.N)
	})

	t.Run("fallback fail unknown PEM type", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not a key"),
		})

		key, err := parsePublicKey(pemBytes)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "unknown public key PEM type: CERTIFICATE")
	})
}

func TestParseAndVerifyToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := "iam.test.com"
	audience := "amadeus-gateway"

	cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	signToken := func(method jwt.SigningMethod, key crypto.PrivateKey, claims *JwtClaims) string {
		tok := jwt.NewWithClaims(method, claims)
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		return signed
	}

	validClaims := func() *JwtClaims {
		return &JwtClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Audience:  jwt.ClaimStrings{audience},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				ID:        "9f1d0b3c-0000-4000-8000-000000000001",
				Subject:   "testuser",
			},
			UserInfo: UserInfo{
				UserID:       101,
				Username:     "testuser",
				RoleID:       1,
				IsStaff:      true,
				TokenVersion: 1,
			},
			Type: TokenTypeAccess,
		}
	}

	t.Run("empty or whitespace token", func(t *testing.T) {
		claims, err := auth.ParseAndVerifyToken("")
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token must not be empty")

		claims, err = auth.ParseAndVerifyToken("   \t\n")
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token must not be empty")
	})

	t.Run("valid access token", func(t *testing.T) {
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, validClaims())
		claims, err := auth.ParseAndVerifyToken(tokenStr)
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, uint32(101), claims.UserID)
		assert.Equal(t, "testuser", claims.Username)
		assert.Equal(t, TokenTypeAccess, claims.Type)
		assert.Equal(t, uint64(1), claims.TokenVersion)
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		// Token signed with HS256 using a symmetric secret
		hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
		signed, err := hsTok.SignedString([]byte("secret"))
		require.NoError(t, err)

		claims, err := auth.ParseAndVerifyToken(signed)
		assert.Error(t, err)
		assert.Nil(t, claims)
		// The algorithm is pinned before the key is consulted, so the token is rejected on its
		// header rather than on a signature computed with the public key as an HMAC secret.
		assert.Contains(t, err.Error(), "HS256")
	})

	t.Run("invalid signature from other key", func(t *testing.T) {
		tokenStr := signToken(jwt.SigningMethodRS256, otherRSAKey, validClaims())
		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("expired token", func(t *testing.T) {
		c := validClaims()
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("wrong issuer", func(t *testing.T) {
		c := validClaims()
		c.Issuer = "wrong-issuer"
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("wrong audience", func(t *testing.T) {
		c := validClaims()
		c.Audience = jwt.ClaimStrings{"wrong-aud"}
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("malformed token string", func(t *testing.T) {
		claims, err := auth.ParseAndVerifyToken("abc.def.ghi")
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("refresh token type rejected", func(t *testing.T) {
		c := validClaims()
		c.Type = TokenTypeRefresh
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token type must be access")
	})

	t.Run("missing user id", func(t *testing.T) {
		c := validClaims()
		c.UserID = 0
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token missing required uid, un or jti claims")
	})

	t.Run("missing username", func(t *testing.T) {
		c := validClaims()
		c.Username = ""
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token missing required uid, un or jti claims")
	})
}

func TestVerifyTokenVersion(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	t.Run("nil token store fails closed", func(t *testing.T) {
		auth, err := NewAuthenticator(JWTConfig{}, nil, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       1,
				TokenVersion: 5,
			},
		}
		err = auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token store is not configured")
	})

	t.Run("memory store nil key fails closed", func(t *testing.T) {
		memStore := NewMemoryTokenVersionStore()
		auth, err := NewAuthenticator(JWTConfig{}, memStore, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       100,
				TokenVersion: 0,
			},
		}
		err = auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token version unavailable")
	})

	t.Run("memory store version matches token_version", func(t *testing.T) {
		memStore := NewMemoryTokenVersionStore()
		require.NoError(t, memStore.SetTokenVersion(ctx, 200, 3))
		auth, err := NewAuthenticator(JWTConfig{}, memStore, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       200,
				TokenVersion: 3,
			},
		}
		err = auth.VerifyTokenVersion(ctx, claims)
		assert.NoError(t, err)
	})

	t.Run("memory store version does not match token_version", func(t *testing.T) {
		memStore := NewMemoryTokenVersionStore()
		require.NoError(t, memStore.SetTokenVersion(ctx, 200, 5))
		auth, err := NewAuthenticator(JWTConfig{}, memStore, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       200,
				TokenVersion: 2,
			},
		}
		err = auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token revoked (server version: 5, token version: 2)")
	})

	t.Run("redis nil key fails closed even with token_version 0", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		auth, err := NewAuthenticatorWithRedis(JWTConfig{}, rdb, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       100,
				TokenVersion: 0,
			},
		}
		err = auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token version unavailable")
	})

	t.Run("redis nil key and token_version non-zero", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		auth, err := NewAuthenticatorWithRedis(JWTConfig{}, rdb, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       100,
				TokenVersion: 2,
			},
		}
		err = auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token version unavailable")
	})

	t.Run("redis version matches token_version", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		auth, err := NewAuthenticatorWithRedis(JWTConfig{}, rdb, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       200,
				TokenVersion: 3,
			},
		}
		require.NoError(t, rdb.Set(ctx, UserTokenVersionKey(200), "3", 0).Err())

		err = auth.VerifyTokenVersion(ctx, claims)
		assert.NoError(t, err)
	})

	t.Run("redis version does not match token_version", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		auth, err := NewAuthenticatorWithRedis(JWTConfig{}, rdb, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       200,
				TokenVersion: 2,
			},
		}
		require.NoError(t, rdb.Set(ctx, UserTokenVersionKey(200), "5", 0).Err())

		err = auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token revoked (server version: 5, token version: 2)")
	})

	t.Run("redis query error", func(t *testing.T) {
		// Client pointing to an unavailable port
		badRdb := redis.NewClient(&redis.Options{
			Addr:        "127.0.0.1:1",
			MaxRetries:  -1,
			DialTimeout: 50 * time.Millisecond,
			ReadTimeout: 50 * time.Millisecond,
		})
		defer func() { _ = badRdb.Close() }()

		auth, err := NewAuthenticatorWithRedis(JWTConfig{}, badRdb, logger)
		require.NoError(t, err)

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       300,
				TokenVersion: 1,
			},
		}
		err = auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to query token version")
	})
}

func TestFetchPublicKeyHTTP(t *testing.T) {
	t.Run("empty base URL", func(t *testing.T) {
		_, err := FetchPublicKeyHTTP(context.Background(), "", "access")
		assert.Error(t, err)
	})
}

// A rotation must be transparent for consumers: tokens signed with the previous key keep verifying
// while that key is configured, and stop verifying once the window closes.
func TestParseAndVerifyToken_KeyRotationWindow(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	activeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	previousKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer, audience := "iam.test.com", "amadeus-gateway"
	cfg := NewJWTConfig(issuer, audience, &activeKey.PublicKey, jwt.SigningMethodES256)
	auth, err := NewAuthenticator(cfg, nil, logger)
	require.NoError(t, err)

	activeID, err := KeyID(&activeKey.PublicKey)
	require.NoError(t, err)
	previousID, err := KeyID(&previousKey.PublicKey)
	require.NoError(t, err)
	require.NotEqual(t, activeID, previousID)

	sign := func(key *ecdsa.PrivateKey, kid string) string {
		claims := &JwtClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Audience:  jwt.ClaimStrings{audience},
				Subject:   "alice",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ID:        "jti-rot",
			},
			UserInfo: UserInfo{UserID: 1, Username: "alice", RoleID: 1, TokenVersion: 1},
			Type:     TokenTypeAccess,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		if kid != "" {
			token.Header["kid"] = kid
		}
		signed, signErr := token.SignedString(key)
		require.NoError(t, signErr)
		return signed
	}

	t.Run("active key", func(t *testing.T) {
		_, err := auth.ParseAndVerifyToken(sign(activeKey, activeID))
		require.NoError(t, err)
	})

	t.Run("rotation window open accepts the previous key", func(t *testing.T) {
		require.NoError(t, auth.SetVerificationKeys(mustVerificationKeys(t, &activeKey.PublicKey, &previousKey.PublicKey)))
		_, err := auth.ParseAndVerifyToken(sign(previousKey, previousID))
		require.NoError(t, err, "a token issued before the rotation must keep working")
	})

	t.Run("legacy token without kid falls back to the previous key", func(t *testing.T) {
		require.NoError(t, auth.SetVerificationKeys(mustVerificationKeys(t, &activeKey.PublicKey, &previousKey.PublicKey)))
		_, err := auth.ParseAndVerifyToken(sign(previousKey, ""))
		require.NoError(t, err)
	})

	t.Run("window closed rejects the previous key", func(t *testing.T) {
		require.NoError(t, auth.SetVerificationKeys(mustVerificationKeys(t, &activeKey.PublicKey, nil)))
		_, err := auth.ParseAndVerifyToken(sign(previousKey, previousID))
		require.Error(t, err)
	})
}

func mustVerificationKeys(t *testing.T, active, previous crypto.PublicKey) *VerificationKeys {
	t.Helper()
	keys, err := NewVerificationKeys(active, previous)
	require.NoError(t, err)
	return keys
}
