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
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"emperror.dev/errors"
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
		key, err := ParsePublicKey([]byte("not a pem"))
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
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

		key, err := ParsePublicKey(pemBytes)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "unknown public key PEM type: CERTIFICATE")
	})

	t.Run("RSA public key too weak rejected", func(t *testing.T) {
		weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)

		derPKIX, err := x509.MarshalPKIXPublicKey(&weakKey.PublicKey)
		require.NoError(t, err)
		pemPKIX := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derPKIX})
		_, err = ParsePublicKey(pemPKIX)
		assert.ErrorContains(t, err, "RSA public key is too weak: 1024 bits, at least 2048 bits required")

		derPKCS1 := x509.MarshalPKCS1PublicKey(&weakKey.PublicKey)
		pemPKCS1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: derPKCS1})
		_, err = ParsePublicKey(pemPKCS1)
		assert.ErrorContains(t, err, "RSA public key is too weak: 1024 bits, at least 2048 bits required")
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
				Subject:   "101",
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
		assert.Equal(t, uint64(101), claims.UserID)
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

	t.Run("subject mismatch with user id", func(t *testing.T) {
		c := validClaims()
		c.Subject = "99999"
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token subject does not match user id")
	})
}

func TestParseAndVerifyToken_ClockSkewLeeway(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := "iam.test.com"
	audience := "amadeus-gateway"

	signToken := func(claims *JwtClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, err := tok.SignedString(rsaKey)
		require.NoError(t, err)
		return signed
	}

	baseClaims := func() *JwtClaims {
		return &JwtClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   issuer,
				Audience: jwt.ClaimStrings{audience},
				ID:       "9f1d0b3c-0000-4000-8000-000000000001",
				Subject:  "101",
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

	t.Run("expired within default leeway succeeds", func(t *testing.T) {
		cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256)
		auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		// Token expired 20 seconds ago, well within DefaultLeeway (1 minute)
		c := baseClaims()
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-20 * time.Second))
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))

		claims, err := auth.ParseAndVerifyToken(signToken(c))
		require.NoError(t, err)
		assert.Equal(t, uint64(101), claims.UserID)
	})

	t.Run("expired beyond leeway fails", func(t *testing.T) {
		cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256)
		auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		// Token expired 90 seconds ago, beyond DefaultLeeway (1 minute)
		c := baseClaims()
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-90 * time.Second))
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))

		claims, err := auth.ParseAndVerifyToken(signToken(c))
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("zero leeway rejects token expired even slightly", func(t *testing.T) {
		cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256).WithLeeway(0)
		auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		c := baseClaims()
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Second))
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))

		claims, err := auth.ParseAndVerifyToken(signToken(c))
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("not before slightly in the future within leeway succeeds", func(t *testing.T) {
		cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256)
		auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		// NotBefore 20 seconds in the future due to clock skew, within DefaultLeeway (1 minute)
		c := baseClaims()
		c.NotBefore = jwt.NewNumericDate(time.Now().Add(20 * time.Second))
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(1 * time.Hour))

		claims, err := auth.ParseAndVerifyToken(signToken(c))
		require.NoError(t, err)
		assert.Equal(t, uint64(101), claims.UserID)
	})

	t.Run("not before in future without leeway fails", func(t *testing.T) {
		cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256).WithLeeway(0)
		auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		// NotBefore 20 seconds in the future without leeway
		c := baseClaims()
		c.NotBefore = jwt.NewNumericDate(time.Now().Add(20 * time.Second))
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(1 * time.Hour))

		claims, err := auth.ParseAndVerifyToken(signToken(c))
		assert.Error(t, err)
		assert.Nil(t, claims)
		if err != nil {
			assert.Contains(t, err.Error(), "invalid token")
		}
	})

	t.Run("not before beyond leeway fails", func(t *testing.T) {
		cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256)
		auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		// NotBefore 90 seconds in the future, beyond DefaultLeeway (1 minute)
		c := baseClaims()
		c.NotBefore = jwt.NewNumericDate(time.Now().Add(90 * time.Second))
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(1 * time.Hour))

		claims, err := auth.ParseAndVerifyToken(signToken(c))
		assert.Error(t, err)
		assert.Nil(t, claims)
		if err != nil {
			assert.Contains(t, err.Error(), "invalid token")
		}
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

	t.Run("session family revocation supports single device kickout", func(t *testing.T) {
		memStore := NewMemoryTokenVersionStore()
		require.NoError(t, memStore.SetTokenVersion(ctx, 400, 1))

		auth, err := NewAuthenticator(JWTConfig{}, memStore, logger)
		require.NoError(t, err)

		// Device 1 and Device 2 for user 400
		claimsDev1 := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       400,
				TokenVersion: 1,
			},
			FamilyID: "fid-dev-1",
		}
		claimsDev2 := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       400,
				TokenVersion: 1,
			},
			FamilyID: "fid-dev-2",
		}

		// Both devices valid initially
		assert.NoError(t, auth.VerifyTokenVersion(ctx, claimsDev1))
		assert.NoError(t, auth.VerifyTokenVersion(ctx, claimsDev2))
		assert.NoError(t, auth.VerifyFamilyID(ctx, "fid-dev-1"))
		assert.NoError(t, auth.VerifyFamilyID(ctx, "fid-dev-2"))

		// Revoke device 1 session family only
		require.NoError(t, memStore.RevokeFamily(ctx, "fid-dev-1", 0))

		// Device 1 should fail verification
		dev1Err := auth.VerifyTokenVersion(ctx, claimsDev1)
		assert.Error(t, dev1Err)
		assert.True(t, errors.Is(dev1Err, ErrTokenFamilyRevoked))
		assert.True(t, errors.Is(dev1Err, ErrTokenRevoked))
		assert.True(t, errors.Is(dev1Err, ErrTokenInvalid))
		assert.True(t, IsTokenFamilyRevoked(dev1Err))
		assert.True(t, IsTokenRevoked(dev1Err))
		assert.Contains(t, dev1Err.Error(), "session family fid-dev-1 has been revoked")

		// VerifyFamilyID on device 1 fails
		assert.ErrorIs(t, auth.VerifyFamilyID(ctx, "fid-dev-1"), ErrTokenFamilyRevoked)

		// Device 2 is unaffected and remains valid!
		assert.NoError(t, auth.VerifyTokenVersion(ctx, claimsDev2))
		assert.NoError(t, auth.VerifyFamilyID(ctx, "fid-dev-2"))

		// Global user token version bump kicks out all devices (including device 2)
		require.NoError(t, memStore.SetTokenVersion(ctx, 400, 2))
		dev2Err := auth.VerifyTokenVersion(ctx, claimsDev2)
		assert.Error(t, dev2Err)
		assert.False(t, errors.Is(dev2Err, ErrTokenFamilyRevoked))
		assert.True(t, errors.Is(dev2Err, ErrTokenRevoked))
	})

	t.Run("VerifyFamilyID edge cases", func(t *testing.T) {
		// Empty family ID is a no-op
		authNoStore, err := NewAuthenticator(JWTConfig{}, nil, logger)
		require.NoError(t, err)
		assert.NoError(t, authNoStore.VerifyFamilyID(ctx, ""))

		// Non-empty family ID without store returns unavailable
		err = authNoStore.VerifyFamilyID(ctx, "some-fid")
		assert.ErrorIs(t, err, ErrTokenVersionUnavailable)
	})

	t.Run("batch token version and family revocation with Redis", func(t *testing.T) {
		_, rdb := startMockRedis(t)
		auth, err := NewAuthenticatorWithRedis(JWTConfig{}, rdb, logger)
		require.NoError(t, err)

		// Set initial user token version in Redis
		require.NoError(t, rdb.Set(ctx, UserTokenVersionKey(500), "1", 0).Err())

		claims := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       500,
				TokenVersion: 1,
			},
			FamilyID: "fid-batch-1",
		}

		// 1. Initial state: version matches, family not revoked -> success in 1 RTT
		assert.NoError(t, auth.VerifyTokenVersion(ctx, claims))

		// 2. Revoke family in Redis -> fails with ErrTokenFamilyRevoked
		require.NoError(t, rdb.Set(ctx, FamilyRevocationKey("fid-batch-1"), "1", 0).Err())
		fErr := auth.VerifyTokenVersion(ctx, claims)
		assert.Error(t, fErr)
		assert.True(t, errors.Is(fErr, ErrTokenFamilyRevoked))

		// 3. Version mismatch takes precedence even when family is revoked
		claimsMismatch := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       500,
				TokenVersion: 99, // Mismatched version
			},
			FamilyID: "fid-batch-1",
		}
		vErr := auth.VerifyTokenVersion(ctx, claimsMismatch)
		assert.Error(t, vErr)
		assert.True(t, errors.Is(vErr, ErrTokenRevoked))
		assert.False(t, errors.Is(vErr, ErrTokenFamilyRevoked))

		// 4. Missing user version in Redis fails closed
		claimsMissing := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       9999,
				TokenVersion: 1,
			},
			FamilyID: "fid-batch-1",
		}
		mErr := auth.VerifyTokenVersion(ctx, claimsMissing)
		assert.Error(t, mErr)
		assert.True(t, IsTokenVersionUnavailable(mErr))
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
				Subject:   "1",
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

func TestAuthenticator_ConcurrentAccess(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := "iam.test.com"
	audience := "amadeus-gateway"

	cfg := NewJWTConfig(issuer, audience, &rsaKey1.PublicKey, jwt.SigningMethodRS256)
	logger := slog.New(slog.DiscardHandler)
	auth, err := NewAuthenticator(cfg, nil, logger)
	require.NoError(t, err)

	claims := &JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ID:        "concurrent-token-id",
			Subject:   "101",
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

	token1, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(rsaKey1)
	require.NoError(t, err)

	keys1, err := NewVerificationKeys(&rsaKey1.PublicKey, nil)
	require.NoError(t, err)
	keys2, err := NewVerificationKeys(&rsaKey2.PublicKey, &rsaKey1.PublicKey)
	require.NoError(t, err)

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Readers: concurrently verify tokens and read ActiveKeyID
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = auth.ActiveKeyID()
					_, _ = auth.ParseAndVerifyToken(token1)
				}
			}
		}()
	}

	// Writers: concurrently update verification keys
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					if id%2 == 0 {
						_ = auth.SetVerificationKeys(keys1)
					} else {
						_ = auth.SetVerificationKeys(keys2)
					}
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestFetchPublicKeyHTTP_Extended(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	t.Run("successful fetch from loopback", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/public-key", r.URL.Path)
			if r.URL.Query().Get("type") == "access" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"public_key": "` + strings.ReplaceAll(string(pubPEM), "\n", "\\n") + `",
					"algorithm": "RS256",
					"issuer": "iam.test.com",
					"audience": "gateway"
				}`))
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
		}))
		defer ts.Close()

		res, err := FetchPublicKeyHTTP(context.Background(), ts.URL, "access")
		require.NoError(t, err)
		assert.Equal(t, "RS256", res.Algorithm)
		assert.Equal(t, "iam.test.com", res.Issuer)

		keys, err := res.VerificationKeys()
		require.NoError(t, err)
		assert.NotNil(t, keys)
	})

	t.Run("non-loopback http rejected", func(t *testing.T) {
		_, err := FetchPublicKeyHTTP(context.Background(), "http://api.example.com", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must use https")
	})

	t.Run("invalid base URL", func(t *testing.T) {
		_, err := FetchPublicKeyHTTP(context.Background(), "://invalid-url", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("server error status", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer ts.Close()

		_, err := FetchPublicKeyHTTP(context.Background(), ts.URL, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 500")
	})

	t.Run("invalid json response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`invalid-json`))
		}))
		defer ts.Close()

		_, err := FetchPublicKeyHTTP(context.Background(), ts.URL, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decode IAM public key response")
	})

	t.Run("response exceeds max bytes limit", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"public_key": "` + strings.Repeat("A", 500) + `"}`))
		}))
		defer ts.Close()

		_, err := FetchPublicKeyHTTP(context.Background(), ts.URL, "", WithMaxBytes(200))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeded maximum size")
	})

	t.Run("fetch standard JWKS using FetchJWKSHTTP and custom client", func(t *testing.T) {
		ring, err := NewVerificationKeys(&rsaKey.PublicKey, nil)
		require.NoError(t, err)
		jwks, err := ring.JWKS("RS256")
		require.NoError(t, err)
		jwksBytes, err := json.Marshal(jwks)
		require.NoError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/.well-known/jwks.json", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		}))
		defer ts.Close()

		customClient := &http.Client{Timeout: 3 * time.Second}
		fetchedJWKS, err := FetchJWKSHTTP(context.Background(), ts.URL, WithHTTPClient(customClient))
		require.NoError(t, err)
		require.Len(t, fetchedJWKS.Keys, 1)

		vkeys, err := fetchedJWKS.VerificationKeys()
		require.NoError(t, err)
		assert.Equal(t, ring.ActiveKeyID(), vkeys.ActiveKeyID())
	})

	t.Run("scheme boundary validation edge cases", func(t *testing.T) {
		ctx := context.Background()

		// ftp scheme rejected even on loopback
		_, err := FetchPublicKeyHTTP(ctx, "ftp://localhost/api/v1/public-key", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must use https")

		// ftp scheme rejected on remote host
		_, err = FetchPublicKeyHTTP(ctx, "ftp://example.com/api/v1/public-key", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must use https")

		// missing scheme
		_, err = FetchPublicKeyHTTP(ctx, "//localhost:8080", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must include a scheme")

		// invalid scheme without protocol prefix
		_, err = FetchPublicKeyHTTP(ctx, "localhost:8080", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must use https")

		// missing host
		_, err = FetchPublicKeyHTTP(ctx, "https://", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "host is required")

		_, err = FetchPublicKeyHTTP(ctx, "http://", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "host is required")

		// non-loopback http rejected
		_, err = FetchPublicKeyHTTP(ctx, "http://10.0.0.1:8080", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must use https")
	})

	t.Run("redirect to non-loopback http is blocked", func(t *testing.T) {
		ctx := context.Background()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://api.example.com/insecure-key", http.StatusFound)
		}))
		defer ts.Close()

		_, err := FetchPublicKeyHTTP(ctx, ts.URL, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect to insecure scheme/host not allowed")
	})
}

func TestPublicKeyResponse_VerificationKeys(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes1, err := x509.MarshalPKIXPublicKey(&rsaKey1.PublicKey)
	require.NoError(t, err)
	pubPEM1 := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes1})

	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes2, err := x509.MarshalPKIXPublicKey(&rsaKey2.PublicKey)
	require.NoError(t, err)
	pubPEM2 := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes2})

	t.Run("single public key fallback", func(t *testing.T) {
		res := PublicKeyResponse{
			PublicKey: string(pubPEM1),
			Algorithm: "RS256",
		}
		ring, err := res.VerificationKeys()
		require.NoError(t, err)
		assert.NotNil(t, ring)
		assert.False(t, ring.HasPrevious())
	})

	t.Run("ring with active and previous", func(t *testing.T) {
		res := PublicKeyResponse{
			Keys: []PublicKeyEntry{
				{KeyID: "key1", PublicKey: string(pubPEM1), Active: false},
				{KeyID: "key2", PublicKey: string(pubPEM2), Active: true},
			},
		}
		ring, err := res.VerificationKeys()
		require.NoError(t, err)
		assert.NotNil(t, ring)
		assert.True(t, ring.HasPrevious())
	})

	t.Run("ring with no active flag defaults to first key", func(t *testing.T) {
		res := PublicKeyResponse{
			Keys: []PublicKeyEntry{
				{KeyID: "key1", PublicKey: string(pubPEM1), Active: false},
			},
		}
		ring, err := res.VerificationKeys()
		require.NoError(t, err)
		assert.NotNil(t, ring)
		assert.False(t, ring.HasPrevious())
	})

	t.Run("ring with invalid pem error", func(t *testing.T) {
		res := PublicKeyResponse{
			Keys: []PublicKeyEntry{
				{KeyID: "bad", PublicKey: "not-a-pem", Active: true},
			},
		}
		_, err := res.VerificationKeys()
		assert.Error(t, err)
	})

	t.Run("jwks standard json response unmarshals and parses into verification keys", func(t *testing.T) {
		origRing, err := NewVerificationKeys(&rsaKey1.PublicKey, &rsaKey2.PublicKey)
		require.NoError(t, err)
		jwks, err := origRing.JWKS("RS256")
		require.NoError(t, err)
		jwksBytes, err := json.Marshal(jwks)
		require.NoError(t, err)

		var res PublicKeyResponse
		err = json.Unmarshal(jwksBytes, &res)
		require.NoError(t, err)

		ring, err := res.VerificationKeys()
		require.NoError(t, err)
		assert.Equal(t, origRing.ActiveKeyID(), ring.ActiveKeyID())
		assert.Equal(t, origRing.PreviousKeyID(), ring.PreviousKeyID())
		assert.True(t, ring.HasPrevious())
	})
}

func TestActiveKeyID(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	auth, err := NewAuthenticator(JWTConfig{}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "", auth.ActiveKeyID())

	keys, err := NewVerificationKeys(&rsaKey.PublicKey, nil)
	require.NoError(t, err)
	require.NoError(t, auth.SetVerificationKeys(keys))
	assert.NotEmpty(t, auth.ActiveKeyID())
}

func TestParseAndVerifyToken_DetailedErrors(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := "iam.test.com"
	audience := "amadeus-gateway"

	cfg := NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256)
	memStore := NewMemoryTokenVersionStore()
	auth, err := NewAuthenticator(cfg, memStore, slog.New(slog.DiscardHandler))
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
				Subject:   "101",
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

	t.Run("empty token matches ErrTokenEmpty", func(t *testing.T) {
		claims, err := auth.ParseAndVerifyToken("  ")
		assert.Nil(t, claims)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenEmpty))
		assert.True(t, IsTokenInvalid(err))
	})

	t.Run("expired token matches ErrTokenExpired", func(t *testing.T) {
		c := validClaims()
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Nil(t, claims)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenExpired))
		assert.True(t, IsTokenExpired(err))
		assert.True(t, errors.Is(err, ErrTokenInvalid))
	})

	t.Run("invalid signature matches ErrTokenSignatureInvalid", func(t *testing.T) {
		c := validClaims()
		tokenStr := signToken(jwt.SigningMethodRS256, otherRSAKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Nil(t, claims)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenSignatureInvalid))
		assert.True(t, IsTokenSignatureInvalid(err))
		assert.True(t, errors.Is(err, ErrTokenInvalid))
	})

	t.Run("refresh token type matches ErrTokenTypeMismatch with details", func(t *testing.T) {
		c := validClaims()
		c.Type = TokenTypeRefresh
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Nil(t, claims)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenTypeMismatch))
		assert.True(t, IsTokenTypeMismatch(err))
		assert.True(t, errors.Is(err, ErrTokenInvalid))

		details := errors.GetDetails(err)
		assert.Contains(t, details, "actual_type")
		assert.Contains(t, details, TokenTypeRefresh)
	})

	t.Run("missing user claims matches ErrTokenClaimsInvalid", func(t *testing.T) {
		c := validClaims()
		c.UserID = 0
		tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, c)

		claims, err := auth.ParseAndVerifyToken(tokenStr)
		assert.Nil(t, claims)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenClaimsInvalid))
		assert.True(t, errors.Is(err, ErrTokenInvalid))
	})

	t.Run("revoked token version matches ErrTokenRevoked with details", func(t *testing.T) {
		ctx := context.Background()
		require.NoError(t, memStore.SetTokenVersion(ctx, 101, 5))

		c := validClaims()
		c.TokenVersion = 2

		err := auth.VerifyTokenVersion(ctx, c)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenRevoked))
		assert.True(t, IsTokenRevoked(err))
		assert.True(t, errors.Is(err, ErrTokenInvalid))

		details := errors.GetDetails(err)
		assert.Contains(t, details, "user_id")
		assert.Contains(t, details, uint64(101))
		assert.Contains(t, details, "server_version")
		assert.Contains(t, details, uint64(5))
		assert.Contains(t, details, "token_version")
		assert.Contains(t, details, uint64(2))
	})

	t.Run("token version unavailable when store unconfigured", func(t *testing.T) {
		unconfAuth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		c := validClaims()
		err = unconfAuth.VerifyTokenVersion(context.Background(), c)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenVersionUnavailable))
		assert.True(t, IsTokenVersionUnavailable(err))
		assert.False(t, errors.Is(err, ErrTokenInvalid))
	})
}

func TestParseAndVerifyTokenContext(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := NewJWTConfig("test-issuer", "test-audience", &rsaKey.PublicKey, jwt.SigningMethodRS256)
	auth, err := NewAuthenticator(cfg, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	signToken := func(method jwt.SigningMethod, key crypto.PrivateKey, claims *JwtClaims) string {
		tok := jwt.NewWithClaims(method, claims)
		str, err := tok.SignedString(key)
		require.NoError(t, err)
		return str
	}

	validClaims := func() *JwtClaims {
		now := time.Now()
		return &JwtClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-issuer",
				Audience:  jwt.ClaimStrings{"test-audience"},
				Subject:   "101",
				ID:        "jti-ctx-1",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
			UserInfo: UserInfo{
				UserID:       101,
				Username:     "testuser",
				TokenVersion: 1,
			},
			Type: TokenTypeAccess,
		}
	}

	tokenStr := signToken(jwt.SigningMethodRS256, rsaKey, validClaims())

	t.Run("valid token with active context", func(t *testing.T) {
		claims, err := auth.ParseAndVerifyTokenContext(context.Background(), tokenStr)
		require.NoError(t, err)
		assert.Equal(t, uint64(101), claims.UserID)
	})

	t.Run("valid token with nil context defaults to background", func(t *testing.T) {
		var nilCtx context.Context
		claims, err := auth.ParseAndVerifyTokenContext(nilCtx, tokenStr)
		require.NoError(t, err)
		assert.Equal(t, uint64(101), claims.UserID)
	})

	t.Run("cancelled context aborts token verification", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		claims, err := auth.ParseAndVerifyTokenContext(ctx, tokenStr)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.True(t, errors.Is(err, ErrTokenInvalid))
		assert.Contains(t, err.Error(), "token verification aborted by context")
	})
}
