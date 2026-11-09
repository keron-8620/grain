package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/auth"
)

func init() {
	gin.SetMode(gin.TestMode)
}

type failingTokenVersionStore struct {
	err error
}

func (f *failingTokenVersionStore) GetTokenVersion(_ context.Context, _ uint64) (uint64, error) {
	return 0, f.err
}

func setupAuthTest(t *testing.T) (*rsa.PrivateKey, *auth.Authenticator, *auth.MemoryTokenVersionStore) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := "iam.test.com"
	audience := "test-audience"
	cfg := auth.NewJWTConfig(issuer, audience, &rsaKey.PublicKey, jwt.SigningMethodRS256)
	store := auth.NewMemoryTokenVersionStore()
	logger := slog.New(slog.DiscardHandler)

	au, err := auth.NewAuthenticator(cfg, store, logger)
	require.NoError(t, err)

	return rsaKey, au, store
}

func generateTestToken(t *testing.T, rsaKey *rsa.PrivateKey, userID uint64, username string, roleID uint64, tokenVersion uint64) string {
	t.Helper()
	claims := &auth.JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "iam.test.com",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ID:        "test-token-jti",
			Subject:   strconv.FormatUint(userID, 10),
		},
		UserInfo: auth.UserInfo{
			UserID:       userID,
			Username:     username,
			RoleID:       roleID,
			IsStaff:      true,
			TokenVersion: tokenVersion,
		},
		Type: auth.TokenTypeAccess,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := tok.SignedString(rsaKey)
	require.NoError(t, err)
	return tokenStr
}

func TestJWTAuthMiddleware(t *testing.T) {
	rsaKey, au, store := setupAuthTest(t)
	logger := slog.New(slog.DiscardHandler)

	setupRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(JWTAuthMiddleware(logger, au))
		r.GET("/protected", func(c *gin.Context) {
			claims, err := auth.GetJwtClaims(c.Request.Context())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"user_id": claims.UserID, "username": claims.Username})
		})
		return r
	}

	t.Run("missing auth header", func(t *testing.T) {
		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "10412") // CodeMissingAuth
	})

	t.Run("invalid token", func(t *testing.T) {
		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "10411") // CodeTokenInvalid
	})

	t.Run("expired token returns CodeTokenExpired", func(t *testing.T) {
		claims := &auth.JwtClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "iam.test.com",
				Audience:  jwt.ClaimStrings{"test-audience"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-3 * time.Hour)),
				ID:        "expired-jti",
				Subject:   "199",
			},
			UserInfo: auth.UserInfo{
				UserID:       199,
				Username:     "expired-user",
				RoleID:       1,
				IsStaff:      true,
				TokenVersion: 1,
			},
			Type: auth.TokenTypeAccess,
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenStr, err := tok.SignedString(rsaKey)
		require.NoError(t, err)

		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "10402") // CodeTokenExpired
	})

	t.Run("valid token and matching version", func(t *testing.T) {
		ctx := t.Context()
		require.NoError(t, store.SetTokenVersion(ctx, 101, 1))

		tokenStr := generateTestToken(t, rsaKey, 101, "alice", 1, 1)

		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"user_id":101`)
		assert.Contains(t, w.Body.String(), `"username":"alice"`)
	})

	t.Run("token version revoked or mismatched", func(t *testing.T) {
		ctx := t.Context()
		// Server version is 2, but token version is 1
		require.NoError(t, store.SetTokenVersion(ctx, 102, 2))

		tokenStr := generateTestToken(t, rsaKey, 102, "bob", 1, 1)

		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "10411") // CodeTokenInvalid
	})

	t.Run("token version not found in store (fail-closed)", func(t *testing.T) {
		// User 103 not present in store
		tokenStr := generateTestToken(t, rsaKey, 103, "charlie", 1, 1)

		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "10411") // CodeTokenInvalid
	})

	t.Run("websocket upgrade extraction", func(t *testing.T) {
		ctx := t.Context()
		require.NoError(t, store.SetTokenVersion(ctx, 104, 1))
		tokenStr := generateTestToken(t, rsaKey, 104, "ws-user", 1, 1)

		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Protocol", tokenStr+", soap")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"user_id":104`)
	})

	t.Run("nil authenticator returns config error", func(t *testing.T) {
		r := gin.New()
		r.Use(JWTAuthMiddleware(logger, nil))
		r.GET("/protected", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20004") // CodeConfigError
	})

	t.Run("token version store query failure returns CodeCacheError", func(t *testing.T) {
		cfg := auth.NewJWTConfig("iam.test.com", "test-audience", &rsaKey.PublicKey, jwt.SigningMethodRS256)
		failStore := &failingTokenVersionStore{err: errors.New("redis connection refused")}
		failAu, err := auth.NewAuthenticator(cfg, failStore, logger)
		require.NoError(t, err)

		r := gin.New()
		r.Use(JWTAuthMiddleware(logger, failAu))
		r.GET("/protected", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		tokenStr := generateTestToken(t, rsaKey, 105, "dave", 1, 1)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadGateway, w.Code)
		assert.Contains(t, w.Body.String(), "30002") // CodeCacheError
	})

	t.Run("authenticator without token store returns CodeConfigError", func(t *testing.T) {
		cfg := auth.NewJWTConfig("iam.test.com", "test-audience", &rsaKey.PublicKey, jwt.SigningMethodRS256)
		unconfiguredAu, err := auth.NewAuthenticator(cfg, nil, logger)
		require.NoError(t, err)

		r := gin.New()
		r.Use(JWTAuthMiddleware(logger, unconfiguredAu))
		r.GET("/protected", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		tokenStr := generateTestToken(t, rsaKey, 106, "eve", 1, 1)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20004") // CodeConfigError
	})
}

func TestCasbinAuthMiddleware(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
`)
	require.NoError(t, err)

	adapter := stringadapter.NewAdapter(`
p, iam:role:1, /api/v1/users, GET
p, iam:role:1, /api/v1/users, POST
`)
	enforcer, err := casbin.NewSyncedEnforcer(m, adapter)
	require.NoError(t, err)

	setupRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			// Simulate claims injection from JWT middleware
			roleStr := c.GetHeader("X-Test-Role")
			if roleStr == "1" {
				claims := &auth.JwtClaims{
					UserInfo: auth.UserInfo{
						UserID:   1,
						Username: "admin",
						RoleID:   1,
					},
				}
				c.Request = c.Request.WithContext(auth.SetJwtClaims(c.Request.Context(), claims))
			} else if roleStr == "2" {
				claims := &auth.JwtClaims{
					UserInfo: auth.UserInfo{
						UserID:   2,
						Username: "viewer",
						RoleID:   2,
					},
				}
				c.Request = c.Request.WithContext(auth.SetJwtClaims(c.Request.Context(), claims))
			}
			c.Next()
		})
		r.Use(CasbinAuthMiddleware(logger, enforcer))
		r.GET("/api/v1/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
		r.DELETE("/api/v1/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "deleted"})
		})
		return r
	}

	t.Run("missing claims in context", func(t *testing.T) {
		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/users", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "10414") // CodeAuthFailed
	})

	t.Run("authorized request", func(t *testing.T) {
		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.Header.Set("X-Test-Role", "1")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("forbidden request for role without policy", func(t *testing.T) {
		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.Header.Set("X-Test-Role", "2")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "10403") // CodeForbidden
	})

	t.Run("forbidden request for unmatched action", func(t *testing.T) {
		r := setupRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/users", nil)
		req.Header.Set("X-Test-Role", "1")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "10403") // CodeForbidden
	})

	t.Run("nil enforcer returns config error", func(t *testing.T) {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			claims := &auth.JwtClaims{
				UserInfo: auth.UserInfo{
					UserID:   1,
					Username: "admin",
					RoleID:   1,
				},
			}
			c.Request = c.Request.WithContext(auth.SetJwtClaims(c.Request.Context(), claims))
			c.Next()
		})
		r.Use(CasbinAuthMiddleware(logger, nil))
		r.GET("/api/v1/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/users", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20004") // CodeConfigError
	})

	t.Run("empty full path returns resource not found", func(t *testing.T) {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			claims := &auth.JwtClaims{
				UserInfo: auth.UserInfo{
					UserID:   1,
					Username: "admin",
					RoleID:   1,
				},
			}
			c.Request = c.Request.WithContext(auth.SetJwtClaims(c.Request.Context(), claims))
			c.Next()
		})
		r.NoRoute(CasbinAuthMiddleware(logger, enforcer))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/unregistered/path", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "10404") // CodeResourceNotFound
	})
}
