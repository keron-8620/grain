package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimsContext(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		claims, err := GetJwtClaims(nil) //nolint:staticcheck // explicitly verify the defensive branch for a nil context
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("missing claims in context", func(t *testing.T) {
		ctx := context.Background()
		claims, err := GetJwtClaims(ctx)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("invalid type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), jwtClaimsContextKey{}, "not-a-claims-struct")
		claims, err := GetJwtClaims(ctx)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("set and get claims successfully", func(t *testing.T) {
		expected := &JwtClaims{
			UserInfo: UserInfo{
				UserID:       1001,
				Username:     "alice",
				RoleID:       1,
				IsStaff:      true,
				TokenVersion: 2,
			},
			Type: TokenTypeAccess,
		}

		ctx := SetJwtClaims(context.Background(), expected)
		claims, err := GetJwtClaims(ctx)
		require.NoError(t, err)
		assert.Equal(t, expected, claims)

		mustClaims, err := GetJwtClaims(ctx)
		assert.NoError(t, err)
		assert.Equal(t, expected, mustClaims)
	})

	t.Run("user token version key", func(t *testing.T) {
		key := UserTokenVersionKey(123)
		assert.Equal(t, "iam:user-token-version:123", key)
	})
}

func TestNewJWTConfig(t *testing.T) {
	cfg := NewJWTConfig("my-issuer", "my-audience", "fake-pubkey", nil)
	assert.Equal(t, "my-issuer", cfg.issuer)
	assert.Equal(t, "my-audience", cfg.audience)
	assert.Equal(t, "fake-pubkey", cfg.publicKey)
	assert.Nil(t, cfg.method)
}
