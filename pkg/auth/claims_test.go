package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimsContext(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		var nilCtx context.Context
		claims, err := GetJwtClaims(nilCtx)
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

		mustClaims := MustGetJwtClaims(ctx)
		assert.Equal(t, expected, mustClaims)
	})

	t.Run("must get jwt claims panics when missing or nil context", func(t *testing.T) {
		assert.Panics(t, func() {
			MustGetJwtClaims(context.Background())
		})
		assert.Panics(t, func() {
			var nilCtx context.Context
			MustGetJwtClaims(nilCtx)
		})
	})

	t.Run("user token version key", func(t *testing.T) {
		key := UserTokenVersionKey(123)
		assert.Equal(t, "iam:user-token-version:123", key)
	})

	t.Run("family revocation key and generator", func(t *testing.T) {
		key := FamilyRevocationKey("fid-xyz-123")
		assert.Equal(t, "iam:revoked-family:fid-xyz-123", key)

		// Trims whitespace
		keyTrim := FamilyRevocationKey("  fid-xyz-123  ")
		assert.Equal(t, "iam:revoked-family:fid-xyz-123", keyTrim)

		// GenerateFamilyID
		fid1, err1 := GenerateFamilyID()
		require.NoError(t, err1)
		assert.Len(t, fid1, 32) // 16 bytes hex is 32 chars

		fid2, err2 := GenerateFamilyID()
		require.NoError(t, err2)
		assert.Len(t, fid2, 32)
		assert.NotEqual(t, fid1, fid2)
	})
}

func TestNewJWTConfig(t *testing.T) {
	cfg := NewJWTConfig("my-issuer", "my-audience", "fake-pubkey", jwt.SigningMethodRS256)
	assert.Equal(t, "my-issuer", cfg.issuer)
	assert.Equal(t, "my-issuer", cfg.Issuer())
	assert.Equal(t, "my-audience", cfg.audience)
	assert.Equal(t, "my-audience", cfg.Audience())
	assert.Equal(t, "fake-pubkey", cfg.publicKey)
	assert.Equal(t, "fake-pubkey", cfg.PublicKey())
	assert.Equal(t, jwt.SigningMethodRS256, cfg.method)
	assert.Equal(t, jwt.SigningMethodRS256, cfg.Method())
	assert.Equal(t, DefaultLeeway, cfg.Leeway())

	// Test WithLeeway customization
	customCfg := cfg.WithLeeway(15 * time.Second)
	assert.Equal(t, 15*time.Second, customCfg.Leeway())

	// Test WithLeeway with negative duration normalizes to 0
	zeroCfg := cfg.WithLeeway(-5 * time.Second)
	assert.Equal(t, time.Duration(0), zeroCfg.Leeway())
}
