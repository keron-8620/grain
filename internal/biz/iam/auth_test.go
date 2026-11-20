package iam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/auth"
	"grain/pkg/errorx"
)

func TestTokenManager_Basics(t *testing.T) {
	ctx := context.Background()
	mgr, err := NewTokenManager(TokenConfig{
		AccessDuration:  time.Hour,
		RefreshDuration: 24 * time.Hour,
	})
	require.NoError(t, err)

	user := &User{
		ID:       100,
		Username: "tester",
		RoleID:   1,
	}

	t.Run("issue token pair and verify", func(t *testing.T) {
		pair, refreshClaims, err := mgr.IssueTokenPair(ctx, user, 1)
		require.NoError(t, err)
		assert.NotEmpty(t, pair.AccessToken)
		assert.NotEmpty(t, pair.RefreshToken)
		assert.Equal(t, "Bearer", pair.TokenType)
		assert.NotEmpty(t, refreshClaims.FamilyID)
		assert.Equal(t, auth.TokenTypeRefresh, refreshClaims.Type)

		// Verify refresh token
		claims, err := mgr.VerifyToken(ctx, pair.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, user.ID, claims.UserID)
		assert.Equal(t, user.Username, claims.Username)
		assert.Equal(t, auth.TokenTypeRefresh, claims.Type)
		assert.Equal(t, uint64(1), claims.TokenVersion)
	})

	t.Run("rotate token pair preserves family ID and authTime", func(t *testing.T) {
		_, originalRefreshClaims, err := mgr.IssueTokenPair(ctx, user, 1)
		require.NoError(t, err)

		newPair, newRefreshClaims, err := mgr.RotateTokenPair(ctx, user, originalRefreshClaims, 1, "new-jti-123")
		require.NoError(t, err)
		assert.Equal(t, originalRefreshClaims.FamilyID, newRefreshClaims.FamilyID)
		assert.Equal(t, originalRefreshClaims.AuthTime.Unix(), newRefreshClaims.AuthTime.Unix())
		assert.Equal(t, "new-jti-123", newRefreshClaims.ID)
		assert.NotEmpty(t, newPair.AccessToken)
		assert.NotEmpty(t, newPair.RefreshToken)
	})
}

func TestAuthUseCase_Login(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	userUC := NewUserUseCase(userRepo, roleRepo, nil)
	tokenMgr, err := NewTokenManager(TokenConfig{})
	require.NoError(t, err)

	authUC := NewAuthUseCase(userRepo, roleRepo, tokenMgr, nil)
	userUC.SetAuthUseCase(authUC)

	role, _ := roleRepo.Create(ctx, &Role{Name: "UserRole"})
	_, err = userUC.Create(ctx, &User{
		Username: "eva",
		RoleID:   role.ID,
		IsActive: true,
	}, "mypassword123")
	require.NoError(t, err)

	t.Run("missing username or password", func(t *testing.T) {
		_, err := authUC.Login(ctx, "", "mypassword123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = authUC.Login(ctx, "eva", "")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("user not found returns CodeAuthFailed", func(t *testing.T) {
		_, err := authUC.Login(ctx, "nonexistent", "password")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeAuthFailed))
	})

	t.Run("wrong password returns CodeAuthFailed", func(t *testing.T) {
		_, err := authUC.Login(ctx, "eva", "wrongpass")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeAuthFailed))
	})

	t.Run("disabled account returns CodeAccountLocked", func(t *testing.T) {
		disabledUser, _ := userUC.Create(ctx, &User{
			Username: "disabled_user",
			RoleID:   role.ID,
			IsActive: false,
		}, "password123")
		_ = disabledUser

		_, err := authUC.Login(ctx, "disabled_user", "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeAccountLocked))
	})

	t.Run("success login directly and via userUseCase delegation", func(t *testing.T) {
		res, err := authUC.Login(ctx, "eva", "mypassword123")
		require.NoError(t, err)
		assert.Equal(t, "eva", res.User.Username)
		assert.Empty(t, res.User.Password)
		assert.NotEmpty(t, res.TokenPair.AccessToken)
		assert.NotEmpty(t, res.TokenPair.RefreshToken)

		// Via UserUseCase delegation
		res2, err := userUC.Login(ctx, "eva", "mypassword123")
		require.NoError(t, err)
		assert.Equal(t, "eva", res2.User.Username)
	})
}

func TestAuthUseCase_RefreshToken(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	userUC := NewUserUseCase(userRepo, roleRepo, nil)
	tokenMgr, err := NewTokenManager(TokenConfig{
		AccessDuration:  time.Hour,
		RefreshDuration: 24 * time.Hour,
	})
	require.NoError(t, err)

	authUC := NewAuthUseCase(userRepo, roleRepo, tokenMgr, nil)
	userUC.SetAuthUseCase(authUC)

	role, _ := roleRepo.Create(ctx, &Role{Name: "UserRole"})
	user, err := userUC.Create(ctx, &User{
		Username: "frank",
		RoleID:   role.ID,
		IsActive: true,
	}, "password123")
	require.NoError(t, err)

	loginRes, err := authUC.Login(ctx, "frank", "password123")
	require.NoError(t, err)
	refreshToken := loginRes.TokenPair.RefreshToken

	t.Run("empty refresh token", func(t *testing.T) {
		_, err := authUC.RefreshToken(ctx, "")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))
	})

	t.Run("invalid token string", func(t *testing.T) {
		_, err := authUC.RefreshToken(ctx, "malformed.jwt.token")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeTokenInvalid))
	})

	t.Run("access token passed instead of refresh token", func(t *testing.T) {
		_, err := authUC.RefreshToken(ctx, loginRes.TokenPair.AccessToken)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeTokenTypeMismatch))
	})

	t.Run("successful refresh token rotation", func(t *testing.T) {
		newTokens, err := authUC.RefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		assert.NotEmpty(t, newTokens.AccessToken)
		assert.NotEmpty(t, newTokens.RefreshToken)
		assert.NotEqual(t, refreshToken, newTokens.RefreshToken)

		// Delegation via UserUseCase
		newTokens2, err := userUC.RefreshToken(ctx, newTokens.RefreshToken)
		require.NoError(t, err)
		assert.NotEmpty(t, newTokens2.AccessToken)
	})

	t.Run("replay attack detected when family compromised", func(t *testing.T) {
		userRepo.rotateResult = RotateFamilyCompromised
		_, err := authUC.RefreshToken(ctx, refreshToken)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeReplayAttack))
		// Replay triggers revocation of user sessions
		assert.Greater(t, userRepo.incrementVersionCalled[user.ID], 0)
		userRepo.rotateResult = RotateFamilySuccess
	})

	t.Run("token version mismatch rejected", func(t *testing.T) {
		// Advance user token version so existing token claims version mismatch
		userRepo.tokenVersions[user.ID] = 999
		_, err := authUC.RefreshToken(ctx, refreshToken)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeTokenInvalid))
	})
}

func TestAuthUseCase_LoginLockout(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	tokenMgr, err := NewTokenManager(TokenConfig{})
	require.NoError(t, err)
	authUC := NewAuthUseCaseWithConfig(userRepo, roleRepo, tokenMgr, nil, AuthUseCaseConfig{
		MaxFailedAttempts: 3,
		LockDuration:      time.Hour,
	})
	userUC := NewUserUseCase(userRepo, roleRepo, nil)
	userUC.SetAuthUseCase(authUC)

	role, _ := roleRepo.Create(ctx, &Role{Name: "LockRole"})
	_, err = userUC.Create(ctx, &User{
		Username: "lock_user",
		RoleID:   role.ID,
		IsActive: true,
	}, "password123")
	require.NoError(t, err)

	t.Run("wrong passwords lock the account at threshold", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			_, err := authUC.Login(ctx, "lock_user", "wrong-password")
			require.Error(t, err)
			assert.True(t, errorx.IsCode(err, errorx.CodeAuthFailed))
		}

		_, err := authUC.Login(ctx, "lock_user", "wrong-password")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeAccountLocked))

		// Even the correct password is rejected while locked.
		_, err = authUC.Login(ctx, "lock_user", "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeAccountLocked))
	})

	t.Run("lock expires when the counter is cleared", func(t *testing.T) {
		delete(userRepo.loginFailures, "lock_user")
		res, err := authUC.Login(ctx, "lock_user", "password123")
		require.NoError(t, err)
		assert.NotEmpty(t, res.TokenPair.AccessToken)
	})

	t.Run("successful login clears previous failures", func(t *testing.T) {
		_, _ = authUC.Login(ctx, "lock_user", "wrong-password")
		_, _ = authUC.Login(ctx, "lock_user", "wrong-password")
		require.Equal(t, int64(2), userRepo.loginFailures["lock_user"])

		_, err := authUC.Login(ctx, "lock_user", "password123")
		require.NoError(t, err)
		assert.Equal(t, int64(0), userRepo.loginFailures["lock_user"])
	})

	t.Run("unknown usernames share the same lockout behaviour", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			_, err := authUC.Login(ctx, "ghost", "wrong-password")
			require.Error(t, err)
			assert.True(t, errorx.IsCode(err, errorx.CodeAuthFailed))
		}
		_, err := authUC.Login(ctx, "ghost", "wrong-password")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeAccountLocked))
	})

	t.Run("lockout store failure is fail-closed", func(t *testing.T) {
		userRepo.loginFailureErr = errors.New("cache down")
		defer func() { userRepo.loginFailureErr = nil }()

		_, err := authUC.Login(ctx, "lock_user", "password123")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeCacheError))
	})
}

func TestAuthUseCase_LogoutAndRevocation(t *testing.T) {
	ctx := context.Background()
	userRepo := newMockUserRepo()
	roleRepo := newMockRoleRepo()
	userUC := NewUserUseCase(userRepo, roleRepo, nil)
	tokenMgr, _ := NewTokenManager(TokenConfig{})
	authUC := NewAuthUseCase(userRepo, roleRepo, tokenMgr, nil)
	userUC.SetAuthUseCase(authUC)

	role, _ := roleRepo.Create(ctx, &Role{Name: "Role1"})
	user, _ := userUC.Create(ctx, &User{Username: "grace", RoleID: role.ID, IsActive: true}, "password123")

	t.Run("logout marks jti consumed and increments version", func(t *testing.T) {
		err := authUC.Logout(ctx, user.ID, "jti-12345", time.Hour)
		require.NoError(t, err)
		assert.True(t, userRepo.consumedTokens["jti-12345"])
		assert.Equal(t, 1, userRepo.incrementVersionCalled[user.ID])

		// Delegation via UserUseCase
		err = userUC.Logout(ctx, user.ID, "jti-67890")
		require.NoError(t, err)
		assert.True(t, userRepo.consumedTokens["jti-67890"])
		assert.Equal(t, 2, userRepo.incrementVersionCalled[user.ID])
	})

	t.Run("revoke user sessions", func(t *testing.T) {
		err := authUC.RevokeUserSessions(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, 3, userRepo.incrementVersionCalled[user.ID])
	})

	t.Run("delegation without auth attached returns NotImplemented", func(t *testing.T) {
		ucWithoutAuth := NewUserUseCase(userRepo, roleRepo, nil)
		_, err := ucWithoutAuth.Login(ctx, "a", "b")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeNotImplemented))

		_, err = ucWithoutAuth.RefreshToken(ctx, "tok")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeNotImplemented))

		err = ucWithoutAuth.Logout(ctx, 1, "jti")
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeNotImplemented))
	})
}

// staticTokenVersionStore is a minimal auth.TokenVersionStore for token-manager tests.
type staticTokenVersionStore struct{ version uint64 }

func (s staticTokenVersionStore) GetTokenVersion(context.Context, uint64) (uint64, error) {
	return s.version, nil
}

// TestTokenManager_VerifyRefreshTokenWithAuthenticator reproduces the production
// wiring (TokenConfig.Authenticator set by iamserver.New). Before the fix the
// authenticator rejected every refresh token with "token type must be access",
// so /auth/refresh always failed and the rotation/replay-detection chain never
// ran.
func TestTokenManager_VerifyRefreshTokenWithAuthenticator(t *testing.T) {
	ctx := context.Background()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &key.PublicKey

	authenticator, err := auth.NewAuthenticator(
		auth.NewJWTConfig("issuer", "audience", publicKey, jwt.SigningMethodRS256),
		staticTokenVersionStore{},
		nil,
	)
	require.NoError(t, err)

	tokenMgr, err := NewTokenManager(TokenConfig{
		Issuer:          "issuer",
		Audience:        "audience",
		AccessDuration:  time.Hour,
		RefreshDuration: 24 * time.Hour,
		SigningMethod:   jwt.SigningMethodRS256,
		SigningKey:      key,
		VerifyKey:       publicKey,
		Authenticator:   authenticator,
	})
	require.NoError(t, err)

	pair, _, err := tokenMgr.IssueTokenPair(ctx, &User{ID: 7, Username: "tester", RoleID: 1}, 0)
	require.NoError(t, err)

	claims, err := tokenMgr.VerifyToken(ctx, pair.RefreshToken)
	require.NoError(t, err, "refresh token must be accepted when Authenticator is wired in")
	assert.Equal(t, auth.TokenTypeRefresh, claims.Type)

	_, err = tokenMgr.VerifyToken(ctx, pair.AccessToken)
	require.Error(t, err, "access token must not be accepted as a refresh token")
	assert.True(t, errors.Is(err, auth.ErrTokenTypeMismatch))
}
