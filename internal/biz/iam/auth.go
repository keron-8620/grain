package iam

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"grain/pkg/auth"
	"grain/pkg/cryptoutil"
	"grain/pkg/errorx"
)

// TokenPair represents the access and refresh token pair issued to a client.
type TokenPair struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// LoginResult wraps the authenticated user DO and the newly issued token pair.
type LoginResult struct {
	User      *User      `json:"user"`
	TokenPair *TokenPair `json:"tokens"`
}

// TokenManager defines the contract for signing, parsing, and rotating IAM JWT tokens.
type TokenManager interface {
	IssueTokenPair(ctx context.Context, user *User, tokenVersion uint64) (*TokenPair, *auth.JwtClaims, error)
	VerifyToken(ctx context.Context, tokenStr string) (*auth.JwtClaims, error)
	RotateTokenPair(ctx context.Context, user *User, oldClaims *auth.JwtClaims, newTokenVersion uint64, newJTI string) (*TokenPair, *auth.JwtClaims, error)
	PublicKey() crypto.PublicKey
	KeyID() string
}

// TokenConfig holds configuration options for initializing a TokenManager.
type TokenConfig struct {
	Issuer          string
	Audience        string
	AccessDuration  time.Duration
	RefreshDuration time.Duration
	SigningMethod   jwt.SigningMethod
	SigningKey      crypto.PrivateKey
	VerifyKey       crypto.PublicKey
	KeyID           string
	Authenticator   *auth.Authenticator
}

type defaultTokenManager struct {
	cfg TokenConfig
}

// NewTokenManager builds a TokenManager with default parameters when fields are omitted.
func NewTokenManager(cfg TokenConfig) (TokenManager, error) {
	if cfg.Issuer == "" {
		cfg.Issuer = "iam.grain.com"
	}
	if cfg.Audience == "" {
		cfg.Audience = "grain-api"
	}
	if cfg.AccessDuration <= 0 {
		cfg.AccessDuration = 2 * time.Hour
	}
	if cfg.RefreshDuration <= 0 {
		cfg.RefreshDuration = 7 * 24 * time.Hour
	}
	if cfg.SigningMethod == nil {
		cfg.SigningMethod = jwt.SigningMethodRS256
	}

	// Auto-generate an ephemeral RSA key pair if no private key was provided
	if cfg.SigningKey == nil {
		slog.Warn("TokenManager: no signing key configured, generated ephemeral in-memory RSA key pair; tokens will be invalid across service restarts or across multiple cluster instances")
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.New("failed to generate fallback RSA key: " + err.Error())
		}
		cfg.SigningKey = rsaKey
		cfg.VerifyKey = &rsaKey.PublicKey
	} else if cfg.VerifyKey == nil {
		pub, err := cryptoutil.ExtractPublicKey(cfg.SigningKey)
		if err != nil {
			return nil, errors.New("failed to extract public key from signing key: " + err.Error())
		}
		cfg.VerifyKey = pub
	}

	if cfg.KeyID == "" && cfg.VerifyKey != nil {
		kid, _ := auth.KeyID(cfg.VerifyKey)
		cfg.KeyID = kid
	}

	return &defaultTokenManager{cfg: cfg}, nil
}

func (m *defaultTokenManager) PublicKey() crypto.PublicKey {
	return m.cfg.VerifyKey
}

func (m *defaultTokenManager) KeyID() string {
	return m.cfg.KeyID
}

func (m *defaultTokenManager) sign(claims *auth.JwtClaims) (string, error) {
	tok := jwt.NewWithClaims(m.cfg.SigningMethod, claims)
	if m.cfg.KeyID != "" {
		tok.Header["kid"] = m.cfg.KeyID
	}
	return tok.SignedString(m.cfg.SigningKey)
}

func (m *defaultTokenManager) VerifyToken(ctx context.Context, tokenStr string) (*auth.JwtClaims, error) {
	if m.cfg.Authenticator != nil {
		return m.cfg.Authenticator.ParseAndVerifyTokenContext(ctx, tokenStr)
	}

	parserOptions := []jwt.ParserOption{
		jwt.WithIssuer(m.cfg.Issuer),
		jwt.WithAudience(m.cfg.Audience),
	}

	tok, err := jwt.ParseWithClaims(tokenStr, &auth.JwtClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != m.cfg.SigningMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.cfg.VerifyKey, nil
	}, parserOptions...)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*auth.JwtClaims)
	if !ok || !tok.Valid {
		return nil, auth.ErrTokenInvalid
	}
	return claims, nil
}

func (m *defaultTokenManager) IssueTokenPair(ctx context.Context, user *User, tokenVersion uint64) (*TokenPair, *auth.JwtClaims, error) {
	if user == nil {
		return nil, nil, errors.New("user cannot be nil")
	}

	now := time.Now()
	accessJTI := uuid.NewString()
	accessClaims := &auth.JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.cfg.Issuer,
			Audience:  jwt.ClaimStrings{m.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.AccessDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        accessJTI,
			Subject:   strconv.FormatUint(user.ID, 10),
		},
		UserInfo: auth.UserInfo{
			UserID:       user.ID,
			Username:     user.Username,
			RoleID:       user.RoleID,
			IsStaff:      true,
			TokenVersion: tokenVersion,
		},
		Type:     auth.TokenTypeAccess,
		AuthTime: jwt.NewNumericDate(now),
	}

	accessStr, err := m.sign(accessClaims)
	if err != nil {
		return nil, nil, err
	}

	refreshJTI := uuid.NewString()
	familyID, err := auth.GenerateFamilyID()
	if err != nil {
		return nil, nil, err
	}

	refreshClaims := &auth.JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.cfg.Issuer,
			Audience:  jwt.ClaimStrings{m.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.RefreshDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        refreshJTI,
			Subject:   strconv.FormatUint(user.ID, 10),
		},
		UserInfo: auth.UserInfo{
			UserID:       user.ID,
			Username:     user.Username,
			RoleID:       user.RoleID,
			IsStaff:      true,
			TokenVersion: tokenVersion,
		},
		Type:     auth.TokenTypeRefresh,
		AuthTime: jwt.NewNumericDate(now),
		FamilyID: familyID,
	}

	refreshStr, err := m.sign(refreshClaims)
	if err != nil {
		return nil, nil, err
	}

	return &TokenPair{
		AccessToken:      accessStr,
		RefreshToken:     refreshStr,
		TokenType:        "Bearer",
		ExpiresIn:        int64(m.cfg.AccessDuration / time.Second),
		RefreshExpiresIn: int64(m.cfg.RefreshDuration / time.Second),
	}, refreshClaims, nil
}

func (m *defaultTokenManager) RotateTokenPair(ctx context.Context, user *User, oldClaims *auth.JwtClaims, newTokenVersion uint64, newJTI string) (*TokenPair, *auth.JwtClaims, error) {
	if user == nil || oldClaims == nil {
		return nil, nil, errors.New("user and old claims cannot be nil")
	}

	now := time.Now()
	authTime := oldClaims.AuthTime
	if authTime == nil {
		authTime = jwt.NewNumericDate(now)
	}

	accessJTI := uuid.NewString()
	accessClaims := &auth.JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.cfg.Issuer,
			Audience:  jwt.ClaimStrings{m.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.AccessDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        accessJTI,
			Subject:   strconv.FormatUint(user.ID, 10),
		},
		UserInfo: auth.UserInfo{
			UserID:       user.ID,
			Username:     user.Username,
			RoleID:       user.RoleID,
			IsStaff:      true,
			TokenVersion: newTokenVersion,
		},
		Type:     auth.TokenTypeAccess,
		AuthTime: authTime,
	}

	accessStr, err := m.sign(accessClaims)
	if err != nil {
		return nil, nil, err
	}

	if newJTI == "" {
		newJTI = uuid.NewString()
	}

	refreshClaims := &auth.JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.cfg.Issuer,
			Audience:  jwt.ClaimStrings{m.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.RefreshDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        newJTI,
			Subject:   strconv.FormatUint(user.ID, 10),
		},
		UserInfo: auth.UserInfo{
			UserID:       user.ID,
			Username:     user.Username,
			RoleID:       user.RoleID,
			IsStaff:      true,
			TokenVersion: newTokenVersion,
		},
		Type:     auth.TokenTypeRefresh,
		AuthTime: authTime,
		FamilyID: oldClaims.FamilyID,
	}

	refreshStr, err := m.sign(refreshClaims)
	if err != nil {
		return nil, nil, err
	}

	return &TokenPair{
		AccessToken:      accessStr,
		RefreshToken:     refreshStr,
		TokenType:        "Bearer",
		ExpiresIn:        int64(m.cfg.AccessDuration / time.Second),
		RefreshExpiresIn: int64(m.cfg.RefreshDuration / time.Second),
	}, refreshClaims, nil
}

// AuthUseCase handles user authentication, refresh token family rotation, and session management.
type AuthUseCase struct {
	userRepo UserRepo
	roleRepo RoleRepo
	tokenMgr TokenManager
	logger   *slog.Logger
	ttl      time.Duration
}

// NewAuthUseCase creates a new AuthUseCase instance.
func NewAuthUseCase(
	userRepo UserRepo,
	roleRepo RoleRepo,
	tokenMgr TokenManager,
	logger *slog.Logger,
	ttl ...time.Duration,
) *AuthUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	refreshTTL := 7 * 24 * time.Hour
	if len(ttl) > 0 && ttl[0] > 0 {
		refreshTTL = ttl[0]
	}
	return &AuthUseCase{
		userRepo: userRepo,
		roleRepo: roleRepo,
		tokenMgr: tokenMgr,
		logger:   logger,
		ttl:      refreshTTL,
	}
}

// TokenManager returns the TokenManager instance.
func (uc *AuthUseCase) TokenManager() TokenManager {
	return uc.tokenMgr
}

// Login authenticates a user by username and password, and issues access and refresh tokens.
func (uc *AuthUseCase) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	cleanUsername := strings.TrimSpace(username)
	if cleanUsername == "" || password == "" {
		return nil, errorx.CodeMissingParam.Error("用户名和密码不能为空")
	}

	user, err := uc.userRepo.FindByUsername(ctx, cleanUsername, "Role")
	if err != nil {
		if errorx.IsRecordNotFound(err) {
			return nil, errorx.CodeAuthFailed.Error("用户名或密码错误")
		}
		return nil, errorx.FromDBError(err)
	}
	if user == nil {
		return nil, errorx.CodeAuthFailed.Error("用户名或密码错误")
	}

	if !user.IsActive {
		return nil, errorx.CodeAccountLocked.Error("账号已被禁用，请联系管理员")
	}

	hasher := cryptoutil.NewBcryptHasher(0)
	valid, err := hasher.VerifyString(password, user.Password)
	if err != nil || !valid {
		return nil, errorx.CodeAuthFailed.Error("用户名或密码错误")
	}

	version, err := uc.userRepo.GetTokenVersion(ctx, user.ID)
	if err != nil {
		version = user.TokenVersion
	}

	tokens, _, err := uc.tokenMgr.IssueTokenPair(ctx, user, version)
	if err != nil {
		uc.logger.ErrorContext(ctx, "failed to issue token pair", slog.Uint64("user_id", user.ID), slog.Any("error", err))
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "签发登录凭证失败")
	}

	return &LoginResult{
		User:      user.Sanitize(),
		TokenPair: tokens,
	}, nil
}

// RefreshToken performs refresh token rotation (RTR) with family reuse detection.
func (uc *AuthUseCase) RefreshToken(ctx context.Context, refreshTokenStr string) (*TokenPair, error) {
	tokenStr := strings.TrimSpace(refreshTokenStr)
	if tokenStr == "" {
		return nil, errorx.CodeMissingParam.Error("刷新令牌不能为空")
	}

	claims, err := uc.tokenMgr.VerifyToken(ctx, tokenStr)
	if err != nil {
		if errors.Is(err, auth.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errorx.CodeTokenExpired.Error("刷新令牌已过期，请重新登录")
		}
		return nil, errorx.CodeTokenInvalid.Error("无效的刷新令牌")
	}

	if claims.Type != auth.TokenTypeRefresh {
		return nil, errorx.CodeTokenTypeMismatch.Error("令牌类型不匹配，需提供刷新令牌")
	}
	if claims.FamilyID == "" || claims.ID == "" {
		return nil, errorx.CodeTokenInvalid.Error("刷新令牌缺少必要标识")
	}

	user, err := uc.userRepo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if user == nil {
		return nil, errorx.CodeRecordNotFound.Error("用户不存在")
	}
	if !user.IsActive {
		return nil, errorx.CodeAccountLocked.Error("账号已被禁用")
	}

	currentVersion, err := uc.userRepo.GetTokenVersion(ctx, user.ID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if claims.TokenVersion != currentVersion {
		return nil, errorx.CodeTokenInvalid.Error("登录状态已失效，请重新登录")
	}

	newJTI := uuid.NewString()
	res, err := uc.userRepo.RotateRefreshTokenFamily(ctx, claims.FamilyID, claims.ID, newJTI, user.ID, uc.ttl)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if res == RotateFamilyCompromised {
		_ = uc.userRepo.IncrementTokenVersion(ctx, user.ID)
		return nil, errorx.CodeReplayAttack.Error("检测到令牌重放风险，所有会话已强制下线")
	}
	if res != RotateFamilySuccess {
		return nil, errorx.CodeAuthFailed.Error("刷新令牌验证失败")
	}

	newTokens, _, err := uc.tokenMgr.RotateTokenPair(ctx, user, claims, currentVersion, newJTI)
	if err != nil {
		uc.logger.ErrorContext(ctx, "failed to rotate token pair", slog.Uint64("user_id", user.ID), slog.Any("error", err))
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "重新签发凭证失败")
	}

	return newTokens, nil
}

// Logout consumes the refresh token and increments user token version to invalidate access tokens.
func (uc *AuthUseCase) Logout(ctx context.Context, userID uint64, jti string, ttl ...time.Duration) error {
	if userID == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	if jti != "" {
		expiration := uc.ttl
		if len(ttl) > 0 && ttl[0] > 0 {
			expiration = ttl[0]
		}
		_, _ = uc.userRepo.ConsumeRefreshToken(ctx, jti, expiration)
	}

	if err := uc.userRepo.IncrementTokenVersion(ctx, userID); err != nil {
		return errorx.FromDBError(err)
	}

	return nil
}

// RevokeUserSessions invalidates all sessions for a user by incrementing their token version.
func (uc *AuthUseCase) RevokeUserSessions(ctx context.Context, userID uint64) error {
	if userID == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}
	if err := uc.userRepo.IncrementTokenVersion(ctx, userID); err != nil {
		return errorx.FromDBError(err)
	}
	return nil
}
