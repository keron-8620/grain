package auth

import (
	"context"
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWT verification
type JWTConfig struct {
	// issuer identifies the principal that issued the token.
	issuer string
	// audience identifies the service that may consume the token.
	audience string
	// publicKey is derived from privateKey and used for verification.
	publicKey crypto.PublicKey
	// method is the signing algorithm (e.g., jwt.SigningMethodRS256).
	method jwt.SigningMethod
}

// NewJWTConfig creates and validates a new JWT configuration.
// It ensures that issuer, token type, signing method (asymmetric only),
// private key type/strength, and expiration are all valid.
func NewJWTConfig(
	issuer string,
	audience string,
	publicKey crypto.PrivateKey,
	method jwt.SigningMethod,
) JWTConfig {
	return JWTConfig{
		issuer:    issuer,
		audience:  audience,
		publicKey: publicKey,
		method:    method,
	}
}

// TokenType defines the purpose type of a JWT token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// jwtClaimsContextKey is the private key type used to store and retrieve JwtClaims in a context.
// A custom type is used instead of a string key to avoid collisions with same-named keys injected by other packages.
type jwtClaimsContextKey struct{}

// UserInfo represents the user payload contract carried by JWTs issued by IAM (shared across the system)
type UserInfo struct {
	UserID       uint32 `json:"uid"` // Unique user ID
	Username     string `json:"un"`  // Username
	RoleID       uint32 `json:"rid"` // Role ID
	IsStaff      bool   `json:"isf"` // Whether the user is internal staff
	TokenVersion uint64 `json:"tv"`  // User token revocation version
}

// UserTokenVersionKey generates the user token version key in Redis
func UserTokenVersionKey(userID uint32) string {
	return fmt.Sprintf("iam:user-token-version:%d", userID)
}

// JwtClaims is the system-wide standard JWT claims contract struct
type JwtClaims struct {
	jwt.RegisteredClaims
	UserInfo
	Type TokenType `json:"typ"` // Token type (access or refresh)
	// AuthTime is the original login time, carried across refresh-token rotations so the
	// server can enforce an absolute session lifetime. Absent on legacy tokens.
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	// FamilyID is the session family ID used for refresh token rotation and replay detection.
	FamilyID string `json:"fid,omitempty"`
}

// GetJwtClaims retrieves JwtClaims from a context.Context
func GetJwtClaims(ctx context.Context) (*JwtClaims, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	val := ctx.Value(jwtClaimsContextKey{})
	if val == nil {
		return nil, fmt.Errorf("claims not found in context")
	}
	claims, ok := val.(*JwtClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims type in context")
	}
	return claims, nil
}

// MustGetJwtClaims retrieves JwtClaims from a context.Context and panics if it is missing
// or has the wrong type. It follows the Must* convention: only call it from request handlers
// after the JWT auth middleware has guaranteed the claims are present. Any other context
// (background jobs, tests without the middleware, transport adapters before authentication)
// must use GetJwtClaims and handle the error instead.
func MustGetJwtClaims(ctx context.Context) *JwtClaims {
	claims, err := GetJwtClaims(ctx)
	if err != nil {
		panic(fmt.Sprintf("MustGetJwtClaims: %v (only valid after the JWT auth middleware)", err))
	}
	return claims
}

// SetJwtClaims injects JwtClaims into a context.Context
func SetJwtClaims(ctx context.Context, claims *JwtClaims) context.Context {
	return context.WithValue(ctx, jwtClaimsContextKey{}, claims)
}
