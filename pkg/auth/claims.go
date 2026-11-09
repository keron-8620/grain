package auth

import (
	"context"
	"crypto"
	"fmt"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"
	"grain/pkg/cryptoutil"
)

// DefaultLeeway is the default clock skew tolerance duration for JWT validation (exp, nbf, iat).
const DefaultLeeway = 1 * time.Minute

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
	// leeway specifies the duration of clock skew tolerance for validation (e.g. exp, nbf, iat).
	leeway time.Duration
}

// NewJWTConfig creates a new JWT configuration used for token verification.
// By default, it sets leeway to DefaultLeeway (1 minute) to account for clock skew.
func NewJWTConfig(
	issuer string,
	audience string,
	publicKey crypto.PublicKey,
	method jwt.SigningMethod,
) JWTConfig {
	return JWTConfig{
		issuer:    issuer,
		audience:  audience,
		publicKey: publicKey,
		method:    method,
		leeway:    DefaultLeeway,
	}
}

// WithLeeway returns a copy of JWTConfig with the specified clock skew tolerance.
// A negative duration is normalized to 0 (no clock skew tolerance).
func (c JWTConfig) WithLeeway(leeway time.Duration) JWTConfig {
	if leeway < 0 {
		leeway = 0
	}
	c.leeway = leeway
	return c
}

// Leeway returns the configured clock skew leeway duration.
func (c JWTConfig) Leeway() time.Duration {
	return c.leeway
}

// Issuer returns the configured token issuer.
func (c JWTConfig) Issuer() string {
	return c.issuer
}

// Audience returns the configured token audience.
func (c JWTConfig) Audience() string {
	return c.audience
}

// PublicKey returns the configured verification public key.
func (c JWTConfig) PublicKey() crypto.PublicKey {
	return c.publicKey
}

// Method returns the configured token signing method.
func (c JWTConfig) Method() jwt.SigningMethod {
	return c.method
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
	UserID       uint64 `json:"uid"` // Unique user ID
	Username     string `json:"un"`  // Username
	RoleID       uint64 `json:"rid"` // Role ID
	IsStaff      bool   `json:"isf"` // Whether the user is internal staff
	TokenVersion uint64 `json:"tv"`  // User token revocation version
}

// UserTokenVersionKey generates the user token version key in Redis
func UserTokenVersionKey(userID uint64) string {
	return fmt.Sprintf("iam:user-token-version:%d", userID)
}

// FamilyRevocationKey generates the Redis key used to record a revoked session family (fid).
func FamilyRevocationKey(familyID string) string {
	return fmt.Sprintf("iam:revoked-family:%s", strings.TrimSpace(familyID))
}

// GenerateFamilyID generates a cryptographically secure random session family ID (hex encoded 16 bytes).
func GenerateFamilyID() (string, error) {
	id, err := cryptoutil.GenerateRandomHex(16)
	if err != nil {
		return "", errors.WrapIf(err, "failed to generate random family ID")
	}
	return id, nil
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
		return nil, errors.New("context is nil")
	}
	val := ctx.Value(jwtClaimsContextKey{})
	if val == nil {
		return nil, errors.New("claims not found in context")
	}
	claims, ok := val.(*JwtClaims)
	if !ok {
		return nil, errors.New("invalid JWT claims type in context")
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
