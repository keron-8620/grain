package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// isLoopbackHost reports whether the host is a loopback address, where plaintext HTTP is acceptable
// for local development.
func isLoopbackHost(host string) bool {
	trimmed := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if trimmed == "localhost" {
		return true
	}
	ip := net.ParseIP(trimmed)
	return ip != nil && ip.IsLoopback()
}

// PublicKeyResponse represents the public key payload returned by IAM.
type PublicKeyResponse struct {
	PublicKey string `json:"public_key"`
	Algorithm string `json:"algorithm"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	// KeyID identifies the active signing key and Keys is the full ring (active plus the previous
	// key while a rotation is in progress). Older IAM versions omit both; PublicKey is then the only
	// key available.
	KeyID string           `json:"key_id"`
	Keys  []PublicKeyEntry `json:"keys"`
}

// VerificationKeys parses the published ring into a verifier key set. It degrades to the single
// PublicKey field when the response carries no ring.
func (r *PublicKeyResponse) VerificationKeys() (*VerificationKeys, error) {
	if len(r.Keys) == 0 {
		pub, err := ParsePublicKey([]byte(r.PublicKey))
		if err != nil {
			return nil, err
		}
		return NewVerificationKeys(pub, nil)
	}
	var active, previous crypto.PublicKey
	for _, entry := range r.Keys {
		pub, err := ParsePublicKey([]byte(entry.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("parse published key %s: %w", entry.KeyID, err)
		}
		if entry.Active {
			active = pub
			continue
		}
		previous = pub
	}
	if active == nil {
		// No key is flagged active: treat the first entry as active so a malformed response cannot
		// silently produce an empty key set.
		pub, err := ParsePublicKey([]byte(r.Keys[0].PublicKey))
		if err != nil {
			return nil, err
		}
		active = pub
	}
	return NewVerificationKeys(active, previous)
}

// FetchPublicKeyHTTP fetches the JWT public key from IAM's HTTP endpoint.
// The transport must be https unless the target is loopback: the fetched key becomes the sole trust
// anchor for every token the consumer accepts, so an attacker able to rewrite a plaintext response
// could substitute its own key and forge tokens for arbitrary users. Prefer configuring a local
// public key (JWT__PUBLIC_KEY) over fetching it at runtime.
func FetchPublicKeyHTTP(ctx context.Context, iamBaseURL, keyType string) (*PublicKeyResponse, error) {
	if iamBaseURL == "" {
		return nil, fmt.Errorf("IAM base URL is required")
	}
	baseURL := strings.TrimRight(iamBaseURL, "/")
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("IAM base URL is invalid: %w", err)
	}
	if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("IAM base URL must use https (or loopback for local development), got %q", parsed.Scheme)
	}

	reqURL := baseURL + "/api/v1/public-key"
	if keyType != "" {
		reqURL = baseURL + "/api/v1/public-key?" + url.Values{"type": []string{keyType}}.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request IAM public key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IAM returned status %d: %s", resp.StatusCode, string(body))
	}

	var res PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode IAM public key response: %w", err)
	}

	return &res, nil
}

// Authenticator provides local JWT public key verification and real-time token version comparison against a TokenVersionStore
type Authenticator struct {
	jwtCfg     JWTConfig
	keys       *VerificationKeys
	tokenStore TokenVersionStore
	logger     *slog.Logger
}

// NewAuthenticator builds an Authenticator instance with a TokenVersionStore.
// A key may be configured later with SetVerificationKeys; an authenticator without one can still be
// used for VerifyTokenVersion, and ParseAndVerifyToken rejects every token until a key is present.
func NewAuthenticator(jwtCfg JWTConfig, store TokenVersionStore, log *slog.Logger) (*Authenticator, error) {
	auth := &Authenticator{jwtCfg: jwtCfg, tokenStore: store, logger: log}
	if jwtCfg.publicKey != nil {
		keys, err := NewVerificationKeys(jwtCfg.publicKey, nil)
		if err != nil {
			return nil, err
		}
		auth.keys = keys
	}
	return auth, nil
}

// NewAuthenticatorWithRedis is a convenience constructor that wraps a Redis client in a RedisTokenVersionStore.
func NewAuthenticatorWithRedis(jwtCfg JWTConfig, rdb redis.UniversalClient, log *slog.Logger) (*Authenticator, error) {
	var store TokenVersionStore
	if rdb != nil {
		store = NewRedisTokenVersionStore(rdb)
	}
	return NewAuthenticator(jwtCfg, store, log)
}

// SetVerificationKeys replaces the verification key set, e.g. after fetching the published ring or
// when a rotation starts. Passing the previous key keeps already-issued tokens valid for the duration
// of the rotation window instead of logging every user out.
func (a *Authenticator) SetVerificationKeys(keys *VerificationKeys) error {
	if keys == nil {
		return fmt.Errorf("verification key set must not be nil")
	}
	a.keys = keys
	return nil
}

// ActiveKeyID returns the key id currently used for verification.
func (a *Authenticator) ActiveKeyID() string {
	if a.keys == nil {
		return ""
	}
	return a.keys.ActiveKeyID()
}

// PublicKeyFromPrivate derives a public key from a private key (lossless for RSA / ECDSA / Ed25519).
// Verifiers and IAM internal middleware share it to avoid inconsistent algorithm support from duplicated implementations.
func PublicKeyFromPrivate(key crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// ParsePublicKey uniformly parses PKCS#1 / PKIX / ECC / Ed25519 public key PEM
func ParsePublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}

	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	default:
		// Try generic parsing
		if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("unknown public key PEM type: %s", block.Type)
	}
}

func parsePublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	return ParsePublicKey(pemBytes)
}

// ParseAndVerifyToken parses and verifies the JWT signature and claim constraints.
// The checks mirror IAM's own server-side middleware (algorithm pinning, issuer, audience, expiry
// required, token type and payload) so a consumer cannot accept a token the issuer would reject.
func (a *Authenticator) ParseAndVerifyToken(tokenString string) (*JwtClaims, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, fmt.Errorf("token must not be empty")
	}
	if a.jwtCfg.method == nil || a.keys == nil {
		return nil, fmt.Errorf("authenticator is not configured with a signing method and verification key")
	}

	claims := &JwtClaims{}
	token, err := ParseWithKeyRing(tokenString, claims, a.keys, a.jwtCfg.method.Alg(),
		a.jwtCfg.issuer, a.jwtCfg.audience,
		// Without this the library treats a missing exp as "valid forever", so a token signed
		// without an expiry would be accepted indefinitely.
		jwt.WithExpirationRequired(),
	)

	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if claims.Type != TokenTypeAccess {
		return nil, fmt.Errorf("token type must be access")
	}

	if claims.UserID == 0 || claims.Username == "" || claims.ID == "" {
		return nil, fmt.Errorf("token missing required uid, un or jti claims")
	}
	if claims.Subject == "" || claims.Subject != claims.Username {
		return nil, fmt.Errorf("token subject does not match username")
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("token is missing the exp claim")
	}

	return claims, nil
}

// VerifyTokenVersion checks the user's real-time token_version against the configured TokenVersionStore
// to prevent the use of revoked tokens.
// It is fail-closed: when the store is not configured, unreachable, or the version key is missing
// (cache eviction, restart, or no login yet), the token is rejected instead of being trusted.
// Callers should treat the error as "re-authenticate required"; a valid refresh token repopulates the cache.
func (a *Authenticator) VerifyTokenVersion(ctx context.Context, claims *JwtClaims) error {
	if a.tokenStore == nil {
		return fmt.Errorf("token version check unavailable: token store is not configured")
	}

	ver, err := a.tokenStore.GetTokenVersion(ctx, claims.UserID)
	if err != nil {
		if errors.Is(err, ErrTokenVersionNotFound) {
			// A missing key means the revocation baseline cannot be verified. Reject rather than
			// accepting tv=0: eviction or a restart without persistence would otherwise
			// revive already-revoked tokens.
			return fmt.Errorf("token version unavailable for user %d", claims.UserID)
		}
		return fmt.Errorf("failed to query token version: %w", err)
	}

	if ver != claims.TokenVersion {
		return fmt.Errorf("token revoked (server version: %d, token version: %d)", ver, claims.TokenVersion)
	}

	return nil
}
