package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"grain/pkg/cryptoutil"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// DefaultFetchMaxBytes is the maximum response body size (1 MiB) accepted from an IAM public key endpoint.
const DefaultFetchMaxBytes = 1024 * 1024

// DefaultFetchTimeout is the default timeout for fetching public keys over HTTP.
const DefaultFetchTimeout = 5 * time.Second

// fetchOptions holds configuration for HTTP public key fetching.
type fetchOptions struct {
	client   *http.Client
	maxBytes int64
	path     string
}

// FetchOption customizes the behavior of FetchPublicKeyHTTP.
type FetchOption func(*fetchOptions)

// WithHTTPClient sets a custom http.Client (e.g. for custom TLS configuration, proxy, or timeout).
func WithHTTPClient(client *http.Client) FetchOption {
	return func(o *fetchOptions) {
		if client != nil {
			o.client = client
		}
	}
}

// WithMaxBytes configures the maximum response body size in bytes.
func WithMaxBytes(maxBytes int64) FetchOption {
	return func(o *fetchOptions) {
		if maxBytes > 0 {
			o.maxBytes = maxBytes
		}
	}
}

// WithPath overrides the default request path (defaults to "/api/v1/public-key").
func WithPath(path string) FetchOption {
	return func(o *fetchOptions) {
		if path != "" {
			o.path = path
		}
	}
}

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
// It natively supports both the standard RFC 7517 JWKS format and legacy PEM-based JSON formats.
type PublicKeyResponse struct {
	// Standard RFC 7517 JWKS keys
	JWKS JSONWebKeySet `json:"-"`

	// Legacy format fields
	PublicKey string           `json:"public_key,omitempty"`
	Algorithm string           `json:"algorithm,omitempty"`
	Issuer    string           `json:"issuer,omitempty"`
	Audience  string           `json:"audience,omitempty"`
	KeyID     string           `json:"key_id,omitempty"`
	Keys      []PublicKeyEntry `json:"keys,omitempty"`
}

// UnmarshalJSON unmarshals either standard RFC 7517 JWKS or legacy PEM-based key responses.
func (r *PublicKeyResponse) UnmarshalJSON(data []byte) error {
	type alias PublicKeyResponse
	var raw struct {
		alias
		RawKeys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.WrapIf(err, "decode public key response JSON")
	}
	r.PublicKey = raw.PublicKey
	r.Algorithm = raw.Algorithm
	r.Issuer = raw.Issuer
	r.Audience = raw.Audience
	r.KeyID = raw.KeyID

	if len(raw.RawKeys) > 0 {
		var firstMap map[string]any
		_ = json.Unmarshal(raw.RawKeys[0], &firstMap)
		if _, hasKty := firstMap["kty"]; hasKty {
			// RFC 7517 standard JWKS
			var jwksKeys []JSONWebKey
			if err := json.Unmarshal(data, &struct {
				Keys *[]JSONWebKey `json:"keys"`
			}{Keys: &jwksKeys}); err == nil && len(jwksKeys) > 0 {
				r.JWKS.Keys = jwksKeys
				return nil
			}
		}
		// Legacy keys with PEM format
		var legacyKeys []PublicKeyEntry
		if err := json.Unmarshal(data, &struct {
			Keys *[]PublicKeyEntry `json:"keys"`
		}{Keys: &legacyKeys}); err == nil {
			r.Keys = legacyKeys
		}
	}
	return nil
}

// VerificationKeys parses the published keys into a verifier key set.
// It supports RFC 7517 JWKS, a multi-key legacy ring, or degrades to the single PublicKey field.
func (r *PublicKeyResponse) VerificationKeys() (*VerificationKeys, error) {
	if len(r.JWKS.Keys) > 0 {
		return r.JWKS.VerificationKeys()
	}
	if len(r.Keys) == 0 {
		if r.PublicKey == "" {
			return nil, errors.New("public key response contains no verification keys")
		}
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
			return nil, errors.Wrapf(err, "parse published key %s", entry.KeyID)
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
func FetchPublicKeyHTTP(ctx context.Context, iamBaseURL, keyType string, opts ...FetchOption) (*PublicKeyResponse, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(iamBaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("IAM base URL is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.Wrapf(err, "IAM base URL is invalid")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		return nil, errors.New("IAM base URL must include a scheme (https:// or http://)")
	}
	if scheme != "https" && scheme != "http" {
		return nil, errors.Errorf("IAM base URL must use https (or http for local loopback development), got scheme %q", parsed.Scheme)
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, errors.New("IAM base URL host is required")
	}
	if scheme == "http" && !isLoopbackHost(hostname) {
		return nil, errors.Errorf("IAM base URL must use https (or http for local loopback development), got %q", parsed.Scheme)
	}

	defaultClient := &http.Client{
		Timeout: DefaultFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			s := strings.ToLower(req.URL.Scheme)
			if s != "https" && (s != "http" || !isLoopbackHost(req.URL.Hostname())) {
				return errors.Errorf("redirect to insecure scheme/host not allowed: %s", req.URL.String())
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	cfg := fetchOptions{
		client:   defaultClient,
		maxBytes: DefaultFetchMaxBytes,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	reqPath := "/api/v1/public-key"
	if cfg.path != "" {
		reqPath = cfg.path
		if !strings.HasPrefix(reqPath, "/") {
			reqPath = "/" + reqPath
		}
	}

	reqURL := baseURL + reqPath
	if keyType != "" {
		separator := "?"
		if strings.Contains(reqURL, "?") {
			separator = "&"
		}
		reqURL = reqURL + separator + url.Values{"type": []string{keyType}}.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := cfg.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "request IAM public key")
	}
	defer func() { _ = resp.Body.Close() }()

	limitedReader := io.LimitReader(resp.Body, cfg.maxBytes+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, errors.Wrapf(err, "read IAM public key response body")
	}
	if int64(len(body)) > cfg.maxBytes {
		return nil, errors.Errorf("IAM public key response exceeded maximum size of %d bytes", cfg.maxBytes)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("IAM returned status %d: %s", resp.StatusCode, string(body))
	}

	var res PublicKeyResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, errors.Wrapf(err, "decode IAM public key response")
	}

	return &res, nil
}

// FetchJWKSHTTP fetches public keys from an RFC 7517 standard JWKS endpoint (defaults to "/.well-known/jwks.json").
func FetchJWKSHTTP(ctx context.Context, iamBaseURL string, opts ...FetchOption) (*JSONWebKeySet, error) {
	combinedOpts := append([]FetchOption{WithPath("/.well-known/jwks.json")}, opts...)
	res, err := FetchPublicKeyHTTP(ctx, iamBaseURL, "", combinedOpts...)
	if err != nil {
		return nil, err
	}
	if len(res.JWKS.Keys) == 0 {
		return nil, errors.New("response did not contain any valid JWK keys")
	}
	return &res.JWKS, nil
}

// Authenticator provides local JWT public key verification and real-time token version comparison against a TokenVersionStore
type Authenticator struct {
	jwtCfg     JWTConfig
	keys       atomic.Pointer[VerificationKeys]
	tokenStore TokenVersionStore
	logger     *slog.Logger
	refresher  *JWKSRefresher
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
		auth.keys.Store(keys)
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

// SetJWKSRefresher attaches a JWKSRefresher to enable automated key synchronization and on-demand refresh.
func (a *Authenticator) SetJWKSRefresher(refresher *JWKSRefresher) {
	a.refresher = refresher
}

// JWKSRefresher returns the attached JWKSRefresher, if any.
func (a *Authenticator) JWKSRefresher() *JWKSRefresher {
	return a.refresher
}

// StartJWKSAutoRefresh creates and starts a JWKSRefresher, performing an initial fetch and running
// background periodic synchronization.
func (a *Authenticator) StartJWKSAutoRefresh(ctx context.Context, cfg KeyRefreshConfig) (*JWKSRefresher, error) {
	if cfg.Logger == nil && a.logger != nil {
		cfg.Logger = a.logger
	}

	refresher, err := NewJWKSRefresher(a, cfg)
	if err != nil {
		return nil, err
	}
	if err := refresher.FetchNow(ctx); err != nil {
		return nil, errors.Wrapf(err, "initial JWKS fetch failed")
	}
	if err := refresher.Start(ctx); err != nil {
		return nil, err
	}
	return refresher, nil
}

// Close stops the attached JWKSRefresher (if configured) and releases resources.
func (a *Authenticator) Close() error {
	if a.refresher != nil {
		return a.refresher.Close()
	}
	return nil
}

// SetVerificationKeys replaces the verification key set, e.g. after fetching the published ring or
// when a rotation starts. Passing the previous key keeps already-issued tokens valid for the duration
// of the rotation window instead of logging every user out.
func (a *Authenticator) SetVerificationKeys(keys *VerificationKeys) error {
	if keys == nil {
		return errors.New("verification key set must not be nil")
	}
	a.keys.Store(keys)
	return nil
}

// ActiveKeyID returns the key id currently used for verification.
func (a *Authenticator) ActiveKeyID() string {
	keys := a.keys.Load()
	if keys == nil {
		return ""
	}
	return keys.ActiveKeyID()
}

// ParsePublicKey uniformly parses PKCS#1 / PKIX / ECC / Ed25519 public key PEM
func ParsePublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	pub, err := cryptoutil.ParsePublicKeyPEM(pemBytes)
	if err != nil {
		if strings.Contains(err.Error(), "data is not valid PEM format") {
			return nil, errors.New("invalid PEM data")
		}
		if strings.Contains(err.Error(), "unsupported public key PEM type:") {
			return nil, errors.New(strings.Replace(err.Error(), "unsupported public key PEM type:", "unknown public key PEM type:", 1))
		}
		return nil, err
	}

	if rsaKey, ok := pub.(*rsa.PublicKey); ok && rsaKey.N.BitLen() < cryptoutil.MinRSABits {
		return nil, errors.Errorf("RSA public key is too weak: %d bits, at least %d bits required", rsaKey.N.BitLen(), cryptoutil.MinRSABits)
	}

	return pub, nil
}

// ParseAndVerifyToken parses and verifies the JWT signature and claim constraints.
// The checks mirror IAM's own server-side middleware (algorithm pinning, issuer, audience, expiry
// required, token type and payload) so a consumer cannot accept a token the issuer would reject.
func (a *Authenticator) ParseAndVerifyToken(tokenString string) (*JwtClaims, error) {
	return a.ParseAndVerifyTokenContext(context.Background(), tokenString)
}

// ParseAndVerifyTokenContext parses and verifies the JWT signature and claim constraints with context awareness.
// If key refresh is required (via JWKSRefresher), the provided ctx is passed to FetchOnDemand to honor
// timeouts and cancellations.
func (a *Authenticator) ParseAndVerifyTokenContext(ctx context.Context, tokenString string) (*JwtClaims, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, wrapAuthError(ErrTokenInvalid, err, "token verification aborted by context")
	}
	if strings.TrimSpace(tokenString) == "" {
		return nil, wrapAuthError(ErrTokenEmpty, nil, "token must not be empty")
	}
	keys := a.keys.Load()
	if a.jwtCfg.method == nil || keys == nil {
		if a.refresher != nil && a.jwtCfg.method != nil {
			// Verification keys not loaded yet, attempt on-demand fetch
			refreshed, rErr := a.refresher.FetchOnDemand(ctx)
			if refreshed && rErr == nil {
				keys = a.keys.Load()
			}
		}
		if a.jwtCfg.method == nil || keys == nil {
			return nil, wrapAuthError(ErrAuthConfigInvalid, nil, "authenticator is not configured with a signing method and verification key")
		}
	}

	claims := &JwtClaims{}
	parseOpts := []jwt.ParserOption{
		// Without this the library treats a missing exp as "valid forever", so a token signed
		// without an expiry would be accepted indefinitely.
		jwt.WithExpirationRequired(),
	}
	if a.jwtCfg.leeway > 0 {
		parseOpts = append(parseOpts, jwt.WithLeeway(a.jwtCfg.leeway))
	}

	token, err := ParseWithKeyRing(tokenString, claims, keys, a.jwtCfg.method.Alg(),
		a.jwtCfg.issuer, a.jwtCfg.audience,
		parseOpts...,
	)

	// If initial verification failed due to unknown key id or signature failure on legacy/unrecognized key,
	// and a JWKSRefresher is attached, attempt a rate-limited on-demand refresh and retry once.
	if (err != nil || token == nil || !token.Valid) && a.refresher != nil {
		if shouldTriggerKeyRefresh(err, token, keys) {
			refreshed, rErr := a.refresher.FetchOnDemand(ctx)
			if refreshed && rErr == nil {
				if updatedKeys := a.keys.Load(); updatedKeys != nil {
					*claims = JwtClaims{}
					token, err = ParseWithKeyRing(tokenString, claims, updatedKeys, a.jwtCfg.method.Alg(),
						a.jwtCfg.issuer, a.jwtCfg.audience,
						parseOpts...,
					)
				}
			}
		}
	}

	if err != nil || token == nil || !token.Valid {
		sentinel := classifyJWTError(err)
		return nil, wrapAuthError(sentinel, err, "invalid token")
	}

	if claims.Type != TokenTypeAccess {
		return nil, wrapAuthError(ErrTokenTypeMismatch, nil, "token type must be access", "actual_type", claims.Type)
	}

	if claims.UserID == 0 || claims.Username == "" || claims.ID == "" {
		return nil, wrapAuthError(ErrTokenClaimsInvalid, nil, "token missing required uid, un or jti claims", "uid", claims.UserID, "un", claims.Username, "jti", claims.ID)
	}
	expectedSub := strconv.FormatUint(claims.UserID, 10)
	if claims.Subject == "" || claims.Subject != expectedSub {
		return nil, wrapAuthError(ErrTokenClaimsInvalid, nil, "token subject does not match user id", "subject", claims.Subject, "user_id", claims.UserID)
	}
	if claims.ExpiresAt == nil {
		return nil, wrapAuthError(ErrTokenClaimsInvalid, nil, "token is missing the exp claim")
	}

	return claims, nil
}

// shouldTriggerKeyRefresh reports whether the verification failure indicates that verification keys
// may have been rotated on IAM and should be refreshed on demand.
// It returns true if the token presented an unknown kid or if a legacy token without kid failed signature verification.
// It returns false if the error is unrelated to key rotation (expired, malformed) or if the signature failed
// on a key whose kid is already present in the local key ring (which indicates a forged or corrupt token).
func shouldTriggerKeyRefresh(err error, token *jwt.Token, keys *VerificationKeys) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "unknown key id") {
		return true
	}
	if !isSignatureFailure(err) {
		return false
	}
	// For signature failures:
	// If the token explicitly specified a kid that is already present in our key ring,
	// the key is already known and immutable. A signature failure is a genuine bad signature /
	// tampering, not a missing key. Refreshing from IAM will not change the public key for this kid.
	if token != nil {
		if kid, ok := token.Header["kid"].(string); ok && kid != "" {
			if keys != nil && keys.HasKey(kid) {
				return false
			}
		}
	}
	// If the token has no kid (legacy token), refreshing keys may pick up the newly
	// rotated active key from IAM.
	return true
}

// VerifyTokenVersion checks the user's real-time token_version against the configured TokenVersionStore
// to prevent the use of revoked tokens.
// It is fail-closed: when the store is not configured, unreachable, or the version key is missing
// (cache eviction, restart, or no login yet), the token is rejected instead of being trusted.
// Callers should treat the error as "re-authenticate required"; a valid refresh token repopulates the cache.
func (a *Authenticator) VerifyTokenVersion(ctx context.Context, claims *JwtClaims) error {
	if claims == nil {
		return wrapAuthError(ErrTokenClaimsInvalid, nil, "claims must not be nil")
	}
	if a.tokenStore == nil {
		return wrapAuthError(ErrTokenVersionUnavailable, ErrAuthConfigInvalid, "token version check unavailable: token store is not configured")
	}

	var ver uint64
	var familyRevoked bool
	var familyChecked bool

	// Batch optimization when familyID is present and store implements BatchRevocationStore
	if claims.FamilyID != "" {
		if batchStore, ok := a.tokenStore.(BatchRevocationStore); ok {
			var bErr error
			ver, familyRevoked, bErr = batchStore.GetTokenAndFamilyRevocation(ctx, claims.UserID, claims.FamilyID)
			if bErr != nil {
				if errors.Is(bErr, ErrTokenVersionNotFound) {
					return wrapAuthError(ErrTokenVersionUnavailable, bErr, fmt.Sprintf("token version unavailable for user %d", claims.UserID), "user_id", claims.UserID)
				}
				return wrapAuthError(ErrTokenVersionUnavailable, bErr, "failed to query token version", "user_id", claims.UserID)
			}
			familyChecked = true
		}
	}

	if !familyChecked {
		var err error
		ver, err = a.tokenStore.GetTokenVersion(ctx, claims.UserID)
		if err != nil {
			if errors.Is(err, ErrTokenVersionNotFound) {
				// A missing key means the revocation baseline cannot be verified. Reject rather than
				// accepting tv=0: eviction or a restart without persistence would otherwise
				// revive already-revoked tokens.
				return wrapAuthError(ErrTokenVersionUnavailable, err, fmt.Sprintf("token version unavailable for user %d", claims.UserID), "user_id", claims.UserID)
			}
			return wrapAuthError(ErrTokenVersionUnavailable, err, "failed to query token version", "user_id", claims.UserID)
		}
	}

	if ver != claims.TokenVersion {
		return wrapAuthError(ErrTokenRevoked, nil, fmt.Sprintf("token revoked (server version: %d, token version: %d)", ver, claims.TokenVersion),
			"user_id", claims.UserID,
			"server_version", ver,
			"token_version", claims.TokenVersion,
		)
	}

	// Session family revocation check (single-device/session kick-out)
	if claims.FamilyID != "" {
		if !familyChecked {
			if famStore, ok := a.tokenStore.(FamilyRevocationStore); ok {
				revoked, fErr := famStore.IsFamilyRevoked(ctx, claims.FamilyID)
				if fErr != nil {
					return wrapAuthError(ErrTokenVersionUnavailable, fErr, "failed to query family revocation status", "family_id", claims.FamilyID)
				}
				familyRevoked = revoked
			}
		}
		if familyRevoked {
			return wrapAuthError(ErrTokenFamilyRevoked, nil, fmt.Sprintf("session family %s has been revoked", claims.FamilyID),
				"user_id", claims.UserID,
				"family_id", claims.FamilyID,
			)
		}
	}

	return nil
}

// VerifyFamilyID checks whether the given session family ID is revoked against the configured store.
func (a *Authenticator) VerifyFamilyID(ctx context.Context, familyID string) error {
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		return nil
	}
	if a.tokenStore == nil {
		return wrapAuthError(ErrTokenVersionUnavailable, ErrAuthConfigInvalid, "token version check unavailable: token store is not configured")
	}
	famStore, ok := a.tokenStore.(FamilyRevocationStore)
	if !ok {
		return nil
	}
	revoked, err := famStore.IsFamilyRevoked(ctx, familyID)
	if err != nil {
		return wrapAuthError(ErrTokenVersionUnavailable, err, "failed to query family revocation status", "family_id", familyID)
	}
	if revoked {
		return wrapAuthError(ErrTokenFamilyRevoked, nil, fmt.Sprintf("session family %s has been revoked", familyID), "family_id", familyID)
	}
	return nil
}
