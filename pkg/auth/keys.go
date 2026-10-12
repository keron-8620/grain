// Package auth exposes the JWT keys of IAM in a form both IAM and its consumers can compute,
// so a key rotation can be performed with an overlap window instead of invalidating every token.
package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// KeyID derives a stable, non-secret identifier for a public key: the first 16 hex characters of the
// SHA-256 over its PKIX DER encoding. Both issuer and verifiers compute it from the same key, so a
// token's `kid` header can be matched against a configured key without any out-of-band mapping.
func KeyID(pub crypto.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("public key must not be nil")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to encode public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16], nil
}

// PublicKeyEntry is one key of the IAM key ring, as published to consumers.
type PublicKeyEntry struct {
	// KeyID matches the `kid` header of the tokens the key signs.
	KeyID string `json:"key_id"`
	// PublicKey is the PEM-encoded public key.
	PublicKey string `json:"public_key"`
	// Algorithm is the JWS algorithm the key is used with (e.g. ES256).
	Algorithm string `json:"algorithm"`
	// Active reports whether IAM is still signing with this key. During a rotation window both the
	// new (active) and the previous (verification-only) key are published.
	Active bool `json:"active"`
}

// VerificationKeys is a key ring a verifier can select from by `kid`.
type VerificationKeys struct {
	active   crypto.PublicKey
	previous crypto.PublicKey
	activeID string
	prevID   string
}

// NewVerificationKeys builds a key ring. previous may be nil when no rotation is in progress.
func NewVerificationKeys(active, previous crypto.PublicKey) (*VerificationKeys, error) {
	if active == nil {
		return nil, fmt.Errorf("active public key must not be nil")
	}
	activeID, err := KeyID(active)
	if err != nil {
		return nil, err
	}
	ring := &VerificationKeys{active: active, previous: previous, activeID: activeID}
	if previous != nil {
		prevID, err := KeyID(previous)
		if err != nil {
			return nil, err
		}
		if prevID == activeID {
			// Same key configured twice: treat it as a single key.
			ring.previous = nil
		} else {
			ring.prevID = prevID
		}
	}
	return ring, nil
}

// ActiveKeyID returns the `kid` of the key IAM signs new tokens with.
func (r *VerificationKeys) ActiveKeyID() string { return r.activeID }

// PreviousKeyID returns the `kid` of the verification-only key (empty when absent).
func (r *VerificationKeys) PreviousKeyID() string { return r.prevID }

// HasPrevious reports whether a rotation window is open.
func (r *VerificationKeys) HasPrevious() bool { return r.previous != nil }

// Resolve returns the key a token with the given `kid` must be verified against.
// An empty kid (tokens issued before kid support) resolves to the active key; the caller is expected
// to retry with ActiveFallback when the signature does not match.
func (r *VerificationKeys) Resolve(kid string) (crypto.PublicKey, error) {
	switch {
	case kid == "" || kid == r.activeID:
		return r.active, nil
	case r.prevID != "" && kid == r.prevID:
		return r.previous, nil
	default:
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
}

// PublicKeys renders the ring for publication, active key first.
func (r *VerificationKeys) PublicKeys(accessAlgorithm string) ([]PublicKeyEntry, error) {
	entries := make([]PublicKeyEntry, 0, 2)
	active, err := publicKeyEntry(r.active, r.activeID, accessAlgorithm, true)
	if err != nil {
		return nil, err
	}
	entries = append(entries, active)
	if r.previous != nil {
		previous, err := publicKeyEntry(r.previous, r.prevID, accessAlgorithm, false)
		if err != nil {
			return nil, err
		}
		entries = append(entries, previous)
	}
	return entries, nil
}

func publicKeyEntry(pub crypto.PublicKey, kid, algorithm string, active bool) (PublicKeyEntry, error) {
	pemBytes, err := MarshalPublicKeyPEM(pub)
	if err != nil {
		return PublicKeyEntry{}, err
	}
	return PublicKeyEntry{
		KeyID:     kid,
		PublicKey: string(pemBytes),
		Algorithm: algorithm,
		Active:    active,
	}, nil
}

// ParseWithKeyRing verifies a token, selecting the key by its `kid` header. A token without a kid
// (issued before key identifiers existed) is first verified with the active key and, when that fails
// on the signature, retried with the previous key — that is what makes a rotation window transparent
// for clients that received their token before the rotation.
func ParseWithKeyRing(tokenString string, claims jwt.Claims, keys *VerificationKeys, alg, issuer, audience string, extraOptions ...jwt.ParserOption) (*jwt.Token, error) {
	if keys == nil {
		return nil, fmt.Errorf("verification key ring must not be nil")
	}
	options := append([]jwt.ParserOption{
		jwt.WithValidMethods([]string{alg}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
	}, extraOptions...)

	keyFunc := func(t *jwt.Token) (any, error) {
		if t.Method == nil {
			return nil, fmt.Errorf("token has no signing method")
		}
		if t.Method.Alg() != alg {
			return nil, fmt.Errorf("signing algorithm mismatch: %s != %s", t.Method.Alg(), alg)
		}
		kid, _ := t.Header["kid"].(string)
		return keys.Resolve(kid)
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, options...)
	if err == nil && token.Valid {
		return token, nil
	}
	if !isSignatureFailure(err) || !keys.HasPrevious() {
		return token, err
	}
	if kid, _ := token.Header["kid"].(string); kid != "" {
		return token, err
	}
	return jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
		return keys.Resolve(keys.PreviousKeyID())
	}, options...)
}

// isSignatureFailure reports whether a parse failure was a signature mismatch (as opposed to an
// expired or malformed token, which must never be retried with another key).
func isSignatureFailure(err error) bool {
	if err == nil {
		return false
	}
	return stderrors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		stderrors.Is(err, jwt.ErrSignatureInvalid) ||
		strings.Contains(err.Error(), "signature is invalid")
}

// MarshalPublicKeyPEM encodes a public key as PEM (PKIX).
func MarshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key must not be nil")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// AlgorithmForPublicKey reports the JWS algorithm matching a key type, used when a consumer needs to
// know what a published key can verify.
func AlgorithmForPublicKey(pub crypto.PublicKey) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		return "ES256"
	case ed25519.PublicKey:
		return "EdDSA"
	default:
		return ""
	}
}
