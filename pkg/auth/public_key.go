// Package auth exposes the JWT keys of IAM in a form both IAM and its consumers can compute,
// so a key rotation can be performed with an overlap window instead of invalidating every token.
package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/big"
	"strings"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"
	"grain/pkg/cryptoutil"
)

// KeyID derives a stable, non-secret identifier for a public key: the first 16 hex characters of the
// SHA-256 over its PKIX DER encoding. Both issuer and verifiers compute it from the same key, so a
// token's `kid` header can be matched against a configured key without any out-of-band mapping.
func KeyID(pub crypto.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("public key must not be nil")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", errors.Wrapf(err, "failed to encode public key")
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16], nil
}

// JSONWebKey represents a public JSON Web Key (JWK) conforming to RFC 7517, RFC 7518, and RFC 8037.
type JSONWebKey struct {
	Kty string `json:"kty"`           // Key Type: "RSA", "EC", "OKP"
	Use string `json:"use,omitempty"` // Public Key Use: "sig"
	Alg string `json:"alg,omitempty"` // Algorithm: "RS256", "ES256", "EdDSA", etc.
	Kid string `json:"kid,omitempty"` // Key ID

	// EC parameters (RFC 7518 Section 6.2)
	Crv string `json:"crv,omitempty"` // Curve: "P-256", "P-384", "P-521"
	X   string `json:"x,omitempty"`   // X coordinate (EC) or public key bytes (OKP)
	Y   string `json:"y,omitempty"`   // Y coordinate (EC)

	// RSA parameters (RFC 7518 Section 6.3)
	N string `json:"n,omitempty"` // Modulus (base64url unpadded)
	E string `json:"e,omitempty"` // Exponent (base64url unpadded)

	// Extension parameter (RFC 7517 Section 4 allows extension members)
	Active *bool `json:"active,omitempty"` // True for current signing key, false for previous verification-only key
}

// JWK is a type alias for JSONWebKey.
type JWK = JSONWebKey

// JSONWebKeySet represents a set of JSON Web Keys conforming to RFC 7517.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JWKS is a type alias for JSONWebKeySet.
type JWKS = JSONWebKeySet

// decodeBase64URL decodes a base64url-encoded string (with or without padding).
func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// PublicKeyToJWK converts a standard crypto.PublicKey into an RFC 7517 JSONWebKey.
func PublicKeyToJWK(pub crypto.PublicKey, kid, alg string) (*JSONWebKey, error) {
	if pub == nil {
		return nil, errors.New("public key must not be nil")
	}
	if kid == "" {
		var err error
		kid, err = KeyID(pub)
		if err != nil {
			return nil, err
		}
	}
	if alg == "" {
		alg = AlgorithmForPublicKey(pub)
	}

	switch k := pub.(type) {
	case *rsa.PublicKey:
		nStr := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
		return &JSONWebKey{
			Kty: "RSA",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			N:   nStr,
			E:   eStr,
		}, nil

	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil || k.Curve.Params() == nil {
			return nil, errors.New("invalid ecdsa public key")
		}
		raw, err := k.Bytes()
		if err != nil {
			return nil, errors.Wrapf(err, "encode ecdsa public key")
		}
		byteLen := (len(raw) - 1) / 2
		xStr := base64.RawURLEncoding.EncodeToString(raw[1 : 1+byteLen])
		yStr := base64.RawURLEncoding.EncodeToString(raw[1+byteLen:])
		return &JSONWebKey{
			Kty: "EC",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			Crv: k.Curve.Params().Name,
			X:   xStr,
			Y:   yStr,
		}, nil

	case ed25519.PublicKey:
		xStr := base64.RawURLEncoding.EncodeToString(k)
		return &JSONWebKey{
			Kty: "OKP",
			Use: "sig",
			Alg: alg,
			Kid: kid,
			Crv: "Ed25519",
			X:   xStr,
		}, nil

	default:
		return nil, errors.Errorf("unsupported public key type: %T", pub)
	}
}

// JWKToPublicKey converts an RFC 7517 JSONWebKey back to a standard crypto.PublicKey.
func JWKToPublicKey(jwk *JSONWebKey) (crypto.PublicKey, error) {
	if jwk == nil {
		return nil, errors.New("JWK must not be nil")
	}
	switch jwk.Kty {
	case "RSA":
		nBytes, err := decodeBase64URL(jwk.N)
		if err != nil {
			return nil, errors.Wrapf(err, "decode RSA modulus n")
		}
		if len(nBytes) == 0 {
			return nil, errors.New("invalid RSA modulus n: must not be empty")
		}
		eBytes, err := decodeBase64URL(jwk.E)
		if err != nil {
			return nil, errors.Wrapf(err, "decode RSA exponent e")
		}
		if len(eBytes) == 0 {
			return nil, errors.New("invalid RSA exponent e: must not be empty")
		}
		if len(eBytes) > 4 {
			return nil, errors.Errorf("invalid RSA exponent e: length %d bytes exceeds maximum of 4 bytes", len(eBytes))
		}
		eInt := 0
		for _, b := range eBytes {
			eInt = (eInt << 8) | int(b)
		}
		if eInt < 2 {
			return nil, errors.Errorf("invalid RSA exponent e: value %d must be at least 2", eInt)
		}
		n := new(big.Int).SetBytes(nBytes)
		if n.BitLen() < minRSABits {
			return nil, errors.Errorf("RSA modulus n is too weak: %d bits, at least %d bits required", n.BitLen(), minRSABits)
		}
		return &rsa.PublicKey{N: n, E: eInt}, nil

	case "EC":
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.Errorf("unsupported elliptic curve: %q", jwk.Crv)
		}
		xBytes, err := decodeBase64URL(jwk.X)
		if err != nil {
			return nil, errors.Wrapf(err, "decode EC x coordinate")
		}
		yBytes, err := decodeBase64URL(jwk.Y)
		if err != nil {
			return nil, errors.Wrapf(err, "decode EC y coordinate")
		}
		byteLen := (curve.Params().BitSize + 7) / 8
		if len(xBytes) > byteLen || len(yBytes) > byteLen {
			return nil, errors.Errorf("EC point is not on curve %s", jwk.Crv)
		}
		uncompressed := make([]byte, 1+2*byteLen)
		uncompressed[0] = 0x04
		copy(uncompressed[1+byteLen-len(xBytes):1+byteLen], xBytes)
		copy(uncompressed[1+2*byteLen-len(yBytes):], yBytes)
		pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
		if err != nil {
			return nil, errors.Errorf("EC point is not on curve %s", jwk.Crv)
		}
		return pubKey, nil

	case "OKP":
		if jwk.Crv != "Ed25519" {
			return nil, errors.Errorf("unsupported OKP curve: %q", jwk.Crv)
		}
		xBytes, err := decodeBase64URL(jwk.X)
		if err != nil {
			return nil, errors.Wrapf(err, "decode OKP public key")
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, errors.Errorf("invalid Ed25519 public key length: got %d, expected %d", len(xBytes), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(xBytes), nil

	default:
		return nil, errors.Errorf("unsupported JWK key type (kty): %q", jwk.Kty)
	}
}

// PublicKeyEntry is one key of the legacy IAM key ring, as published to consumers.
// Deprecated: use JSONWebKey / JWK instead.
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
	byID     map[string]crypto.PublicKey
}

// NewVerificationKeys builds a key ring. previous may be nil when no rotation is in progress.
func NewVerificationKeys(active, previous crypto.PublicKey) (*VerificationKeys, error) {
	if active == nil {
		return nil, errors.New("active public key must not be nil")
	}
	activeID, err := KeyID(active)
	if err != nil {
		return nil, err
	}
	ring := &VerificationKeys{
		active:   active,
		previous: previous,
		activeID: activeID,
		byID:     make(map[string]crypto.PublicKey),
	}
	ring.byID[activeID] = active
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
			ring.byID[prevID] = previous
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

// HasKey reports whether the key ring contains a verification key for the given kid.
func (r *VerificationKeys) HasKey(kid string) bool {
	if r == nil {
		return false
	}
	switch {
	case kid == "" || kid == r.activeID:
		return r.active != nil
	case r.prevID != "" && kid == r.prevID:
		return r.previous != nil
	default:
		if r.byID != nil {
			pub, ok := r.byID[kid]
			return ok && pub != nil
		}
		return false
	}
}

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
		if r.byID != nil {
			if pub, ok := r.byID[kid]; ok {
				return pub, nil
			}
		}
		return nil, errors.Errorf("unknown key id %q", kid)
	}
}

// JWKS renders the ring for publication as a standard RFC 7517 JSON Web Key Set.
func (r *VerificationKeys) JWKS(accessAlgorithm string) (*JSONWebKeySet, error) {
	keys := make([]JSONWebKey, 0, 2)
	activeJWK, err := PublicKeyToJWK(r.active, r.activeID, accessAlgorithm)
	if err != nil {
		return nil, err
	}
	t := true
	activeJWK.Active = &t
	keys = append(keys, *activeJWK)

	if r.previous != nil {
		prevJWK, err := PublicKeyToJWK(r.previous, r.prevID, accessAlgorithm)
		if err != nil {
			return nil, err
		}
		f := false
		prevJWK.Active = &f
		keys = append(keys, *prevJWK)
	}
	return &JSONWebKeySet{Keys: keys}, nil
}

// VerificationKeys parses the published JWKS into a verifier key set.
func (jwks *JSONWebKeySet) VerificationKeys() (*VerificationKeys, error) {
	if len(jwks.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}
	var active, previous crypto.PublicKey
	var activeID, prevID string
	byID := make(map[string]crypto.PublicKey, len(jwks.Keys))

	for _, jwk := range jwks.Keys {
		pub, err := JWKToPublicKey(&jwk)
		if err != nil {
			return nil, errors.Wrapf(err, "parse JWK key_id=%s", jwk.Kid)
		}
		kid := jwk.Kid
		if kid == "" {
			var kErr error
			kid, kErr = KeyID(pub)
			if kErr != nil {
				return nil, kErr
			}
		}
		byID[kid] = pub

		if jwk.Active != nil {
			if *jwk.Active {
				active = pub
				activeID = kid
			} else {
				previous = pub
				prevID = kid
			}
		}
	}

	if active == nil {
		firstJWK := jwks.Keys[0]
		active = byID[firstJWK.Kid]
		if active == nil {
			active, _ = JWKToPublicKey(&firstJWK)
		}
		activeID = firstJWK.Kid
		if len(jwks.Keys) > 1 && previous == nil {
			secondJWK := jwks.Keys[1]
			previous = byID[secondJWK.Kid]
			prevID = secondJWK.Kid
		}
	}

	vk, err := NewVerificationKeys(active, previous)
	if err != nil {
		return nil, err
	}
	maps.Copy(vk.byID, byID)
	if activeID != "" {
		vk.activeID = activeID
	}
	if prevID != "" {
		vk.prevID = prevID
	}
	return vk, nil
}

// ParseJWKS parses raw JSON bytes representing an RFC 7517 JWKS into a VerificationKeys key ring.
func ParseJWKS(data []byte) (*VerificationKeys, error) {
	var jwks JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, errors.WrapIf(err, "decode JWKS JSON")
	}
	return jwks.VerificationKeys()
}

// PublicKeys renders the ring for legacy publication, active key first.
// Deprecated: use JWKS instead.
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
		return nil, errors.New("verification key ring must not be nil")
	}
	options := append([]jwt.ParserOption{
		jwt.WithValidMethods([]string{alg}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
	}, extraOptions...)

	keyFunc := func(t *jwt.Token) (any, error) {
		if t.Method == nil {
			return nil, errors.New("token has no signing method")
		}
		if t.Method.Alg() != alg {
			return nil, errors.Errorf("signing algorithm mismatch: %s != %s", t.Method.Alg(), alg)
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
	return errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrSignatureInvalid) ||
		strings.Contains(err.Error(), "signature is invalid")
}

// MarshalPublicKeyPEM encodes a public key as PEM (PKIX).
func MarshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	return cryptoutil.MarshalPublicKeyPKIXPEM(pub)
}

// AlgorithmForPublicKey reports the JWS algorithm matching a key type, used when a consumer needs to
// know what a published key can verify.
func AlgorithmForPublicKey(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil || k.Curve.Params() == nil {
			return ""
		}
		switch k.Curve.Params().Name {
		case "P-256":
			return "ES256"
		case "P-384":
			return "ES384"
		case "P-521":
			return "ES512"
		default:
			switch k.Curve.Params().BitSize {
			case 256:
				return "ES256"
			case 384:
				return "ES384"
			case 521:
				return "ES512"
			default:
				return ""
			}
		}
	case ed25519.PublicKey:
		return "EdDSA"
	default:
		return ""
	}
}
