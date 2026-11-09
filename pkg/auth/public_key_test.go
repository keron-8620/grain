package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlgorithmForPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	assert.Equal(t, "RS256", AlgorithmForPublicKey(&rsaKey.PublicKey))

	ecKey256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, "ES256", AlgorithmForPublicKey(&ecKey256.PublicKey))

	ecKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, "ES384", AlgorithmForPublicKey(&ecKey384.PublicKey))

	ecKey521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, "ES512", AlgorithmForPublicKey(&ecKey521.PublicKey))

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", AlgorithmForPublicKey(edPub))

	assert.Equal(t, "", AlgorithmForPublicKey("not-a-key"))
	assert.Equal(t, "", AlgorithmForPublicKey(nil))
	assert.Equal(t, "", AlgorithmForPublicKey(&ecdsa.PublicKey{}))
}

func TestMarshalPublicKeyPEM(t *testing.T) {
	_, err := MarshalPublicKeyPEM(nil)
	assert.Error(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes, err := MarshalPublicKeyPEM(&rsaKey.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, string(pemBytes), "-----BEGIN PUBLIC KEY-----")
}

func TestVerificationKeys_PublicKeys(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ring, err := NewVerificationKeys(&rsaKey1.PublicKey, &rsaKey2.PublicKey)
	require.NoError(t, err)

	entries, err := ring.PublicKeys("RS256")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.True(t, entries[0].Active)
	assert.False(t, entries[1].Active)
}

func TestPublicKeyToJWK_RoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		gen  func(t *testing.T) crypto.PublicKey
	}{
		{
			name: "RSA-2048",
			gen: func(t *testing.T) crypto.PublicKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return &k.PublicKey
			},
		},
		{
			name: "ECDSA-P256",
			gen: func(t *testing.T) crypto.PublicKey {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &k.PublicKey
			},
		},
		{
			name: "ECDSA-P384",
			gen: func(t *testing.T) crypto.PublicKey {
				k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return &k.PublicKey
			},
		},
		{
			name: "ECDSA-P521",
			gen: func(t *testing.T) crypto.PublicKey {
				k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return &k.PublicKey
			},
		},
		{
			name: "Ed25519",
			gen: func(t *testing.T) crypto.PublicKey {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return pub
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			origPub := tc.gen(t)

			jwk, err := PublicKeyToJWK(origPub, "", "")
			require.NoError(t, err)
			assert.NotEmpty(t, jwk.Kty)
			assert.NotEmpty(t, jwk.Kid)
			assert.NotEmpty(t, jwk.Alg)

			// JSON marshal & unmarshal
			data, err := json.Marshal(jwk)
			require.NoError(t, err)

			var decodedJWK JSONWebKey
			err = json.Unmarshal(data, &decodedJWK)
			require.NoError(t, err)

			parsedPub, err := JWKToPublicKey(&decodedJWK)
			require.NoError(t, err)

			assert.Equal(t, origPub, parsedPub)
		})
	}

	t.Run("invalid inputs", func(t *testing.T) {
		_, err := PublicKeyToJWK(nil, "", "")
		assert.Error(t, err)

		_, err = JWKToPublicKey(nil)
		assert.Error(t, err)

		_, err = JWKToPublicKey(&JSONWebKey{Kty: "UNKNOWN"})
		assert.Error(t, err)

		_, err = JWKToPublicKey(&JSONWebKey{Kty: "EC", Crv: "UNKNOWN_CURVE"})
		assert.Error(t, err)

		_, err = JWKToPublicKey(&JSONWebKey{Kty: "OKP", Crv: "Ed448"})
		assert.Error(t, err)

		// RSA invalid modulus and exponents
		_, err = JWKToPublicKey(&JSONWebKey{Kty: "RSA", N: "", E: "AQAB"})
		assert.ErrorContains(t, err, "modulus n: must not be empty")

		_, err = JWKToPublicKey(&JSONWebKey{Kty: "RSA", N: "AQAB", E: ""})
		assert.ErrorContains(t, err, "exponent e: must not be empty")

		// Exponent exceeds 4 bytes (5 bytes)
		oversizedE := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4, 5})
		_, err = JWKToPublicKey(&JSONWebKey{Kty: "RSA", N: "AQAB", E: oversizedE})
		assert.ErrorContains(t, err, "exceeds maximum of 4 bytes")

		// Exponent value < 2 (0 and 1)
		zeroE := base64.RawURLEncoding.EncodeToString([]byte{0})
		_, err = JWKToPublicKey(&JSONWebKey{Kty: "RSA", N: "AQAB", E: zeroE})
		assert.ErrorContains(t, err, "must be at least 2")

		oneE := base64.RawURLEncoding.EncodeToString([]byte{1})
		_, err = JWKToPublicKey(&JSONWebKey{Kty: "RSA", N: "AQAB", E: oneE})
		assert.ErrorContains(t, err, "must be at least 2")

		// RSA modulus < 2048 bits rejected
		weakRSAKey, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		weakJWK, err := PublicKeyToJWK(&weakRSAKey.PublicKey, "", "RS256")
		require.NoError(t, err)
		_, err = JWKToPublicKey(weakJWK)
		assert.ErrorContains(t, err, "RSA modulus n is too weak: 1024 bits, at least 2048 bits required")
	})
}

func TestVerificationKeys_JWKS(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ring, err := NewVerificationKeys(&rsaKey1.PublicKey, &rsaKey2.PublicKey)
	require.NoError(t, err)

	jwks, err := ring.JWKS("RS256")
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 2)
	require.NotNil(t, jwks.Keys[0].Active)
	assert.True(t, *jwks.Keys[0].Active)
	require.NotNil(t, jwks.Keys[1].Active)
	assert.False(t, *jwks.Keys[1].Active)

	// Roundtrip: VerificationKeys from JWKS
	parsedRing, err := jwks.VerificationKeys()
	require.NoError(t, err)
	assert.Equal(t, ring.ActiveKeyID(), parsedRing.ActiveKeyID())
	assert.Equal(t, ring.PreviousKeyID(), parsedRing.PreviousKeyID())
	assert.True(t, parsedRing.HasPrevious())

	// Test ParseJWKS directly from JSON
	rawJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	parsedFromJSON, err := ParseJWKS(rawJSON)
	require.NoError(t, err)
	assert.Equal(t, ring.ActiveKeyID(), parsedFromJSON.ActiveKeyID())

	// Sign a token with active key and verify using parsed ring
	claims := &JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-aud"},
			ID:        "jti-1",
			Subject:   "1",
		},
		UserInfo: UserInfo{
			UserID:   1,
			Username: "alice",
		},
		Type: TokenTypeAccess,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = ring.ActiveKeyID()
	tokenStr, err := token.SignedString(rsaKey1)
	require.NoError(t, err)

	verifiedToken, err := ParseWithKeyRing(tokenStr, &JwtClaims{}, parsedFromJSON, "RS256", "test-issuer", "test-aud")
	require.NoError(t, err)
	assert.True(t, verifiedToken.Valid)
}

func TestVerificationKeys_HasKey(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ring, err := NewVerificationKeys(&rsaKey1.PublicKey, &rsaKey2.PublicKey)
	require.NoError(t, err)

	assert.True(t, ring.HasKey(ring.ActiveKeyID()), "should have active key ID")
	assert.True(t, ring.HasKey(ring.PreviousKeyID()), "should have previous key ID")
	assert.True(t, ring.HasKey(""), "empty kid resolves to active key and should return true")
	assert.False(t, ring.HasKey("unknown-kid"), "unknown kid should return false")

	var nilRing *VerificationKeys
	assert.False(t, nilRing.HasKey("any-kid"), "nil ring should return false")

	singleRing, err := NewVerificationKeys(&rsaKey1.PublicKey, nil)
	require.NoError(t, err)
	assert.True(t, singleRing.HasKey(singleRing.ActiveKeyID()))
	assert.False(t, singleRing.HasKey("unknown-kid"))
}
