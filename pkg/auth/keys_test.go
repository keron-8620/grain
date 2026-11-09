package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMinRSABitsConstant(t *testing.T) {
	assert.Equal(t, 2048, MinRSABits)
	assert.Equal(t, 2048, minRSABits)
}

func TestLoadPublicKey_InlinePEM(t *testing.T) {
	t.Run("RSA PKIX public key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)
		pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

		pub, err := LoadPublicKey(pemStr)
		require.NoError(t, err)
		rsaPub, ok := pub.(*rsa.PublicKey)
		require.True(t, ok)
		assert.True(t, key.PublicKey.Equal(rsaPub))
	})

	t.Run("RSA PKCS1 public key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		der := x509.MarshalPKCS1PublicKey(&key.PublicKey)
		pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))

		pub, err := LoadPublicKey(pemStr)
		require.NoError(t, err)
		rsaPub, ok := pub.(*rsa.PublicKey)
		require.True(t, ok)
		assert.True(t, key.PublicKey.Equal(rsaPub))
	})

	t.Run("ECDSA PKIX public key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)
		pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

		pub, err := LoadPublicKey(pemStr)
		require.NoError(t, err)
		ecPub, ok := pub.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.True(t, key.PublicKey.Equal(ecPub))
	})

	t.Run("Ed25519 PKIX public key", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalPKIXPublicKey(pubKey)
		require.NoError(t, err)
		pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

		pub, err := LoadPublicKey(pemStr)
		require.NoError(t, err)
		edPub, ok := pub.(ed25519.PublicKey)
		require.True(t, ok)
		assert.True(t, pubKey.Equal(edPub))
	})
}

func TestLoadPublicKey_FromFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	tmpFile := filepath.Join(t.TempDir(), "pubkey.pem")
	require.NoError(t, os.WriteFile(tmpFile, pemBytes, 0o600))

	pub, err := LoadPublicKey(tmpFile)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.True(t, key.PublicKey.Equal(rsaPub))
}

func TestLoadPublicKeyRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"invalid pem", "not-a-pem"},
		{"unknown file", "/path/that/does/not/exist.pem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadPublicKey(tc.in)
			assert.Error(t, err)
		})
	}

	t.Run("invalid file content", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "corrupt.pem")
		require.NoError(t, os.WriteFile(tmpFile, []byte("bad content not pem"), 0o600))
		_, err := LoadPublicKey(tmpFile)
		assert.Error(t, err)
	})
}

func TestLoadPublicKeyRejectsWeakRSA(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&weakKey.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	_, err = LoadPublicKey(string(pemBytes))
	assert.ErrorContains(t, err, "RSA public key is too weak: 1024 bits, at least 2048 bits required")

	derPKCS1 := x509.MarshalPKCS1PublicKey(&weakKey.PublicKey)
	pemPKCS1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: derPKCS1})
	_, err = LoadPublicKey(string(pemPKCS1))
	assert.ErrorContains(t, err, "RSA public key is too weak: 1024 bits, at least 2048 bits required")
}

func TestValidateServiceToken(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "empty is allowed (endpoints fail closed)", value: ""},
		{name: "strong token", value: "u7Qw2mZk9pXc4vBn6sTd1fGh3jKl5rYt"},
		{name: "too short", value: "short-token", wantErr: true},
		{name: "documented placeholder", value: "change-me-policy-token-at-least-32-bytes", wantErr: true},
		{name: "replace placeholder", value: "REPLACE_ME_WITH_openssl_rand_base64_32", wantErr: true},
		{name: "contains placeholder word", value: "this-is-a-placeholder-token-value-1234", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceToken("IAM_POLICY_TOKEN", tt.value)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), "IAM_POLICY_TOKEN"))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestIsKnownPlaceholderSecret(t *testing.T) {
	assert.True(t, IsKnownPlaceholderSecret("change-me"))
	assert.True(t, IsKnownPlaceholderSecret("Change-Me-Anything"))
	assert.True(t, IsKnownPlaceholderSecret("my-placeholder-value"))
	assert.False(t, IsKnownPlaceholderSecret("u7Qw2mZk9pXc4vBn6sTd1fGh3jKl5rYt"))
}
