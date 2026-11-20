package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/internal/conf"
	"grain/pkg/cryptoutil"
)

func writeTestRSAKey(t *testing.T, bits int, mode os.FileMode) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "jwt-signing-key.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), mode))
	require.NoError(t, os.Chmod(path, mode))
	return path
}

func bootstrapWithSigningKey(path string) *conf.Bootstrap {
	return &conf.Bootstrap{
		IAM: &conf.IAMConfig{
			Token: conf.TokenConfig{PrivateKey: path},
		},
	}
}

func TestLoadJWTKeysRejectsWeakRSAKey(t *testing.T) {
	path := writeTestRSAKey(t, 1024, 0o600)

	_, _, _, err := loadJWTKeys(bootstrapWithSigningKey(path))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "长度不足")
}

func TestLoadJWTKeysAcceptsStrongKey(t *testing.T) {
	path := writeTestRSAKey(t, 2048, 0o600)

	privateKey, publicKey, kid, err := loadJWTKeys(bootstrapWithSigningKey(path))
	require.NoError(t, err)
	assert.NotNil(t, privateKey)
	assert.NotNil(t, publicKey)
	assert.NotEmpty(t, kid)
}

func TestLoadJWTKeysRejectsGroupWritableKeyFile(t *testing.T) {
	path := writeTestRSAKey(t, 2048, 0o666)

	_, _, _, err := loadJWTKeys(bootstrapWithSigningKey(path))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "可写")
}

func TestGeneratedKeyDoesNotMatchLeakedFingerprint(t *testing.T) {
	assert.Len(t, leakedDevSigningKeySHA256, 64)

	path := writeTestRSAKey(t, 2048, 0o600)
	privateKey, _, _, err := loadJWTKeys(bootstrapWithSigningKey(path))
	require.NoError(t, err)

	publicKey, err := cryptoutil.ExtractPublicKey(privateKey)
	require.NoError(t, err)
	fingerprint, err := publicKeyFingerprint(publicKey)
	require.NoError(t, err)
	assert.NotEqual(t, leakedDevSigningKeySHA256, fingerprint)
	assert.Len(t, fingerprint, 64)
}
