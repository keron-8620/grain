package cryptoutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test RFC 5869 Official Test Case 1 (SHA-256)
func TestHKDF_RFC5869_Case1(t *testing.T) {
	ikm, err := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	require.NoError(t, err)
	salt, err := hex.DecodeString("000102030405060708090a0b0c")
	require.NoError(t, err)
	info, err := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	require.NoError(t, err)
	l := 42

	expectedPRK := "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
	expectedOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	// 1. Test step function HKDFExtract
	prk, err := HKDFExtract(sha256.New, ikm, salt)
	require.NoError(t, err)
	assert.Equal(t, expectedPRK, hex.EncodeToString(prk))

	// 2. Test step function HKDFExpand
	okmFromExpand, err := HKDFExpand(sha256.New, prk, info, l)
	require.NoError(t, err)
	assert.Equal(t, expectedOKM, hex.EncodeToString(okmFromExpand))

	// 3. Test HKDFExpandSHA256
	okmFromExpand256, err := HKDFExpandSHA256(prk, info, l)
	require.NoError(t, err)
	assert.Equal(t, expectedOKM, hex.EncodeToString(okmFromExpand256))

	// 4. Test one-shot HKDF
	okm, err := HKDF(sha256.New, ikm, salt, info, l)
	require.NoError(t, err)
	assert.Equal(t, expectedOKM, hex.EncodeToString(okm))

	// 5. Test one-shot HKDFSHA256
	okm256, err := HKDFSHA256(ikm, salt, info, l)
	require.NoError(t, err)
	assert.Equal(t, expectedOKM, hex.EncodeToString(okm256))
}

// Test RFC 5869 Official Test Case 2 (SHA-256 with longer inputs)
func TestHKDF_RFC5869_Case2(t *testing.T) {
	ikm := make([]byte, 80)
	for i := range ikm {
		ikm[i] = byte(i)
	}

	salt := make([]byte, 80)
	for i := range salt {
		salt[i] = byte(0x60 + i)
	}

	info := make([]byte, 80)
	for i := range info {
		info[i] = byte(0xb0 + i)
	}
	l := 82

	expectedPRK := "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
	expectedOKM := "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"

	prk, err := HKDFExtract(sha256.New, ikm, salt)
	require.NoError(t, err)
	assert.Equal(t, expectedPRK, hex.EncodeToString(prk))

	okm, err := HKDF(sha256.New, ikm, salt, info, l)
	require.NoError(t, err)
	assert.Equal(t, expectedOKM, hex.EncodeToString(okm))
}

// Test RFC 5869 Official Test Case 3 (SHA-256 with empty salt and info)
func TestHKDF_RFC5869_Case3(t *testing.T) {
	ikm, err := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	require.NoError(t, err)
	var salt []byte
	var info []byte
	l := 42

	expectedPRK := "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
	expectedOKM := "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

	// 1. Empty slices vs nil slices produce identical results
	prk, err := HKDFExtract(sha256.New, ikm, salt)
	require.NoError(t, err)
	assert.Equal(t, expectedPRK, hex.EncodeToString(prk))

	prkNil, err := HKDFExtract(sha256.New, ikm, nil)
	require.NoError(t, err)
	assert.Equal(t, expectedPRK, hex.EncodeToString(prkNil))

	okm, err := HKDF(sha256.New, ikm, salt, info, l)
	require.NoError(t, err)
	assert.Equal(t, expectedOKM, hex.EncodeToString(okm))

	okmNil, err := HKDF(sha256.New, ikm, nil, nil, l)
	require.NoError(t, err)
	assert.Equal(t, expectedOKM, hex.EncodeToString(okmNil))
}

// Test HKDF with SHA-512
func TestHKDF_SHA512(t *testing.T) {
	secret := []byte("master-secret-key-for-test-512")
	salt := []byte("random-salt-1234")
	info := []byte("context-session-token")

	key32, err := HKDFSHA512(secret, salt, info, 32)
	require.NoError(t, err)
	assert.Len(t, key32, 32)

	key64, err := HKDFSHA512(secret, salt, info, 64)
	require.NoError(t, err)
	assert.Len(t, key64, 64)
	assert.Equal(t, key32, key64[:32])

	// Consistent with Extract + Expand
	prk, err := HKDFExtract(sha512.New, secret, salt)
	require.NoError(t, err)
	assert.Len(t, prk, 64)

	expanded, err := HKDFExpand(sha512.New, prk, info, 64)
	require.NoError(t, err)
	assert.Equal(t, key64, expanded)
}

// Test boundary constraints and error handling
func TestHKDF_BoundaryAndErrors(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")

	// Nil hash function
	_, err := HKDF(nil, secret, salt, info, 32)
	assert.Error(t, err)

	_, err = HKDFExtract(nil, secret, salt)
	assert.Error(t, err)

	_, err = HKDFExpand(nil, secret, info, 32)
	assert.Error(t, err)

	// Non-positive keyLen
	_, err = HKDF(sha256.New, secret, salt, info, 0)
	assert.Error(t, err)

	_, err = HKDF(sha256.New, secret, salt, info, -5)
	assert.Error(t, err)

	_, err = HKDFExpand(sha256.New, make([]byte, 32), info, 0)
	assert.Error(t, err)

	// Exceeding maximum allowed output (255 * HashLen)
	maxLen256 := 255 * sha256.Size // 255 * 32 = 8160
	okmMax, err := HKDF(sha256.New, secret, salt, info, maxLen256)
	require.NoError(t, err)
	assert.Len(t, okmMax, maxLen256)

	_, err = HKDF(sha256.New, secret, salt, info, maxLen256+1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds HKDF maximum")

	// PRK too short in Expand
	_, err = HKDFExpand(sha256.New, []byte("too-short-prk"), info, 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PRK length")
}

// Test DeriveSubkeyHKDF and KeyManager integration
func TestKeyManager_DeriveSubkeyHKDF(t *testing.T) {
	km := NewKeyManager()
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	require.Len(t, masterKey, 32)

	// Subkey for Tenant A
	subKeyA, err := km.DeriveSubkeyHKDF(masterKey, nil, []byte("tenant:1001"), 32)
	require.NoError(t, err)
	assert.Len(t, subKeyA, 32)

	// Subkey for Tenant B
	subKeyB, err := km.DeriveSubkeyHKDF(masterKey, nil, []byte("tenant:1002"), 32)
	require.NoError(t, err)
	assert.Len(t, subKeyB, 32)

	// Assert distinct subkeys
	assert.NotEqual(t, subKeyA, subKeyB)

	// Default length (when subkeyLen <= 0, uses km.keyLen = 32)
	subKeyDefault, err := km.DeriveSubkeyHKDF(masterKey, nil, []byte("tenant:1001"), 0)
	require.NoError(t, err)
	assert.Equal(t, subKeyA, subKeyDefault)

	// Empty master key error
	_, err = km.DeriveSubkeyHKDF(nil, nil, []byte("tenant:1001"), 32)
	assert.Error(t, err)

	// Standalone DeriveSubkeyHKDF helper
	standaloneKey, err := DeriveSubkeyHKDF(masterKey, nil, []byte("tenant:1001"), 32)
	require.NoError(t, err)
	assert.Equal(t, subKeyA, standaloneKey)

	// Empty master key for standalone helper
	_, err = DeriveSubkeyHKDF(nil, nil, []byte("tenant:1001"), 32)
	assert.Error(t, err)

	// Derived subkey is fully usable with AESGCMCipher
	cipher, err := NewAESGCMCipher(subKeyA)
	require.NoError(t, err)

	plaintext := []byte("Secret Tenant Data Payload")
	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
