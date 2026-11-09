package cryptoutil

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test AES-CBC mode
func TestAESCipher(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes for AES-128

	cipher, err := NewAESCipher(key)
	require.NoError(t, err)

	// Test byte-level Encrypt / Decrypt
	plaintext := []byte("Hello, AES-CBC World!")
	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	assert.Greater(t, len(ciphertext), len(plaintext))

	decrypted, err := cipher.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Test string-level EncryptString / DecryptString
	text := "Sensitive user credential"
	b64Cipher, err := cipher.EncryptString(text)
	require.NoError(t, err)
	assert.True(t, IsValidBase64(b64Cipher))

	plainText, err := cipher.DecryptString(b64Cipher)
	require.NoError(t, err)
	assert.Equal(t, text, plainText)

	// DecryptString invalid base64
	_, err = cipher.DecryptString("invalid-base64???")
	assert.Error(t, err)

	// NewAESCipher invalid key size
	_, err = NewAESCipher([]byte("invalid-key-length"))
	assert.Error(t, err)

	// Test package-level helper
	pHelperCipher, err := EncryptString(cipher, text)
	require.NoError(t, err)
	pHelperPlain, err := DecryptString(cipher, pHelperCipher)
	require.NoError(t, err)
	assert.Equal(t, text, pHelperPlain)

	_, err = DecryptString(cipher, "invalid-base64???")
	assert.Error(t, err)
}

// Test AES-CBC cross-instance decryption and IV uniqueness
func TestAESCipher_SecurityProperties(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256

	// Cross-instance decryption: instance A encrypts, independent instance B decrypts
	cipherA, err := NewAESCipher(key)
	require.NoError(t, err)
	cipherB, err := NewAESCipher(key)
	require.NoError(t, err)

	original := []byte("Cross-instance secret data payload")
	ciphertextA, err := cipherA.Encrypt(original)
	require.NoError(t, err)

	decryptedB, err := cipherB.Decrypt(ciphertextA)
	require.NoError(t, err)
	assert.Equal(t, original, decryptedB)

	// IV Uniqueness: encrypting identical plaintext produces distinct IVs and ciphertexts
	seenIVs := make(map[string]bool)
	seenCiphertexts := make(map[string]bool)
	for range 200 {
		ct, err := cipherA.Encrypt(original)
		require.NoError(t, err)

		ivHex := hex.EncodeToString(ct[:aes.BlockSize])
		ctHex := hex.EncodeToString(ct)

		assert.False(t, seenIVs[ivHex], "IV collision detected!")
		assert.False(t, seenCiphertexts[ctHex], "Ciphertext collision detected!")

		seenIVs[ivHex] = true
		seenCiphertexts[ctHex] = true
	}

	// Deterministic EncryptWithIV
	fixedIV := []byte("1234567890abcdef")
	detCipher1, err := cipherA.EncryptWithIV(original, fixedIV)
	require.NoError(t, err)
	detCipher2, err := cipherB.EncryptWithIV(original, fixedIV)
	require.NoError(t, err)
	assert.Equal(t, detCipher1, detCipher2)

	// EncryptWithIV invalid IV length
	_, err = cipherA.EncryptWithIV(original, []byte("short"))
	assert.Error(t, err)

	// Decrypt corrupt/short ciphertext
	_, err = cipherA.Decrypt([]byte("too-short"))
	assert.Error(t, err)

	// Non-aligned block size
	unaligned := make([]byte, 35) // not 16 + k*16
	_, err = cipherA.Decrypt(unaligned)
	assert.Error(t, err)
}

// Test AES-GCM mode
func TestAESGCMCipher(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	gcm, err := NewAESGCMCipher(key)
	require.NoError(t, err)
	assert.NotNil(t, gcm.Block())

	// Verify AEADCipher interface implementation
	var aeadCipher AEADCipher = gcm
	assert.NotNil(t, aeadCipher)

	plaintext := []byte("Confidential GCM authenticated message")
	ciphertext, err := gcm.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := gcm.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Test EncryptString / DecryptString
	strCipher, err := gcm.EncryptString(string(plaintext))
	require.NoError(t, err)
	strPlain, err := gcm.DecryptString(strCipher)
	require.NoError(t, err)
	assert.Equal(t, string(plaintext), strPlain)

	// DecryptString invalid base64
	_, err = gcm.DecryptString("invalid-base64???")
	assert.Error(t, err)

	// NewAESGCMCipher invalid key size
	_, err = NewAESGCMCipher([]byte("invalid-key-length"))
	assert.Error(t, err)

	// Test with AAD (Additional Authenticated Data)
	aad := []byte("tenant_id=42;user_id=100")
	aadCipher, err := gcm.EncryptWithAAD(plaintext, aad)
	require.NoError(t, err)

	// Decrypt with matching AAD
	aadPlain, err := gcm.DecryptWithAAD(aadCipher, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, aadPlain)

	// Decrypt with mismatched AAD must fail
	_, err = gcm.DecryptWithAAD(aadCipher, []byte("tenant_id=99"))
	assert.Error(t, err)

	// Tampered ciphertext must fail authentication
	tamperedCipher := append([]byte(nil), ciphertext...)
	tamperedCipher[len(tamperedCipher)-1] ^= 0x01
	_, err = gcm.Decrypt(tamperedCipher)
	assert.Error(t, err)

	// Cross-instance decryption
	gcm2, err := NewAESGCMCipher(key)
	require.NoError(t, err)
	decrypted2, err := gcm2.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)
}

// Test PKCS#7 padding and unpadding
func TestPKCS7Padding(t *testing.T) {
	blockSize := 16

	// Test various lengths
	testCases := []int{0, 1, 15, 16, 17, 31, 32}
	for _, length := range testCases {
		data := make([]byte, length)
		for i := range data {
			data[i] = byte(i)
		}

		padded, err := pkcs7Padding(data, blockSize)
		require.NoError(t, err)
		assert.Equal(t, 0, len(padded)%blockSize)
		assert.Greater(t, len(padded), len(data))

		unpadded, err := pkcs7Unpadding(padded, blockSize)
		require.NoError(t, err)
		assert.Equal(t, data, unpadded)
	}

	// Negative tests
	// Empty data
	_, err := pkcs7Unpadding([]byte{}, blockSize)
	assert.Error(t, err)

	// Not multiple of block size
	_, err = pkcs7Unpadding([]byte{1, 2, 3}, blockSize)
	assert.Error(t, err)

	// Invalid pad length (0)
	corruptPadZero := make([]byte, 16)
	corruptPadZero[15] = 0x00
	_, err = pkcs7Unpadding(corruptPadZero, blockSize)
	assert.Error(t, err)

	// Invalid pad length (> blockSize)
	corruptPadTooBig := make([]byte, 16)
	corruptPadTooBig[15] = 0x11
	_, err = pkcs7Unpadding(corruptPadTooBig, blockSize)
	assert.Error(t, err)

	// Inconsistent padding bytes (e.g. pad length is 3, but bytes are [1, 3, 3])
	corruptBytes := []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 1, 3, 3,
	}
	_, err = pkcs7Unpadding(corruptBytes, blockSize)
	assert.Error(t, err)

	// Invalid block size
	_, err = pkcs7Padding([]byte("test"), 0)
	assert.Error(t, err)
	_, err = pkcs7Unpadding([]byte("test"), 0)
	assert.Error(t, err)
}

// Test KeyManager and key derivation
func TestKeyManager(t *testing.T) {
	km := NewKeyManager()

	// DeriveKey requires non-empty salt
	password := "user-secure-master-password"
	_, err := km.DeriveKey(password, nil)
	assert.Error(t, err, "DeriveKey must fail if salt is empty")

	_, err = km.DeriveKey(password, []byte{})
	assert.Error(t, err)

	// DeriveKeyWithNewSalt generates salt and key
	key1, salt1, err := km.DeriveKeyWithNewSalt(password)
	require.NoError(t, err)
	assert.Len(t, key1, 32)
	assert.Len(t, salt1, 16)

	// Re-deriving with the same salt must produce the exact same key
	key2, err := km.DeriveKey(password, salt1)
	require.NoError(t, err)
	assert.Equal(t, key1, key2)

	// Different salt produces different key
	key3, salt3, err := km.DeriveKeyWithNewSalt(password)
	require.NoError(t, err)
	assert.NotEqual(t, salt1, salt3)
	assert.NotEqual(t, key1, key3)

	// Random key generation
	randKey, err := km.GenerateRandomKey()
	require.NoError(t, err)
	assert.Len(t, randKey, 32)

	randKey16, err := GenerateRandomKeyWithSize(16)
	require.NoError(t, err)
	assert.Len(t, randKey16, 16)

	// Encodings
	b64Key := KeyToBase64(key1)
	parsedB64, err := KeyFromBase64(b64Key)
	require.NoError(t, err)
	assert.Equal(t, key1, parsedB64)

	hexKey := KeyToHex(key1)
	parsedHex, err := KeyFromHex(hexKey)
	require.NoError(t, err)
	assert.Equal(t, key1, parsedHex)

	// Key size validation
	assert.NoError(t, ValidateKeySize(make([]byte, 16), "aes"))
	assert.NoError(t, ValidateKeySize(make([]byte, 24), "aes"))
	assert.NoError(t, ValidateKeySize(make([]byte, 32), "aes"))
	assert.Error(t, ValidateKeySize(make([]byte, 15), "aes"))

	// Exact key size validation for explicit variants
	assert.NoError(t, ValidateKeySize(make([]byte, 16), "aes-128"))
	assert.Error(t, ValidateKeySize(make([]byte, 24), "aes-128"))
	assert.Error(t, ValidateKeySize(make([]byte, 32), "aes-128"))

	assert.NoError(t, ValidateKeySize(make([]byte, 24), "aes-192"))
	assert.Error(t, ValidateKeySize(make([]byte, 16), "aes-192"))
	assert.Error(t, ValidateKeySize(make([]byte, 32), "aes-192"))

	assert.NoError(t, ValidateKeySize(make([]byte, 32), "aes-256"))
	assert.Error(t, ValidateKeySize(make([]byte, 16), "aes-256"))
	assert.Error(t, ValidateKeySize(make([]byte, 24), "aes-256"))

	assert.NoError(t, ValidateKeySize(make([]byte, 32), "hmac"))
	assert.Error(t, ValidateKeySize(make([]byte, 8), "hmac"))
	assert.Error(t, ValidateKeySize(make([]byte, 16), "unsupported-algo"))

	// Custom params
	kmCustom := NewKeyManagerWithParams(16, 16384, 8, 1, 32)
	kCustom, sCustom, err := kmCustom.DeriveKeyWithNewSalt(password)
	require.NoError(t, err)
	assert.Len(t, kCustom, 32)
	assert.Len(t, sCustom, 16)

	// Zero wipes key memory
	kmCustom.Zero(kCustom)
	for _, b := range kCustom {
		assert.Equal(t, byte(0), b)
	}
}

// Test ScryptHasher with self-describing PHC format
func TestScryptHasher(t *testing.T) {
	hasher := NewScryptHasher()

	password := "my-secret-scrypt-password"
	hashStr, err := hasher.HashString(password)
	require.NoError(t, err)
	assert.Contains(t, hashStr, "$scrypt$ln=")

	// Verify with correct password
	valid, err := hasher.VerifyString(password, hashStr)
	require.NoError(t, err)
	assert.True(t, valid)

	// Verify with wrong password
	valid, err = hasher.VerifyString("wrong-password", hashStr)
	require.NoError(t, err)
	assert.False(t, valid)

	// Test byte-level interface
	hashBytes, err := hasher.Hash([]byte(password))
	require.NoError(t, err)
	valid, err = hasher.Verify([]byte(password), hashBytes)
	require.NoError(t, err)
	assert.True(t, valid)

	// Cross-parameter upgrade test:
	// A hash generated with custom parameters can still be verified by the default hasher
	customHasher := NewScryptHasherWithParams(16, 16384, 8, 1, 32)
	customHash, err := customHasher.HashString(password)
	require.NoError(t, err)

	validUpgrade, err := hasher.VerifyString(password, customHash)
	require.NoError(t, err)
	assert.True(t, validUpgrade, "Standard hasher must verify hash generated with different N/r/p")

	// Invalid PHC string
	_, err = hasher.VerifyString(password, "$scrypt$badformat")
	assert.Error(t, err)

	// DoS Protection: parameters exceeding safety limits must be rejected without hanging or OOM
	_, err = hasher.VerifyString(password, "$scrypt$ln=25,r=8,p=1$c2FsdHNhbHQ$aGFzaA")
	assert.Error(t, err)
	_, err = hasher.VerifyString(password, "$scrypt$ln=10,r=100,p=1$c2FsdHNhbHQ$aGFzaA")
	assert.Error(t, err)
	_, err = hasher.VerifyString(password, "$scrypt$ln=10,r=8,p=100$c2FsdHNhbHQ$aGFzaA")
	assert.Error(t, err)
	_, err = hasher.VerifyString(password, "$scrypt$n=1000,r=8,p=1$c2FsdHNhbHQ$aGFzaA") // not power of 2
	assert.Error(t, err)
	// Excessive memory usage (ln=20 => N=1048576, r=16 => 128*N*r = 2 GiB > 128 MiB)
	_, err = hasher.VerifyString(password, "$scrypt$ln=20,r=16,p=1$c2FsdHNhbHQ$aGFzaA")
	assert.Error(t, err)

	// Legacy format (base64 of salt || hash)
	legacySalt := []byte("1234567890123456")
	kmLegacy := NewKeyManagerWithParams(16, 32768, 8, 1, 32)
	legacyDerived, err := kmLegacy.DeriveKey(password, legacySalt)
	require.NoError(t, err)
	legacyCombined := append(legacySalt, legacyDerived...)
	legacyB64 := EncodeBase64(legacyCombined)

	validLegacy, err := hasher.VerifyString(password, legacyB64)
	require.NoError(t, err)
	assert.True(t, validLegacy, "Must verify legacy scrypt format")
}

// Test BcryptHasher
func TestBcryptHasher(t *testing.T) {
	hasher := NewBcryptHasher(0)

	password := "bcrypt-super-secret"
	hashStr, err := hasher.HashString(password)
	require.NoError(t, err)

	// Valid password
	valid, err := hasher.VerifyString(password, hashStr)
	require.NoError(t, err)
	assert.True(t, valid)

	// Wrong password returns false, nil (not error)
	valid, err = hasher.VerifyString("wrong-pass", hashStr)
	require.NoError(t, err)
	assert.False(t, valid)

	// Malformed hash returns error
	_, err = hasher.VerifyString(password, "invalid-bcrypt-hash")
	assert.Error(t, err)

	// Byte interface
	hashBytes, err := hasher.Hash([]byte(password))
	require.NoError(t, err)
	valid, err = hasher.Verify([]byte(password), hashBytes)
	require.NoError(t, err)
	assert.True(t, valid)
}

// Test HMAC functions
func TestHMACHasher(t *testing.T) {
	key := []byte("hmac-secret-signing-key-32bytes!")

	hasher256, err := NewHMACHasher(key, HMACSHA256)
	require.NoError(t, err)
	data := []byte("Authenticate this message content")

	mac, err := hasher256.Hash(data)
	require.NoError(t, err)

	// Verify bytes
	valid, err := hasher256.Verify(data, mac)
	require.NoError(t, err)
	assert.True(t, valid)

	// Tampered data
	valid, err = hasher256.Verify([]byte("Tampered content"), mac)
	require.NoError(t, err)
	assert.False(t, valid)

	// Test String & Case-Insensitive Hex Verification
	hexMAC, err := hasher256.HashString(string(data))
	require.NoError(t, err)

	valid, err = hasher256.VerifyString(string(data), hexMAC)
	require.NoError(t, err)
	assert.True(t, valid)

	// Explicit HashHex and VerifyHex
	hexMAC2, err := hasher256.HashHex(string(data))
	require.NoError(t, err)
	assert.Equal(t, hexMAC, hexMAC2)
	valid, err = hasher256.VerifyHex(string(data), hexMAC2)
	require.NoError(t, err)
	assert.True(t, valid)

	// Explicit HashBase64 and VerifyBase64
	b64MAC, err := hasher256.HashBase64(string(data))
	require.NoError(t, err)
	valid, err = hasher256.VerifyBase64(string(data), b64MAC)
	require.NoError(t, err)
	assert.True(t, valid)
	_, err = hasher256.VerifyBase64(string(data), "invalid-base64???")
	assert.Error(t, err)

	// Uppercase hex
	valid, err = hasher256.VerifyString(string(data), bytes.NewBufferString(hexMAC).String())
	require.NoError(t, err)
	assert.True(t, valid)

	// HMAC-SHA512
	hasher512, err := NewHMACHasher(key, HMACSHA512)
	require.NoError(t, err)
	mac512, err := hasher512.Hash(data)
	require.NoError(t, err)
	assert.Equal(t, 64, len(mac512))

	// Standalone functions
	hVal, err := GenerateHMAC("my-data", key, HMACSHA256)
	require.NoError(t, err)
	hValid, err := VerifyHMAC("my-data", hVal, key, HMACSHA256)
	require.NoError(t, err)
	assert.True(t, hValid)

	// Key validation & error handling
	// Unsupported algorithm
	_, err = NewHMACHasher(key, "unsupported")
	assert.Error(t, err)

	// Key size too small (< 16 for HMAC-SHA256)
	_, err = NewHMACHasher([]byte("short-key"), HMACSHA256)
	assert.Error(t, err)

	// Key size too small (< 32 for HMAC-SHA512)
	_, err = NewHMACHasher([]byte("sixteen-byte-key"), HMACSHA512)
	assert.Error(t, err)

	// NewHMACHasherUnchecked allows short keys for test vectors
	unchecked, err := NewHMACHasherUnchecked([]byte("short"), HMACSHA256)
	require.NoError(t, err)
	shortMAC, err := unchecked.Hash(data)
	require.NoError(t, err)
	assert.NotEmpty(t, shortMAC)

	_, err = NewHMACHasherUnchecked([]byte("short"), "unsupported")
	assert.Error(t, err)
}

// Test SHA256 and SHA512 hashers
func TestSHAHashers(t *testing.T) {
	data := []byte("Hash verification payload")

	// SHA-256
	sha256Hasher := NewSHA256Hasher()
	digest256, err := sha256Hasher.Hash(data)
	require.NoError(t, err)
	assert.Len(t, digest256, 32)

	valid, err := sha256Hasher.Verify(data, digest256)
	require.NoError(t, err)
	assert.True(t, valid)

	hex256, err := sha256Hasher.HashString(string(data))
	require.NoError(t, err)
	valid, err = sha256Hasher.VerifyString(string(data), hex256)
	require.NoError(t, err)
	assert.True(t, valid)

	// SHA-256 HashHex & HashBase64
	hexExplicit, err := sha256Hasher.HashHex(string(data))
	require.NoError(t, err)
	assert.Equal(t, hex256, hexExplicit)
	valid, err = sha256Hasher.VerifyHex(string(data), hexExplicit)
	require.NoError(t, err)
	assert.True(t, valid)

	b64Explicit, err := sha256Hasher.HashBase64(string(data))
	require.NoError(t, err)
	valid, err = sha256Hasher.VerifyBase64(string(data), b64Explicit)
	require.NoError(t, err)
	assert.True(t, valid)
	_, err = sha256Hasher.VerifyBase64(string(data), "invalid-base64???")
	assert.Error(t, err)

	// SHA-512
	sha512Hasher := NewSHA512Hasher()
	digest512, err := sha512Hasher.Hash(data)
	require.NoError(t, err)
	assert.Len(t, digest512, 64)

	valid, err = sha512Hasher.Verify(data, digest512)
	require.NoError(t, err)
	assert.True(t, valid)

	hex512, err := sha512Hasher.HashString(string(data))
	require.NoError(t, err)
	valid, err = sha512Hasher.VerifyString(string(data), hex512)
	require.NoError(t, err)
	assert.True(t, valid)

	// SHA-512 HashHex & HashBase64
	hex512Explicit, err := sha512Hasher.HashHex(string(data))
	require.NoError(t, err)
	assert.Equal(t, hex512, hex512Explicit)
	valid, err = sha512Hasher.VerifyHex(string(data), hex512Explicit)
	require.NoError(t, err)
	assert.True(t, valid)

	b64512Explicit, err := sha512Hasher.HashBase64(string(data))
	require.NoError(t, err)
	valid, err = sha512Hasher.VerifyBase64(string(data), b64512Explicit)
	require.NoError(t, err)
	assert.True(t, valid)
	_, err = sha512Hasher.VerifyBase64(string(data), "invalid-base64???")
	assert.Error(t, err)

	// Package-level HashString, HashHex, HashBase64, VerifyString, VerifyHex, VerifyBase64
	pkgHashHex, err := HashHex(sha256Hasher, string(data))
	require.NoError(t, err)
	validHex, err := VerifyHex(sha256Hasher, string(data), pkgHashHex)
	require.NoError(t, err)
	assert.True(t, validHex)

	pkgHashB64, err := HashBase64(sha256Hasher, string(data))
	require.NoError(t, err)
	validB64, err := VerifyBase64(sha256Hasher, string(data), pkgHashB64)
	require.NoError(t, err)
	assert.True(t, validB64)

	// Package-level VerifyString accepts BOTH hex and base64
	validFromHex, err := VerifyString(sha256Hasher, string(data), pkgHashHex)
	require.NoError(t, err)
	assert.True(t, validFromHex, "VerifyString must verify hex-encoded hash")

	validFromB64, err := VerifyString(sha256Hasher, string(data), pkgHashB64)
	require.NoError(t, err)
	assert.True(t, validFromB64, "VerifyString must verify base64-encoded hash")

	// Package-level HashString & VerifyString for PHC/Bcrypt formats (starting with $)
	scryptHasher := NewScryptHasher()
	scryptStr, err := HashString(scryptHasher, "my-pass")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(scryptStr, "$scrypt$"))
	scryptValid, err := VerifyString(scryptHasher, "my-pass", scryptStr)
	require.NoError(t, err)
	assert.True(t, scryptValid)

	// Encoding errors
	_, err = VerifyHex(sha256Hasher, "data", "not-a-valid-hex-string!!!")
	assert.Error(t, err)
	_, err = VerifyBase64(sha256Hasher, "data", "not-valid-base64???")
	assert.Error(t, err)
	_, err = VerifyString(sha256Hasher, "data", "")
	assert.Error(t, err)
	_, err = VerifyString(sha256Hasher, "data", "invalid-hash-content!@#$%^&*()")
	assert.Error(t, err)

	// Nil checks
	_, err = HashString(nil, "data")
	assert.Error(t, err)
	_, err = HashHex(nil, "data")
	assert.Error(t, err)
	_, err = HashBase64(nil, "data")
	assert.Error(t, err)
	_, err = VerifyString(nil, "data", "hash")
	assert.Error(t, err)
	_, err = VerifyHex(nil, "data", "hash")
	assert.Error(t, err)
	_, err = VerifyBase64(nil, "data", "hash")
	assert.Error(t, err)
	_, err = EncryptString(nil, "data")
	assert.Error(t, err)
	_, err = DecryptString(nil, "data")
	assert.Error(t, err)
}

// Test streaming and file encryption
func TestFileEncryptor(t *testing.T) {
	ctx := context.Background()
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	fe, err := NewFileEncryptor(key)
	require.NoError(t, err)

	tempDir := t.TempDir()
	srcPath := filepath.Join(tempDir, "plaintext.dat")
	encPath := filepath.Join(tempDir, "encrypted.dat")
	decPath := filepath.Join(tempDir, "decrypted.dat")

	// Generate multi-chunk test file (> 150 KiB to cross multiple 64 KiB chunks)
	fileSize := 160 * 1024
	testData := make([]byte, fileSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	err = os.WriteFile(srcPath, testData, 0644)
	require.NoError(t, err)

	// Encrypt file
	err = fe.EncryptFile(ctx, srcPath, encPath)
	require.NoError(t, err)

	// Check file permissions are 0600
	encInfo, err := os.Stat(encPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), encInfo.Mode().Perm())

	// Decrypt file
	err = fe.DecryptFile(ctx, encPath, decPath)
	require.NoError(t, err)

	decryptedContent, err := os.ReadFile(decPath)
	require.NoError(t, err)
	assert.Equal(t, testData, decryptedContent)

	// Stream test (io.Reader to io.Writer)
	var encBuf bytes.Buffer
	err = fe.EncryptStream(ctx, bytes.NewReader(testData), &encBuf)
	require.NoError(t, err)

	encBytes := encBuf.Bytes()
	var decBuf bytes.Buffer
	err = fe.DecryptStream(ctx, bytes.NewReader(encBytes), &decBuf)
	require.NoError(t, err)
	assert.Equal(t, testData, decBuf.Bytes())

	// Empty file encryption/decryption
	emptySrc := filepath.Join(tempDir, "empty.dat")
	emptyEnc := filepath.Join(tempDir, "empty.enc")
	emptyDec := filepath.Join(tempDir, "empty.dec")
	require.NoError(t, os.WriteFile(emptySrc, []byte{}, 0644))

	require.NoError(t, fe.EncryptFile(ctx, emptySrc, emptyEnc))
	require.NoError(t, fe.DecryptFile(ctx, emptyEnc, emptyDec))
	emptyContent, err := os.ReadFile(emptyDec)
	require.NoError(t, err)
	assert.Empty(t, emptyContent)

	// Tampered encrypted stream
	corruptEnc := append([]byte(nil), encBytes...)
	corruptEnc[len(corruptEnc)-5] ^= 0xFF
	var corruptDecBuf bytes.Buffer
	err = fe.DecryptStream(ctx, bytes.NewReader(corruptEnc), &corruptDecBuf)
	assert.Error(t, err, "Tampered file stream must fail authentication")

	// Context cancellation aborts stream
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // pre-cancel
	err = fe.EncryptFile(cancelCtx, srcPath, filepath.Join(tempDir, "canceled.enc"))
	assert.Error(t, err)
	assert.NoFileExists(t, filepath.Join(tempDir, "canceled.enc"), "Canceled encryption must not leave destination file behind")

	// Target supports BlockProvider
	gcmCipher, err := NewAESGCMCipher(key)
	require.NoError(t, err)
	feFromCipher, err := NewAESFileEncryptor(gcmCipher)
	require.NoError(t, err)
	require.NoError(t, feFromCipher.EncryptFile(ctx, srcPath, encPath))

	cbcCipher, err := NewAESCipher(key)
	require.NoError(t, err)
	assert.NotNil(t, cbcCipher.Block())
	feFromCBC, err := NewAESFileEncryptor(cbcCipher)
	require.NoError(t, err)
	require.NoError(t, feFromCBC.EncryptFile(ctx, srcPath, encPath))

	// Invalid target for NewAESFileEncryptor
	_, err = NewAESFileEncryptor(12345)
	assert.Error(t, err)

	// Stream decryption error handling
	// Invalid magic
	var badMagicBuf bytes.Buffer
	err = fe.DecryptStream(ctx, bytes.NewReader([]byte("BADM\x010123456789ab")), &badMagicBuf)
	assert.Error(t, err)

	// Unsupported version
	var badVerBuf bytes.Buffer
	err = fe.DecryptStream(ctx, bytes.NewReader([]byte("GRNC\x990123456789ab")), &badVerBuf)
	assert.Error(t, err)

	// Standalone package-level helpers
	require.NoError(t, EncryptFile(ctx, key, srcPath, encPath))
	require.NoError(t, DecryptFile(ctx, key, encPath, decPath))

	// In-place file encryption & decryption (srcPath == dstPath)
	inPlacePath := filepath.Join(tempDir, "inplace.dat")
	require.NoError(t, os.WriteFile(inPlacePath, testData, 0644))
	require.NoError(t, fe.EncryptFile(ctx, inPlacePath, inPlacePath))

	// Verify the file on disk is encrypted
	encOnDisk, err := os.ReadFile(inPlacePath)
	require.NoError(t, err)
	assert.NotEqual(t, testData, encOnDisk)

	// Decrypt in-place
	require.NoError(t, fe.DecryptFile(ctx, inPlacePath, inPlacePath))
	decOnDisk, err := os.ReadFile(inPlacePath)
	require.NoError(t, err)
	assert.Equal(t, testData, decOnDisk)
}

// Test utils hardening
func TestUtilsHardening(t *testing.T) {
	// Random bytes
	b, err := GenerateRandomBytes(32)
	require.NoError(t, err)
	assert.Len(t, b, 32)

	_, err = GenerateRandomBytes(-1)
	assert.Error(t, err)

	// Random string
	s, err := GenerateRandomString(16)
	require.NoError(t, err)
	assert.NotEmpty(t, s)

	// Random hex
	h, err := GenerateRandomHex(16)
	require.NoError(t, err)
	assert.Len(t, h, 32)

	// Random alphanumeric
	alnum, err := GenerateRandomAlphanumeric(20)
	require.NoError(t, err)
	assert.Len(t, alnum, 20)

	emptyAlnum, err := GenerateRandomAlphanumeric(0)
	require.NoError(t, err)
	assert.Empty(t, emptyAlnum)

	_, err = GenerateRandomAlphanumeric(-5)
	assert.Error(t, err)

	// Random integer: safe boundaries
	randInt, err := GenerateRandomInt(10, 20)
	require.NoError(t, err)
	assert.True(t, randInt >= 10 && randInt <= 20)

	// min == max
	randIntSame, err := GenerateRandomInt(50, 50)
	require.NoError(t, err)
	assert.Equal(t, int64(50), randIntSame)

	// min > max must error, NOT panic
	_, err = GenerateRandomInt(100, 10)
	assert.Error(t, err)

	// Large 64-bit bounds without overflow panic
	largeInt, err := GenerateRandomInt(math.MinInt64/2, math.MaxInt64/2)
	require.NoError(t, err)
	assert.True(t, largeInt >= math.MinInt64/2 && largeInt <= math.MaxInt64/2)

	// Encodings
	data := []byte("Encoding test bytes")
	b64 := EncodeBase64(data)
	assert.True(t, IsValidBase64(b64))
	decB64, err := DecodeBase64(b64)
	require.NoError(t, err)
	assert.Equal(t, data, decB64)

	hexStr := EncodeHex(data)
	assert.True(t, IsValidHex(hexStr))
	decHex, err := DecodeHex(hexStr)
	require.NoError(t, err)
	assert.Equal(t, data, decHex)

	// Padding
	assert.Equal(t, "abc000", PadRight("abc", '0', 6))
	assert.Equal(t, "000abc", PadLeft("abc", '0', 6))
	assert.Equal(t, "toolong", PadRight("toolong", '0', 4))

	// TruncateString UTF-8 Rune safety
	assert.Equal(t, "", TruncateString("hello", 0))
	assert.Equal(t, "", TruncateString("hello", -2))
	assert.Equal(t, "he", TruncateString("hello", 2))

	// Chinese multi-byte characters
	chinese := "你好世界，欢迎来到密码学"
	truncatedChinese := TruncateString(chinese, 4)
	assert.Equal(t, "你好世界", truncatedChinese)
	assert.True(t, utf8.ValidString(truncatedChinese))

	// Emoji
	emojis := "🚀🎉🔥🌟✨"
	truncatedEmojis := TruncateString(emojis, 3)
	assert.Equal(t, "🚀🎉🔥", truncatedEmojis)
	assert.True(t, utf8.ValidString(truncatedEmojis))

	// Constant time comparison
	assert.True(t, SafeEqual("secure-token-123", "secure-token-123"))
	assert.False(t, SafeEqual("secure-token-123", "secure-token-456"))
	assert.False(t, SafeEqual("short", "longer-string"))

	assert.True(t, SafeEqualBytes([]byte{1, 2, 3}, []byte{1, 2, 3}))
	assert.False(t, SafeEqualBytes([]byte{1, 2, 3}, []byte{1, 2, 4}))

	// ZeroBytes memory sanitization
	sensitiveBuf := []byte("confidential-token-string")
	ZeroBytes(sensitiveBuf)
	for _, b := range sensitiveBuf {
		assert.Equal(t, byte(0), b)
	}

	// ZeroBytes with empty slice should not panic
	assert.NotPanics(t, func() {
		ZeroBytes([]byte{})
		ZeroBytes(nil)
	})
}

// Benchmarks
func BenchmarkAESCBC_Encrypt(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewAESCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte("This is a benchmark payload for AES-CBC symmetric encryption.")

	b.ResetTimer()
	for b.Loop() {
		_, err := cipher.Encrypt(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAESGCM_Encrypt(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewAESGCMCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte("This is a benchmark payload for AES-GCM symmetric encryption.")

	b.ResetTimer()
	for b.Loop() {
		_, err := cipher.Encrypt(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSHA256_Hash(b *testing.B) {
	hasher := NewSHA256Hasher()
	payload := []byte("This is a benchmark payload for SHA-256 hash.")

	b.ResetTimer()
	for b.Loop() {
		_, err := hasher.Hash(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHMAC_Hash(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	hasher, err := NewHMACHasher(key, HMACSHA256)
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte("This is a benchmark payload for HMAC-SHA256.")

	b.ResetTimer()
	for b.Loop() {
		_, err := hasher.Hash(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileEncryptor_Stream(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	fe, err := NewFileEncryptor(key)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 256*1024) // 256 KiB
	ctx := context.Background()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for b.Loop() {
		var out bytes.Buffer
		err := fe.EncryptStream(ctx, bytes.NewReader(payload), &out)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileEncryptor_DecryptStream(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	fe, err := NewFileEncryptor(key)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 256*1024) // 256 KiB
	ctx := context.Background()
	var encBuf bytes.Buffer
	if err := fe.EncryptStream(ctx, bytes.NewReader(payload), &encBuf); err != nil {
		b.Fatal(err)
	}
	ciphertext := encBuf.Bytes()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for b.Loop() {
		var out bytes.Buffer
		err := fe.DecryptStream(ctx, bytes.NewReader(ciphertext), &out)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestKeyManager_ByteMethods(t *testing.T) {
	km := NewKeyManager()
	pwd := []byte("SensitiveMasterKeySecret!2026")
	salt := []byte("1234567812345678")

	// DeriveKeyFromBytes
	derived1, err := km.DeriveKeyFromBytes(pwd, salt)
	require.NoError(t, err)
	assert.Len(t, derived1, 32)

	// Compare with string-based DeriveKey
	derived2, err := km.DeriveKey(string(pwd), salt)
	require.NoError(t, err)
	assert.Equal(t, derived1, derived2)

	// DeriveKeyWithNewSaltFromBytes
	derived3, newSalt, err := km.DeriveKeyWithNewSaltFromBytes(pwd)
	require.NoError(t, err)
	assert.Len(t, derived3, 32)
	assert.Len(t, newSalt, 16)

	// Re-derive with returned salt
	derived4, err := km.DeriveKeyFromBytes(pwd, newSalt)
	require.NoError(t, err)
	assert.Equal(t, derived3, derived4)

	// Empty salt rejected
	_, err = km.DeriveKeyFromBytes(pwd, nil)
	assert.Error(t, err)

	// ZeroBytes on password
	ZeroBytes(pwd)
	assert.Equal(t, make([]byte, len(pwd)), pwd)
}

func TestFileEncryptor_ConcurrentStreams(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	fe, err := NewFileEncryptor(key)
	require.NoError(t, err)

	ctx := context.Background()
	payload := []byte(strings.Repeat("Concurrent STREAM encryption validation data block. ", 1500)) // ~75 KiB (> 1 chunk)

	done := make(chan bool)
	for i := 0; i < 15; i++ {
		go func() {
			var encBuf bytes.Buffer
			err := fe.EncryptStream(ctx, bytes.NewReader(payload), &encBuf)
			assert.NoError(t, err)

			var decBuf bytes.Buffer
			err = fe.DecryptStream(ctx, bytes.NewReader(encBuf.Bytes()), &decBuf)
			assert.NoError(t, err)
			assert.Equal(t, payload, decBuf.Bytes())

			done <- true
		}()
	}

	for i := 0; i < 15; i++ {
		<-done
	}
}

func TestFileEncryptor_PartialDataFlushBehavior(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	fe, err := NewFileEncryptor(key)
	require.NoError(t, err)

	ctx := context.Background()
	// Create payload spanning 2 chunks (64 KiB + 10 KiB)
	chunk1 := bytes.Repeat([]byte("A"), FileChunkSize)
	chunk2 := bytes.Repeat([]byte("B"), 10*1024)
	fullPayload := append(append([]byte(nil), chunk1...), chunk2...)

	var encBuf bytes.Buffer
	err = fe.EncryptStream(ctx, bytes.NewReader(fullPayload), &encBuf)
	require.NoError(t, err)

	encBytes := encBuf.Bytes()
	// Truncate right before the second chunk finishes, keeping only the first valid chunk
	// Header (33B for V2) + Frame 1 (5B header + 64 KiB ciphertext + 16B tag)
	firstChunkFrameLen := FileHeaderSizeV2 + 5 + FileChunkSize + 16
	truncated := encBytes[:firstChunkFrameLen+10] // Contains 1st full chunk + partial 2nd chunk

	var decBuf bytes.Buffer
	err = fe.DecryptStream(ctx, bytes.NewReader(truncated), &decBuf)
	// Must return an error due to stream truncation
	assert.Error(t, err)
	// But first chunk was verified and written to decBuf
	assert.Equal(t, chunk1, decBuf.Bytes())

	// In contrast, DecryptFile cleans up on error and leaves no corrupt file
	tmpDir := t.TempDir()
	srcTruncatedFile := filepath.Join(tmpDir, "truncated.enc")
	dstFile := filepath.Join(tmpDir, "decrypted.txt")
	require.NoError(t, os.WriteFile(srcTruncatedFile, truncated, 0o600))

	err = fe.DecryptFile(ctx, srcTruncatedFile, dstFile)
	assert.Error(t, err)
	// Target file must NOT exist (atomic cleanup)
	_, statErr := os.Stat(dstFile)
	assert.True(t, os.IsNotExist(statErr))
}

func TestFileEncryptor_V2AndV1BackwardCompatibility(t *testing.T) {
	ctx := context.Background()
	key, err := GenerateRandomBytes(32)
	require.NoError(t, err)

	fe, err := NewFileEncryptor(key)
	require.NoError(t, err)

	testData := []byte("Testing backward compatibility across V1 and V2 file streaming formats")

	// 1. Encrypt with FileVersionV1
	feV1, err := NewFileEncryptor(key)
	require.NoError(t, err)
	require.NoError(t, feV1.SetVersion(FileVersionV1))

	var v1Buf bytes.Buffer
	require.NoError(t, feV1.EncryptStream(ctx, bytes.NewReader(testData), &v1Buf))
	v1Bytes := v1Buf.Bytes()

	// Verify V1 header: 17 bytes, version 0x01
	assert.Equal(t, FileMagic, string(v1Bytes[:4]))
	assert.Equal(t, FileVersionV1, v1Bytes[4])
	assert.True(t, len(v1Bytes) >= FileHeaderSizeV1)

	// Decrypt V1 stream with default V2 encryptor (seamless backward compatibility)
	var decV1Buf bytes.Buffer
	require.NoError(t, fe.DecryptStream(ctx, bytes.NewReader(v1Bytes), &decV1Buf))
	assert.Equal(t, testData, decV1Buf.Bytes())

	// 2. Encrypt with FileVersionV2 (default)
	var v2Buf bytes.Buffer
	require.NoError(t, fe.EncryptStream(ctx, bytes.NewReader(testData), &v2Buf))
	v2Bytes := v2Buf.Bytes()

	// Verify V2 header: 33 bytes, version 0x02
	assert.Equal(t, FileMagic, string(v2Bytes[:4]))
	assert.Equal(t, FileVersionV2, v2Bytes[4])
	assert.True(t, len(v2Bytes) >= FileHeaderSizeV2)

	// Decrypt V2 stream
	var decV2Buf bytes.Buffer
	require.NoError(t, fe.DecryptStream(ctx, bytes.NewReader(v2Bytes), &decV2Buf))
	assert.Equal(t, testData, decV2Buf.Bytes())
}

func TestFileEncryptor_SaltUniquenessAndKeyIsolation(t *testing.T) {
	ctx := context.Background()
	key, err := GenerateRandomBytes(32)
	require.NoError(t, err)

	fe, err := NewFileEncryptor(key)
	require.NoError(t, err)

	testData := []byte("Identical payload encrypted multiple times must have isolated keys and salts")

	salts := make(map[string]bool)
	ciphertexts := make(map[string]bool)

	for i := 0; i < 20; i++ {
		var buf bytes.Buffer
		require.NoError(t, fe.EncryptStream(ctx, bytes.NewReader(testData), &buf))
		cBytes := buf.Bytes()

		require.True(t, len(cBytes) >= FileHeaderSizeV2)
		salt := string(cBytes[5:21])
		assert.False(t, salts[salt], "HKDF salt must be unique across all streams")
		salts[salt] = true

		cStr := string(cBytes)
		assert.False(t, ciphertexts[cStr], "Ciphertext must be unique even for identical input payloads")
		ciphertexts[cStr] = true
	}
}

func TestFileEncryptor_TamperAndDowngradeDetection(t *testing.T) {
	ctx := context.Background()
	key, err := GenerateRandomBytes(32)
	require.NoError(t, err)

	fe, err := NewFileEncryptor(key)
	require.NoError(t, err)

	testData := []byte("Tampering verification payload")
	var encBuf bytes.Buffer
	require.NoError(t, fe.EncryptStream(ctx, bytes.NewReader(testData), &encBuf))
	encBytes := encBuf.Bytes()

	// 1. Version downgrade attack: modify version 0x02 -> 0x01
	downgrade := append([]byte(nil), encBytes...)
	downgrade[4] = FileVersionV1
	var decBuf bytes.Buffer
	err = fe.DecryptStream(ctx, bytes.NewReader(downgrade), &decBuf)
	assert.Error(t, err, "Downgrade attack from V2 to V1 must fail authentication")

	// 2. Unsupported version
	unsupported := append([]byte(nil), encBytes...)
	unsupported[4] = 0x03
	err = fe.DecryptStream(ctx, bytes.NewReader(unsupported), &decBuf)
	assert.Error(t, err, "Unsupported version must return an error")

	// 3. Corrupted salt in V2 header
	corruptSalt := append([]byte(nil), encBytes...)
	corruptSalt[10] ^= 0xFF
	err = fe.DecryptStream(ctx, bytes.NewReader(corruptSalt), &decBuf)
	assert.Error(t, err, "Corrupted salt must fail HKDF subkey authentication")

	// 4. Corrupted base nonce in V2 header
	corruptNonce := append([]byte(nil), encBytes...)
	corruptNonce[25] ^= 0xFF
	err = fe.DecryptStream(ctx, bytes.NewReader(corruptNonce), &decBuf)
	assert.Error(t, err, "Corrupted base nonce must fail AEAD authentication")
}

func TestFileEncryptor_ZeroAndSetVersion(t *testing.T) {
	key, err := GenerateRandomBytes(32)
	require.NoError(t, err)

	fe, err := NewFileEncryptor(key)
	require.NoError(t, err)

	// Invalid version
	assert.Error(t, fe.SetVersion(0x99))

	// BlockProvider encryptor cannot use V2
	gcmCipher, err := NewAESGCMCipher(key)
	require.NoError(t, err)
	feFromBlock, err := NewAESFileEncryptor(gcmCipher)
	require.NoError(t, err)
	assert.Error(t, feFromBlock.SetVersion(FileVersionV2))

	// fe.Zero() wipes master key
	fe.Zero()
	var encBuf bytes.Buffer
	err = fe.EncryptStream(context.Background(), bytes.NewReader([]byte("test")), &encBuf)
	assert.Error(t, err, "Encrypting V2 stream after Zero() must return error")
}

func TestKeyManager_Argon2id(t *testing.T) {
	km := NewKeyManager()
	pwd := []byte("SensitivePassword!2026")
	salt := []byte("argon2-salt-16b!")

	// 1. DeriveKeyArgon2idFromBytes
	key1, err := km.DeriveKeyArgon2idFromBytes(pwd, salt)
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	// Consistency with string helper
	key2, err := km.DeriveKeyArgon2id(string(pwd), salt)
	require.NoError(t, err)
	assert.Equal(t, key1, key2)

	// 2. DeriveKeyArgon2idWithNewSaltFromBytes
	key3, newSalt, err := km.DeriveKeyArgon2idWithNewSaltFromBytes(pwd)
	require.NoError(t, err)
	assert.Len(t, key3, 32)
	assert.Len(t, newSalt, 16)

	// Re-deriving with returned newSalt must yield identical key
	key4, err := km.DeriveKeyArgon2idFromBytes(pwd, newSalt)
	require.NoError(t, err)
	assert.Equal(t, key3, key4)

	// String helper for new salt
	keyStr, saltStr, err := km.DeriveKeyArgon2idWithNewSalt(string(pwd))
	require.NoError(t, err)
	assert.Len(t, keyStr, 32)
	assert.Len(t, saltStr, 16)

	// 3. Error cases: empty salt, oversized salt
	_, err = km.DeriveKeyArgon2idFromBytes(pwd, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "salt cannot be empty")

	oversizedSalt := make([]byte, MaxArgon2MaterialLen+1)
	_, err = km.DeriveKeyArgon2idFromBytes(pwd, oversizedSalt)
	assert.Error(t, err)

	// 4. Custom Argon2 parameters constructor
	customKM, err := NewKeyManagerWithArgon2Params(16, 16*1024, 2, 2, 32)
	require.NoError(t, err)
	require.NotNil(t, customKM)

	customKey, err := customKM.DeriveKeyArgon2idFromBytes(pwd, salt)
	require.NoError(t, err)
	assert.Len(t, customKey, 32)

	// Invalid param boundaries
	_, err = NewKeyManagerWithArgon2Params(16, MinArgon2Memory-1, 2, 2, 32)
	assert.Error(t, err)
	_, err = NewKeyManagerWithArgon2Params(16, MaxArgon2Memory+1, 2, 2, 32)
	assert.Error(t, err)
	_, err = NewKeyManagerWithArgon2Params(16, 64*1024, 0, 2, 32)
	assert.Error(t, err)
	_, err = NewKeyManagerWithArgon2Params(16, 64*1024, MaxArgon2Time+1, 2, 32)
	assert.Error(t, err)
	_, err = NewKeyManagerWithArgon2Params(16, 64*1024, 2, 0, 32)
	assert.Error(t, err)
	_, err = NewKeyManagerWithArgon2Params(16, 64*1024, 2, MaxArgon2Threads+1, 32)
	assert.Error(t, err)
	_, err = NewKeyManagerWithArgon2Params(16, 64*1024, 2, 2, 10)
	assert.Error(t, err)
	_, err = NewKeyManagerWithArgon2Params(4, 64*1024, 2, 2, 32)
	assert.Error(t, err)

	// 5. Package-level helper
	pkgKey, err := DeriveKeyArgon2id(pwd, salt, 16*1024, 1, 1, 32)
	require.NoError(t, err)
	assert.Len(t, pkgKey, 32)

	_, err = DeriveKeyArgon2id(pwd, nil, 16*1024, 1, 1, 32)
	assert.Error(t, err)
}

func TestGenerateRandomAlphanumeric_Optimized(t *testing.T) {
	// Length 0
	str0, err := GenerateRandomAlphanumeric(0)
	require.NoError(t, err)
	assert.Empty(t, str0)

	// Negative length
	_, err = GenerateRandomAlphanumeric(-5)
	assert.Error(t, err)

	// Various lengths
	for _, l := range []int{1, 5, 16, 32, 64, 128, 512, 1024} {
		s, err := GenerateRandomAlphanumeric(l)
		require.NoError(t, err)
		assert.Equal(t, l, len(s))

		// Ensure all runes are in alphanumericCharset
		for _, ch := range s {
			assert.True(t, strings.ContainsRune(alphanumericCharset, ch), "character %c not in alphanumeric charset", ch)
		}
	}

	// Uniqueness across consecutive calls
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := GenerateRandomAlphanumeric(16)
		require.NoError(t, err)
		assert.False(t, seen[s], "collision detected in random alphanumeric string")
		seen[s] = true
	}
}

func BenchmarkGenerateRandomAlphanumeric(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := GenerateRandomAlphanumeric(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestVerifyString_AmbiguityAndStrict(t *testing.T) {
	hasher := NewSHA256Hasher()
	plaintext := "GrainSecurePasswordValidation2026"

	// SHA-256 hash in hex (64 chars) and base64
	hexDigest, err := hasher.HashHex(plaintext)
	require.NoError(t, err)
	assert.Len(t, hexDigest, 64)

	b64Digest, err := hasher.HashBase64(plaintext)
	require.NoError(t, err)

	// 1. VerifyString with hex digest
	validHex, err := VerifyString(hasher, plaintext, hexDigest)
	require.NoError(t, err)
	assert.True(t, validHex)

	// 2. VerifyString with wrong password on 64-char hex
	// Must return false without falling through to base64 decoding error
	invalidHex, err := VerifyString(hasher, "WrongPassword", hexDigest)
	require.NoError(t, err)
	assert.False(t, invalidHex)

	// 3. VerifyString with Base64 digest
	validB64, err := VerifyString(hasher, plaintext, b64Digest)
	require.NoError(t, err)
	assert.True(t, validB64)

	// 4. VerifyString with unpadded Base64
	rawB64 := strings.TrimRight(b64Digest, "=")
	validRawB64, err := VerifyString(hasher, plaintext, rawB64)
	require.NoError(t, err)
	assert.True(t, validRawB64)

	// 5. Strict methods
	validStrictHex, err := VerifyHex(hasher, plaintext, hexDigest)
	require.NoError(t, err)
	assert.True(t, validStrictHex)

	validStrictB64, err := VerifyBase64(hasher, plaintext, b64Digest)
	require.NoError(t, err)
	assert.True(t, validStrictB64)

	// 6. PHC strings (Argon2id and Scrypt)
	argonHasher := NewArgon2idHasher()
	phcHash, err := HashString(argonHasher, plaintext)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(phcHash, "$argon2id$"))

	validPHC, err := VerifyString(argonHasher, plaintext, phcHash)
	require.NoError(t, err)
	assert.True(t, validPHC)

	// 7. Error handling: nil hasher, empty string, invalid encoding
	_, err = VerifyString(nil, plaintext, hexDigest)
	assert.Error(t, err)

	_, err = VerifyString(hasher, plaintext, "   ")
	assert.Error(t, err)

	_, err = VerifyString(hasher, plaintext, "!!!not-valid-hex-or-base64???")
	assert.Error(t, err)
}
