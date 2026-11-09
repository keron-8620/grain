package cryptoutil

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

// Test XChaCha20-Poly1305 key size validation
func TestXChaCha20Poly1305_KeySize(t *testing.T) {
	// Valid 32-byte key
	validKey := make([]byte, 32)
	cipher, err := NewXChaCha20Poly1305Cipher(validKey)
	require.NoError(t, err)
	assert.NotNil(t, cipher)
	assert.Equal(t, chacha20poly1305.NonceSizeX, cipher.AEAD().NonceSize())
	assert.Equal(t, chacha20poly1305.Overhead, cipher.AEAD().Overhead())

	// Invalid key sizes
	invalidSizes := []int{0, 15, 16, 24, 31, 33, 64}
	for _, sz := range invalidSizes {
		key := make([]byte, sz)
		_, err := NewXChaCha20Poly1305Cipher(key)
		assert.Error(t, err, "key size %d should fail", sz)
	}
}

// Test XChaCha20-Poly1305 basic encryption and decryption
func TestXChaCha20Poly1305_RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cipher, err := NewXChaCha20Poly1305Cipher(key)
	require.NoError(t, err)

	// 1. Byte-level Encrypt / Decrypt
	plaintext := []byte("Hello, XChaCha20-Poly1305 extended nonce world!")
	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	// Length should be 24-byte Nonce + len(plaintext) + 16-byte Poly1305 tag
	expectedLen := chacha20poly1305.NonceSizeX + len(plaintext) + chacha20poly1305.Overhead
	assert.Equal(t, expectedLen, len(ciphertext))

	decrypted, err := cipher.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 2. String-level EncryptString / DecryptString
	text := "Confidential token payload: 2026-XCHACHA"
	b64Cipher, err := cipher.EncryptString(text)
	require.NoError(t, err)
	assert.True(t, IsValidBase64(b64Cipher))

	plainText, err := cipher.DecryptString(b64Cipher)
	require.NoError(t, err)
	assert.Equal(t, text, plainText)

	// Invalid base64 decoding error
	_, err = cipher.DecryptString("!not-valid-base64!")
	assert.Error(t, err)

	// 3. Package-level helper integration (Cipher interface)
	pHelperCipher, err := EncryptString(cipher, text)
	require.NoError(t, err)
	pHelperPlain, err := DecryptString(cipher, pHelperCipher)
	require.NoError(t, err)
	assert.Equal(t, text, pHelperPlain)
}

// Test XChaCha20-Poly1305 empty plaintext and large payload
func TestXChaCha20Poly1305_PayloadSizes(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewXChaCha20Poly1305Cipher(key)
	require.NoError(t, err)

	// Empty plaintext
	emptyPlain := []byte{}
	emptyCipher, err := cipher.Encrypt(emptyPlain)
	require.NoError(t, err)
	assert.Equal(t, chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead, len(emptyCipher)) // 24 + 16 = 40 bytes

	decryptedEmpty, err := cipher.Decrypt(emptyCipher)
	require.NoError(t, err)
	assert.Empty(t, decryptedEmpty)

	// Large payload (128 KiB)
	largePlain := bytes.Repeat([]byte("XChaCha20Poly1305BlockData!"), 5000)
	largeCipher, err := cipher.Encrypt(largePlain)
	require.NoError(t, err)

	decryptedLarge, err := cipher.Decrypt(largeCipher)
	require.NoError(t, err)
	assert.Equal(t, largePlain, decryptedLarge)
}

// Test XChaCha20-Poly1305 AAD authentication
func TestXChaCha20Poly1305_AAD(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewXChaCha20Poly1305Cipher(key)
	require.NoError(t, err)

	plaintext := []byte("Sensitive transaction amount: $500,000")
	aad := []byte("account_id:1001,currency:USD")

	// Encrypt with AAD
	ciphertext, err := cipher.EncryptWithAAD(plaintext, aad)
	require.NoError(t, err)

	// Decrypt with correct AAD -> Success
	decrypted, err := cipher.DecryptWithAAD(ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Decrypt with tampered AAD -> Error
	tamperedAAD := []byte("account_id:1002,currency:USD")
	_, err = cipher.DecryptWithAAD(ciphertext, tamperedAAD)
	assert.Error(t, err)

	// Decrypt with nil AAD when encrypted with AAD -> Error
	_, err = cipher.DecryptWithAAD(ciphertext, nil)
	assert.Error(t, err)

	// Encrypt with nil AAD, decrypt with non-nil AAD -> Error
	noAADCiphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)
	_, err = cipher.DecryptWithAAD(noAADCiphertext, aad)
	assert.Error(t, err)
}

// Test XChaCha20-Poly1305 cross-instance decryption and key isolation
func TestXChaCha20Poly1305_CrossInstanceAndKeyIsolation(t *testing.T) {
	keyA := []byte("key-A-32bytes-0123456789abcdef01")
	keyB := []byte("key-B-32bytes-0123456789abcdef02")

	instanceA1, err := NewXChaCha20Poly1305Cipher(keyA)
	require.NoError(t, err)
	instanceA2, err := NewXChaCha20Poly1305Cipher(keyA)
	require.NoError(t, err)
	instanceB, err := NewXChaCha20Poly1305Cipher(keyB)
	require.NoError(t, err)

	payload := []byte("Inter-service encrypted token payload")

	// Instance A1 encrypts, Instance A2 decrypts
	ctA, err := instanceA1.Encrypt(payload)
	require.NoError(t, err)

	decryptedA2, err := instanceA2.Decrypt(ctA)
	require.NoError(t, err)
	assert.Equal(t, payload, decryptedA2)

	// Instance B cannot decrypt ciphertext from Key A
	_, err = instanceB.Decrypt(ctA)
	assert.Error(t, err)
}

// Test XChaCha20-Poly1305 tamper resistance and truncation
func TestXChaCha20Poly1305_TamperAndTruncation(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewXChaCha20Poly1305Cipher(key)
	require.NoError(t, err)

	plaintext := []byte("Integrity verification payload")
	ciphertext, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	// 1. Bit flip in Nonce (bytes 0..23)
	tamperedNonce := make([]byte, len(ciphertext))
	copy(tamperedNonce, ciphertext)
	tamperedNonce[5] ^= 0x01
	_, err = cipher.Decrypt(tamperedNonce)
	assert.Error(t, err)

	// 2. Bit flip in Ciphertext payload (bytes 24..len-16)
	tamperedPayload := make([]byte, len(ciphertext))
	copy(tamperedPayload, ciphertext)
	tamperedPayload[26] ^= 0x01
	_, err = cipher.Decrypt(tamperedPayload)
	assert.Error(t, err)

	// 3. Bit flip in Poly1305 Tag (last 16 bytes)
	tamperedTag := make([]byte, len(ciphertext))
	copy(tamperedTag, ciphertext)
	tamperedTag[len(tamperedTag)-1] ^= 0x01
	_, err = cipher.Decrypt(tamperedTag)
	assert.Error(t, err)

	// 4. Truncation checks (< 40 bytes)
	minLen := chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead // 40
	shortLengths := []int{0, 10, 24, 39}
	for _, l := range shortLengths {
		shortCT := ciphertext[:l]
		_, err := cipher.Decrypt(shortCT)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	}

	// 5. Truncating one byte of valid tag
	truncatedTag := ciphertext[:len(ciphertext)-1]
	if len(truncatedTag) >= minLen {
		_, err := cipher.Decrypt(truncatedTag)
		assert.Error(t, err)
	}
}

// Test XChaCha20-Poly1305 192-bit Nonce uniqueness across 500 iterations
func TestXChaCha20Poly1305_NonceUniqueness(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, err := NewXChaCha20Poly1305Cipher(key)
	require.NoError(t, err)

	plaintext := []byte("Static payload testing random 192-bit nonce distribution")
	seenNonces := make(map[string]bool)
	seenCiphertexts := make(map[string]bool)

	for range 500 {
		ct, err := cipher.Encrypt(plaintext)
		require.NoError(t, err)

		nonceHex := hex.EncodeToString(ct[:chacha20poly1305.NonceSizeX])
		ctHex := hex.EncodeToString(ct)

		assert.False(t, seenNonces[nonceHex], "Nonce collision detected!")
		assert.False(t, seenCiphertexts[ctHex], "Ciphertext collision detected!")

		seenNonces[nonceHex] = true
		seenCiphertexts[ctHex] = true
	}
}
