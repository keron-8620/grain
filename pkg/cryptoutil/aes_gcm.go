package cryptoutil

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"emperror.dev/errors"
)

// AESGCMCipher AES-GCM mode cipher
type AESGCMCipher struct {
	block cipher.Block
	key   []byte
	BaseCipher
}

// NewAESGCMCipher creates an AES-GCM cipher instance
func NewAESGCMCipher(key []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create AES cipher")
	}

	return &AESGCMCipher{
		block: block,
		key:   key,
	}, nil
}

// Encrypt encrypts data using GCM mode
func (a *AESGCMCipher) Encrypt(ctx context.Context, plaintext string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	plainBytes := []byte(plaintext)

	// Create GCM mode
	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return "", errors.WrapIf(err, "failed to create GCM mode")
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", errors.WrapIf(err, "failed to generate random nonce")
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plainBytes, nil)

	// Encode encrypted result to base64 string
	return a.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using GCM mode
func (a *AESGCMCipher) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	// Decode base64 string
	cipherBytes, err := a.DecodeString(ciphertext)
	if err != nil {
		return "", errors.WrapIf(err, "failed to decode base64 for AES-GCM decryption")
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return "", errors.WrapIf(err, "failed to create GCM mode")
	}

	// Check ciphertext length
	if len(cipherBytes) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertextBytes := cipherBytes[:gcm.NonceSize()], cipherBytes[gcm.NonceSize():]

	// Decrypt and verify
	plainBytes, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", errors.WrapIf(err, "failed to decrypt or authenticate GCM")
	}

	return string(plainBytes), nil
}
