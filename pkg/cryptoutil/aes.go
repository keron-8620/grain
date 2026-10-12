package cryptoutil

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"emperror.dev/errors"
)

type aesCipher struct {
	block cipher.Block
	key   []byte
	iv    []byte
	BaseCipher
}

// NewAESCipher creates an AES cipher instance
func NewAESCipher(key []byte, iv ...[]byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create AES cipher")
	}
	// Set IV, generate random IV by default
	actualIV := make([]byte, aes.BlockSize)
	if len(iv) > 0 && len(iv[0]) == aes.BlockSize {
		copy(actualIV, iv[0])
	} else {
		// Generate random IV
		if _, err := rand.Read(actualIV); err != nil {
			return nil, errors.WrapIf(err, "failed to generate random IV")
		}
	}

	return &aesCipher{
		block: block,
		key:   key,
		iv:    actualIV,
	}, nil
}

// Encrypt encrypts data, takes a plaintext string and returns the encrypted string
func (a *aesCipher) Encrypt(ctx context.Context, plaintext string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	plainBytes := []byte(plaintext)

	// Apply PKCS7 padding
	blockSize := a.block.BlockSize()
	plainBytes = pkcs7Padding(plainBytes, blockSize)

	// CBC mode encryption
	ciphertext := make([]byte, len(plainBytes))

	// Create encrypter
	mode := cipher.NewCBCEncrypter(a.block, a.iv)
	mode.CryptBlocks(ciphertext, plainBytes)

	// Encode encrypted result to base64 string
	return a.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data, takes an encrypted string and returns the decrypted string
func (a *aesCipher) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	// Decode base64 string
	cipherBytes, err := a.DecodeString(ciphertext)
	if err != nil {
		return "", errors.WrapIf(err, "failed to decode base64 for AES decryption")
	}

	// CBC mode decryption
	blockSize := a.block.BlockSize()
	if len(cipherBytes)%blockSize != 0 {
		return "", errors.Errorf("ciphertext is not a multiple of block size: %d", len(cipherBytes))
	}

	plainBytes := make([]byte, len(cipherBytes))

	mode := cipher.NewCBCDecrypter(a.block, a.iv)
	mode.CryptBlocks(plainBytes, cipherBytes)

	// Remove PKCS7 padding
	plainBytes, err = pkcs7Unpadding(plainBytes)
	if err != nil {
		return "", errors.WrapIf(err, "failed to unpad PKCS7 for AES decryption")
	}

	return string(plainBytes), nil
}
