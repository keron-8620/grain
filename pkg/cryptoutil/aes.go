package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"emperror.dev/errors"
)

// AESCBCCipher implements the Cipher interface using AES in CBC mode with PKCS#7 padding.
// Ciphertexts prepend a randomly generated 16-byte initialization vector (IV): [IV(16 bytes)][Ciphertext].
type AESCBCCipher struct {
	block cipher.Block
}

var _ Cipher = (*AESCBCCipher)(nil)

// NewAESCipher creates a new AES-CBC cipher instance. Key size must be 16, 24, or 32 bytes (AES-128, AES-192, or AES-256).
func NewAESCipher(key []byte) (*AESCBCCipher, error) {
	if err := ValidateKeySize(key, "aes"); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create AES cipher")
	}

	return &AESCBCCipher{
		block: block,
	}, nil
}

// Block returns the underlying AES block cipher.
func (a *AESCBCCipher) Block() cipher.Block {
	return a.block
}

// Encrypt encrypts plaintext bytes using AES-CBC with a freshly generated random IV and PKCS#7 padding.
// The returned ciphertext format is: [16-byte IV][CBC-encrypted blocks].
func (a *AESCBCCipher) Encrypt(plaintext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random IV")
	}
	return a.EncryptWithIV(plaintext, iv)
}

// EncryptWithIV encrypts plaintext bytes using the provided 16-byte IV.
// The returned ciphertext format is: [16-byte IV][CBC-encrypted blocks].
func (a *AESCBCCipher) EncryptWithIV(plaintext, iv []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.Errorf("IV length must be exactly %d bytes, got %d", aes.BlockSize, len(iv))
	}

	padded, err := pkcs7Padding(plaintext, aes.BlockSize)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to pad plaintext")
	}

	out := make([]byte, aes.BlockSize+len(padded))
	copy(out[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(a.block, iv)
	mode.CryptBlocks(out[aes.BlockSize:], padded)

	return out, nil
}

// Decrypt decrypts ciphertext bytes formatted as [16-byte IV][CBC-encrypted blocks].
func (a *AESCBCCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize*2 {
		return nil, errors.Errorf("ciphertext too short: minimum length is %d bytes, got %d", aes.BlockSize*2, len(ciphertext))
	}

	payloadLen := len(ciphertext) - aes.BlockSize
	if payloadLen%aes.BlockSize != 0 {
		return nil, errors.Errorf("ciphertext payload length %d is not a multiple of block size %d", payloadLen, aes.BlockSize)
	}

	iv := ciphertext[:aes.BlockSize]
	encryptedBlocks := ciphertext[aes.BlockSize:]

	plainPadded := make([]byte, len(encryptedBlocks))
	mode := cipher.NewCBCDecrypter(a.block, iv)
	mode.CryptBlocks(plainPadded, encryptedBlocks)

	plainBytes, err := pkcs7Unpadding(plainPadded, aes.BlockSize)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to unpad PKCS#7 for AES decryption")
	}

	return plainBytes, nil
}

// EncryptString encrypts a plaintext string and returns a base64-encoded ciphertext.
func (a *AESCBCCipher) EncryptString(plaintext string) (string, error) {
	cipherBytes, err := a.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DecryptString decodes a base64-encoded ciphertext and returns the decrypted plaintext string.
func (a *AESCBCCipher) DecryptString(ciphertext string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.WrapIf(err, "failed to decode base64 for AES decryption")
	}
	plainBytes, err := a.Decrypt(cipherBytes)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}
