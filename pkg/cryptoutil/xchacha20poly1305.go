package cryptoutil

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"emperror.dev/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20Poly1305Cipher implements authenticated symmetric encryption (AEAD) using
// XChaCha20-Poly1305 with an extended 192-bit (24-byte) nonce (RFC 8439 / draft-irtf-cfrg-xchacha-01).
//
// Ciphertext wire format: [Nonce (24 bytes)][Ciphertext][Poly1305 Tag (16 bytes)].
//
// Cryptographic Advantages & Security Properties:
//  1. Extended Nonce (192-bit):
//     Standard AES-GCM and ChaCha20 employ 96-bit (12-byte) nonces. Under random generation,
//     birthday-bound collisions become non-negligible around 2^32 invocations, demanding strict
//     message caps or stateful counters (NIST SP 800-38D).
//     In contrast, XChaCha20-Poly1305's 192-bit nonce allows truly stateless, random nonce generation
//     with negligible collision probability (~2^-96 even after 2^64 encryptions under the same key).
//  2. Constant-Time by Construction:
//     ChaCha20 uses simple Add-Rotate-XOR (ARX) operations that execute in constant time across
//     all CPU architectures, making it inherently immune to software AES cache-timing side-channel attacks.
type XChaCha20Poly1305Cipher struct {
	aead cipher.AEAD
}

var (
	_ Cipher     = (*XChaCha20Poly1305Cipher)(nil)
	_ AEADCipher = (*XChaCha20Poly1305Cipher)(nil)
)

// NewXChaCha20Poly1305Cipher creates an XChaCha20-Poly1305 cipher instance.
// Key size must be exactly 32 bytes (256 bits).
func NewXChaCha20Poly1305Cipher(key []byte) (*XChaCha20Poly1305Cipher, error) {
	if err := ValidateKeySize(key, "xchacha20-poly1305"); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create XChaCha20-Poly1305 cipher")
	}

	return &XChaCha20Poly1305Cipher{
		aead: aead,
	}, nil
}

// AEAD returns the underlying cipher.AEAD instance.
func (c *XChaCha20Poly1305Cipher) AEAD() cipher.AEAD {
	return c.aead
}

// Encrypt encrypts plaintext bytes using a freshly generated random 24-byte nonce.
// Returns [24-byte Nonce][Ciphertext + 16-byte Poly1305 Tag].
func (c *XChaCha20Poly1305Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	return c.EncryptWithAAD(plaintext, nil)
}

// EncryptWithAAD encrypts plaintext bytes with additional authenticated data (AAD).
// Returns [24-byte Nonce][Ciphertext + 16-byte Poly1305 Tag].
func (c *XChaCha20Poly1305Cipher) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random nonce")
	}
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt decrypts and authenticates ciphertext bytes.
func (c *XChaCha20Poly1305Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return c.DecryptWithAAD(ciphertext, nil)
}

// DecryptWithAAD decrypts and authenticates ciphertext bytes with additional authenticated data (AAD).
func (c *XChaCha20Poly1305Cipher) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	minLen := nonceSize + c.aead.Overhead()
	if len(ciphertext) < minLen {
		return nil, errors.Errorf("ciphertext too short for XChaCha20-Poly1305: got %d bytes, minimum is %d", len(ciphertext), minLen)
	}

	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	plainBytes, err := c.aead.Open(nil, nonce, encryptedData, aad)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to decrypt or authenticate XChaCha20-Poly1305")
	}

	return plainBytes, nil
}

// EncryptString encrypts a plaintext string and returns a base64-encoded ciphertext.
func (c *XChaCha20Poly1305Cipher) EncryptString(plaintext string) (string, error) {
	cipherBytes, err := c.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DecryptString decodes a base64-encoded ciphertext and returns the decrypted plaintext string.
func (c *XChaCha20Poly1305Cipher) DecryptString(ciphertext string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.WrapIf(err, "failed to decode base64 for XChaCha20-Poly1305 decryption")
	}
	plainBytes, err := c.Decrypt(cipherBytes)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}
