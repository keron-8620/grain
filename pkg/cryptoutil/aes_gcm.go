package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"emperror.dev/errors"
)

// AESGCMCipher implements authenticated symmetric encryption (AEAD) using AES in Galois/Counter Mode (GCM).
// Ciphertexts prepend a randomly generated nonce: [Nonce (12 bytes)][Ciphertext][Tag (16 bytes)].
//
// Cryptographic Nonce Safety & Limits (NIST SP 800-38D):
// AES-GCM employs a 96-bit (12-byte) initialization vector (nonce). Reusing a nonce with the same key
// catastrophically destroys both confidentiality and integrity (enabling polynomial MAC key recovery).
// When generating random 96-bit nonces via crypto/rand, birthday bound collision probability reaches
// unacceptable levels (~2^-32) around 2^32 invocations.
//
// NIST SP 800-38D Section 8.3 explicitly mandates that for a given key, the total number of encryption
// operations with random 96-bit nonces SHALL NOT exceed 2^32 (approx 4.29 billion messages).
//
// Recommendations for High-Throughput & Production Deployments:
// 1. Key Rotation: Automate periodic key rotation (e.g. every 90 days or after message volume limits).
// 2. Ephemeral Subkeys: Use HKDF-SHA256 to derive distinct subkeys per session, tenant, or data partition.
// 3. Structured Nonces: If single-key throughput must exceed 2^32 messages, use deterministic counter-based
//    nonces (e.g. 32-bit instance ID + 64-bit monotonic counter) or extended-nonce algorithms (e.g. XChaCha20-Poly1305).
type AESGCMCipher struct {
	block cipher.Block
	aead  cipher.AEAD
}

var (
	_ Cipher     = (*AESGCMCipher)(nil)
	_ AEADCipher = (*AESGCMCipher)(nil)
)

// Block returns the underlying AES block cipher.
func (a *AESGCMCipher) Block() cipher.Block {
	return a.block
}

// NewAESGCMCipher creates an AES-GCM cipher instance. Key size must be 16, 24, or 32 bytes.
func NewAESGCMCipher(key []byte) (*AESGCMCipher, error) {
	if err := ValidateKeySize(key, "aes"); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create AES cipher")
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create GCM AEAD")
	}

	return &AESGCMCipher{
		block: block,
		aead:  aead,
	}, nil
}

// Encrypt encrypts plaintext bytes with GCM mode using a freshly generated random nonce.
// Returns [Nonce][Ciphertext + Tag].
func (a *AESGCMCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return a.EncryptWithAAD(plaintext, nil)
}

// EncryptWithAAD encrypts plaintext bytes with additional authenticated data (AAD).
func (a *AESGCMCipher) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random nonce")
	}
	return a.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt decrypts and authenticates ciphertext bytes.
func (a *AESGCMCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return a.DecryptWithAAD(ciphertext, nil)
}

// DecryptWithAAD decrypts and authenticates ciphertext bytes with additional authenticated data (AAD).
func (a *AESGCMCipher) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	nonceSize := a.aead.NonceSize()
	minLen := nonceSize + a.aead.Overhead()
	if len(ciphertext) < minLen {
		return nil, errors.Errorf("ciphertext too short for AES-GCM: got %d bytes, minimum is %d", len(ciphertext), minLen)
	}

	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	plainBytes, err := a.aead.Open(nil, nonce, encryptedData, aad)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to decrypt or authenticate GCM")
	}

	return plainBytes, nil
}

// EncryptString encrypts a plaintext string and returns a base64-encoded ciphertext.
func (a *AESGCMCipher) EncryptString(plaintext string) (string, error) {
	cipherBytes, err := a.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DecryptString decodes a base64-encoded ciphertext and returns the decrypted plaintext string.
func (a *AESGCMCipher) DecryptString(ciphertext string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.WrapIf(err, "failed to decode base64 for AES-GCM decryption")
	}
	plainBytes, err := a.Decrypt(cipherBytes)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}
