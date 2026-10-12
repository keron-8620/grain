package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"emperror.dev/errors"
	"golang.org/x/crypto/scrypt"
)

// KeyManager manages cryptographic keys
type KeyManager struct {
	saltLen int
	n       int
	r       int
	p       int
	keyLen  int
}

// NewKeyManager creates a KeyManager instance
func NewKeyManager() *KeyManager {
	return &KeyManager{
		saltLen: 16,
		n:       32768, // 2^15
		r:       8,
		p:       1,
		keyLen:  32, // Default 32-byte key (AES-256)
	}
}

// NewKeyManagerWithParams creates a KeyManager instance with custom parameters
func NewKeyManagerWithParams(saltLen, n, r, p, keyLen int) *KeyManager {
	return &KeyManager{
		saltLen: saltLen,
		n:       n,
		r:       r,
		p:       p,
		keyLen:  keyLen,
	}
}

// DeriveKey derives a key from a password
func (km *KeyManager) DeriveKey(password string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, km.saltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, errors.WrapIf(err, "failed to generate salt")
		}
	}

	key, err := scrypt.Key([]byte(password), salt, km.n, km.r, km.p, km.keyLen)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to derive key")
	}

	return key, nil
}

// GenerateRandomKey generates a random key
func (km *KeyManager) GenerateRandomKey() ([]byte, error) {
	key := make([]byte, km.keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random key")
	}
	return key, nil
}

// GenerateRandomKeyWithSize generates a random key with the specified size
func GenerateRandomKeyWithSize(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random key")
	}
	return key, nil
}

// KeyToBase64 converts a key to a base64 string
func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// KeyFromBase64 parses a key from a base64 string
func KeyFromBase64(keyStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyStr)
}

// KeyToHex converts a key to a hex string
func KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}

// KeyFromHex parses a key from a hex string
func KeyFromHex(keyStr string) ([]byte, error) {
	return hex.DecodeString(keyStr)
}

// ValidateKeySize validates whether the key size is suitable for the specified algorithm
func ValidateKeySize(key []byte, algorithm string) error {
	size := len(key)
	switch algorithm {
	case "aes":
		if size != 16 && size != 24 && size != 32 {
			return errors.Errorf("AES key size must be 16, 24, or 32 bytes, got: %d", size)
		}
	case "des":
		if size != 8 {
			return errors.Errorf("DES key size must be 8 bytes, got: %d", size)
		}
	case "sha256":
		if size != 32 {
			return errors.Errorf("SHA-256 key size must be 32 bytes, got: %d", size)
		}
	case "sha512":
		if size != 64 {
			return errors.Errorf("SHA-512 key size must be 64 bytes, got: %d", size)
		}
	default:
		return errors.Errorf("unsupported algorithm: %s", algorithm)
	}
	return nil
}
