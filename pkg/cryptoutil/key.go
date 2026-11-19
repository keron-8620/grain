package cryptoutil

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"strings"

	"emperror.dev/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// KeyManager manages cryptographic keys and key derivation.
type KeyManager struct {
	saltLen int
	// Scrypt parameters
	n int
	r int
	p int
	// Derived key length
	keyLen int
	// Argon2id parameters
	argon2Memory  uint32
	argon2Time    uint32
	argon2Threads uint8
}

// NewKeyManager creates a KeyManager instance with standard default parameters (32-byte key for AES-256).
func NewKeyManager() *KeyManager {
	return &KeyManager{
		saltLen:       16,
		n:             32768, // 2^15
		r:             8,
		p:             1,
		keyLen:        32, // Default 32-byte key (AES-256)
		argon2Memory:  DefaultArgon2Memory,
		argon2Time:    DefaultArgon2Time,
		argon2Threads: DefaultArgon2Threads,
	}
}

// NewKeyManagerWithParams creates a KeyManager instance with custom scrypt parameters.
func NewKeyManagerWithParams(saltLen, n, r, p, keyLen int) *KeyManager {
	return &KeyManager{
		saltLen:       saltLen,
		n:             n,
		r:             r,
		p:             p,
		keyLen:        keyLen,
		argon2Memory:  DefaultArgon2Memory,
		argon2Time:    DefaultArgon2Time,
		argon2Threads: DefaultArgon2Threads,
	}
}

// NewKeyManagerWithArgon2Params creates a KeyManager instance with custom Argon2id parameters.
func NewKeyManagerWithArgon2Params(saltLen int, memory, time uint32, threads uint8, keyLen int) (*KeyManager, error) {
	if memory < MinArgon2Memory || memory > MaxArgon2Memory {
		return nil, errors.Errorf("argon2 memory %d KiB out of acceptable range [%d, %d]", memory, MinArgon2Memory, MaxArgon2Memory)
	}
	if time < MinArgon2Time || time > MaxArgon2Time {
		return nil, errors.Errorf("argon2 iterations %d out of acceptable range [%d, %d]", time, MinArgon2Time, MaxArgon2Time)
	}
	if threads < MinArgon2Threads || threads > MaxArgon2Threads {
		return nil, errors.Errorf("argon2 threads %d out of acceptable range [%d, %d]", threads, MinArgon2Threads, MaxArgon2Threads)
	}
	if keyLen < 16 || keyLen > MaxArgon2MaterialLen {
		return nil, errors.Errorf("key length %d out of acceptable range [16, %d]", keyLen, MaxArgon2MaterialLen)
	}
	if saltLen < 8 || saltLen > MaxArgon2MaterialLen {
		return nil, errors.Errorf("salt length %d out of acceptable range [8, %d]", saltLen, MaxArgon2MaterialLen)
	}

	return &KeyManager{
		saltLen:       saltLen,
		n:             32768,
		r:             8,
		p:             1,
		keyLen:        keyLen,
		argon2Memory:  memory,
		argon2Time:    time,
		argon2Threads: threads,
	}, nil
}

// DeriveKeyFromBytes derives a cryptographic key from a byte-slice password and an existing salt.
// Callers can pass byte slices that can be securely sanitized with ZeroBytes immediately after invocation.
// Salt must be non-empty so the derived key can be reproduced.
func (km *KeyManager) DeriveKeyFromBytes(password, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty: salt must be retained to re-derive key")
	}

	key, err := scrypt.Key(password, salt, km.n, km.r, km.p, km.keyLen)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to derive key")
	}

	return key, nil
}

// DeriveKeyWithNewSaltFromBytes generates a fresh cryptographically random salt and derives a key
// from a byte-slice password. Callers can wipe the password byte slice with ZeroBytes after invocation.
// Returns both the derived key and the generated salt.
func (km *KeyManager) DeriveKeyWithNewSaltFromBytes(password []byte) ([]byte, []byte, error) {
	salt := make([]byte, km.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, errors.WrapIf(err, "failed to generate random salt")
	}

	key, err := scrypt.Key(password, salt, km.n, km.r, km.p, km.keyLen)
	if err != nil {
		return nil, nil, errors.WrapIf(err, "failed to derive key")
	}

	return key, salt, nil
}

// DeriveKey derives a cryptographic key from a password string and an existing salt.
// Note: Go strings are immutable and cannot be wiped in memory; prefer DeriveKeyFromBytes
// when handling high-sensitivity credentials.
func (km *KeyManager) DeriveKey(password string, salt []byte) ([]byte, error) {
	return km.DeriveKeyFromBytes([]byte(password), salt)
}

// DeriveKeyWithNewSalt generates a fresh cryptographically random salt and derives a key from password.
// Note: Go strings are immutable and cannot be wiped in memory; prefer DeriveKeyWithNewSaltFromBytes
// when handling high-sensitivity credentials.
func (km *KeyManager) DeriveKeyWithNewSalt(password string) ([]byte, []byte, error) {
	return km.DeriveKeyWithNewSaltFromBytes([]byte(password))
}

// DeriveKeyArgon2idFromBytes derives a cryptographic key from a byte-slice password and an existing salt
// using Argon2id (RFC 9106 / PHC winner).
// Callers can wipe the password byte slice with ZeroBytes after invocation.
func (km *KeyManager) DeriveKeyArgon2idFromBytes(password, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty: salt must be retained to re-derive key")
	}
	if len(salt) > MaxArgon2MaterialLen {
		return nil, errors.Errorf("salt length %d exceeds maximum allowable %d bytes", len(salt), MaxArgon2MaterialLen)
	}

	if km.keyLen < 0 || km.keyLen > math.MaxUint32 {
		return nil, fmt.Errorf("keyLen overflow uint32")
	}
	key := argon2.IDKey(password, salt, km.argon2Time, km.argon2Memory, km.argon2Threads, uint32(km.keyLen))
	return key, nil
}

// DeriveKeyArgon2idWithNewSaltFromBytes generates a fresh cryptographically random salt and derives a key
// using Argon2id (RFC 9106). Callers can wipe the password byte slice with ZeroBytes after invocation.
// Returns both the derived key and the generated salt.
func (km *KeyManager) DeriveKeyArgon2idWithNewSaltFromBytes(password []byte) ([]byte, []byte, error) {
	salt := make([]byte, km.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, errors.WrapIf(err, "failed to generate random salt")
	}

	key, err := km.DeriveKeyArgon2idFromBytes(password, salt)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// DeriveKeyArgon2id derives a cryptographic key from a password string and an existing salt using Argon2id.
// Note: Go strings are immutable and cannot be wiped in memory; prefer DeriveKeyArgon2idFromBytes
// when handling high-sensitivity credentials.
func (km *KeyManager) DeriveKeyArgon2id(password string, salt []byte) ([]byte, error) {
	return km.DeriveKeyArgon2idFromBytes([]byte(password), salt)
}

// DeriveKeyArgon2idWithNewSalt generates a fresh cryptographically random salt and derives a key
// from a password string using Argon2id.
// Note: Go strings are immutable and cannot be wiped in memory; prefer DeriveKeyArgon2idWithNewSaltFromBytes
// when handling high-sensitivity credentials.
func (km *KeyManager) DeriveKeyArgon2idWithNewSalt(password string) ([]byte, []byte, error) {
	return km.DeriveKeyArgon2idWithNewSaltFromBytes([]byte(password))
}

// DeriveKeyArgon2id is a package-level helper to derive a key from password and salt with custom Argon2id parameters.
func DeriveKeyArgon2id(password, salt []byte, memory, time uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}
	return argon2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

// DeriveSubkeyHKDF derives an ephemeral subkey from a master key using HKDF-SHA256 (RFC 5869).
// If subkeyLen <= 0, KeyManager's default keyLen (32 bytes) is used.
func (km *KeyManager) DeriveSubkeyHKDF(masterKey, salt, info []byte, subkeyLen int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("master key cannot be empty")
	}
	if subkeyLen <= 0 {
		subkeyLen = km.keyLen
	}
	return HKDFSHA256(masterKey, salt, info, subkeyLen)
}

// GenerateRandomKey generates a random key of default keyLen.
func (km *KeyManager) GenerateRandomKey() ([]byte, error) {
	return GenerateRandomKeyWithSize(km.keyLen)
}

// Zero wipes a key slice from memory using ZeroBytes to prevent credential leakage.
func (km *KeyManager) Zero(key []byte) {
	ZeroBytes(key)
}

// GenerateRandomKeyWithSize generates a random key of the specified size.
func GenerateRandomKeyWithSize(size int) ([]byte, error) {
	return GenerateRandomBytes(size)
}

// KeyToBase64 converts a key to a standard base64 string.
func KeyToBase64(key []byte) string {
	return EncodeBase64(key)
}

// KeyFromBase64 parses a key from a standard base64 string.
func KeyFromBase64(keyStr string) ([]byte, error) {
	return DecodeBase64(keyStr)
}

// KeyToHex converts a key to a hex string.
func KeyToHex(key []byte) string {
	return EncodeHex(key)
}

// KeyFromHex parses a key from a hex string.
func KeyFromHex(keyStr string) ([]byte, error) {
	return DecodeHex(keyStr)
}

// ValidateKeySize validates whether the key size is suitable for the specified algorithm.
func ValidateKeySize(key []byte, algorithm string) error {
	size := len(key)
	switch strings.ToLower(algorithm) {
	case "aes":
		if size != 16 && size != 24 && size != 32 {
			return errors.Errorf("AES key size must be 16, 24, or 32 bytes, got %d", size)
		}
	case "aes-128":
		if size != 16 {
			return errors.Errorf("AES-128 key size must be exactly 16 bytes, got %d", size)
		}
	case "aes-192":
		if size != 24 {
			return errors.Errorf("AES-192 key size must be exactly 24 bytes, got %d", size)
		}
	case "aes-256":
		if size != 32 {
			return errors.Errorf("AES-256 key size must be exactly 32 bytes, got %d", size)
		}
	case "hmac", "hmac-sha256":
		if size < 16 {
			return errors.Errorf("HMAC key size too small: minimum 16 bytes recommended, got %d", size)
		}
	case "hmac-sha512":
		if size < 32 {
			return errors.Errorf("HMAC-SHA512 key size too small: minimum 32 bytes recommended, got %d", size)
		}
	case "xchacha20-poly1305", "chacha20poly1305", "xchacha20":
		if size != chacha20poly1305.KeySize {
			return errors.Errorf("XChaCha20-Poly1305 key size must be exactly %d bytes, got %d", chacha20poly1305.KeySize, size)
		}
	default:
		return errors.Errorf("unsupported algorithm: %s", algorithm)
	}
	return nil
}
