package cryptoutil

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"emperror.dev/errors"
	"golang.org/x/crypto/scrypt"
)

const (
	// MaxScryptCostN defines the maximum allowable N parameter (2^20) for scrypt verification to prevent DoS.
	MaxScryptCostN = 1 << 20
	// MaxScryptR defines the maximum allowable r parameter for scrypt verification.
	MaxScryptR = 16
	// MaxScryptP defines the maximum allowable p parameter for scrypt verification.
	MaxScryptP = 16
	// MaxScryptMaterialLen defines the maximum salt or hash byte length to prevent allocation DoS.
	MaxScryptMaterialLen = 1024
	// MaxScryptMemoryLimit defines the maximum allowable memory consumption (128 MiB) for scrypt verification.
	// Memory cost for scrypt is approximately 128 * N * r bytes.
	MaxScryptMemoryLimit int64 = 128 * 1024 * 1024
)

// ScryptHasher implements scrypt password hashing using standard PHC string format.
// Formatted hash: $scrypt$ln=<ln>,r=<r>,p=<p>$<salt-b64>$<hash-b64>
type ScryptHasher struct {
	saltLen int
	n       int
	r       int
	p       int
	keyLen  int
}

// NewScryptHasher creates a ScryptHasher with recommended defaults (N=32768, r=8, p=1, keyLen=32).
func NewScryptHasher() *ScryptHasher {
	return &ScryptHasher{
		saltLen: 16,
		n:       32768, // 2^15
		r:       8,
		p:       1,
		keyLen:  32,
	}
}

// NewScryptHasherWithParams creates a ScryptHasher with custom parameters.
func NewScryptHasherWithParams(saltLen, n, r, p, keyLen int) *ScryptHasher {
	return &ScryptHasher{
		saltLen: saltLen,
		n:       n,
		r:       r,
		p:       p,
		keyLen:  keyLen,
	}
}

// Hash hashes the input byte slice using scrypt and returns the PHC-formatted hash bytes.
// Callers can pass byte slices directly and sanitize them with ZeroBytes() immediately after use.
func (h *ScryptHasher) Hash(data []byte) ([]byte, error) {
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, errors.WrapIf(err, "failed to generate salt")
	}

	hash, err := scrypt.Key(data, salt, h.n, h.r, h.p, h.keyLen)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to derive scrypt key")
	}

	ln := int(math.Round(math.Log2(float64(h.n))))
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	phc := fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s", ln, h.r, h.p, saltB64, hashB64)
	return []byte(phc), nil
}

// Verify verifies whether byte-slice data matches the PHC-formatted hash bytes.
// Callers can pass byte slices directly and sanitize them with ZeroBytes() after use.
func (h *ScryptHasher) Verify(data, hash []byte) (bool, error) {
	return h.VerifyBytes(data, hash)
}

// HashString hashes a password string and returns a self-describing PHC string.
// Note: Go strings are immutable and cannot be zeroed in memory; prefer Hash([]byte)
// for high-sensitivity credentials.
func (h *ScryptHasher) HashString(password string) (string, error) {
	res, err := h.Hash([]byte(password))
	if err != nil {
		return "", err
	}
	return string(res), nil
}

// VerifyBytes verifies whether byte-slice data matches the formatted scrypt hash bytes.
func (h *ScryptHasher) VerifyBytes(data, hashBytes []byte) (bool, error) {
	return h.VerifyString(string(data), string(hashBytes))
}

// VerifyString checks whether a password matches the formatted scrypt hash.
// It parses n, r, p, and salt from the hash itself, allowing parameter upgrades over time.
func (h *ScryptHasher) VerifyString(password, hashStr string) (bool, error) {
	hashStr = strings.TrimSpace(hashStr)

	// Check for standard PHC format: $scrypt$ln=<ln>,r=<r>,p=<p>$<salt>$<hash>
	if strings.HasPrefix(hashStr, "$scrypt$") {
		parts := strings.Split(hashStr, "$")
		// parts: ["", "scrypt", "ln=..,r=..,p=..", "<salt>", "<hash>"]
		if len(parts) != 5 {
			return false, errors.New("invalid scrypt PHC format")
		}

		params := strings.Split(parts[2], ",")
		var n, r, p int
		for _, param := range params {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				return false, errors.Errorf("malformed scrypt parameter: %s", param)
			}
			val, err := strconv.Atoi(kv[1])
			if err != nil {
				return false, errors.WrapIf(err, "invalid parameter integer value")
			}
			switch kv[0] {
			case "ln":
				n = 1 << val
			case "n":
				n = val
			case "r":
				r = val
			case "p":
				p = val
			}
		}

		if n <= 1 || (n&(n-1)) != 0 || n > MaxScryptCostN || r <= 0 || r > MaxScryptR || p <= 0 || p > MaxScryptP {
			return false, errors.New("scrypt parameters exceed acceptable safety limits or are invalid")
		}

		mem := int64(128) * int64(n) * int64(r)
		if mem > MaxScryptMemoryLimit {
			return false, errors.Errorf("scrypt memory requirement (%d bytes) exceeds safety limit (%d bytes)", mem, MaxScryptMemoryLimit)
		}

		salt, err := base64.RawStdEncoding.DecodeString(parts[3])
		if err != nil {
			// Fallback to standard base64 if padded
			salt, err = base64.StdEncoding.DecodeString(parts[3])
			if err != nil {
				return false, errors.WrapIf(err, "failed to decode scrypt salt")
			}
		}

		expectedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
		if err != nil {
			expectedHash, err = base64.StdEncoding.DecodeString(parts[4])
			if err != nil {
				return false, errors.WrapIf(err, "failed to decode scrypt hash")
			}
		}

		if len(salt) == 0 || len(salt) > MaxScryptMaterialLen || len(expectedHash) == 0 || len(expectedHash) > MaxScryptMaterialLen {
			return false, errors.New("scrypt salt or hash length is invalid or exceeds safety limits")
		}

		derived, err := scrypt.Key([]byte(password), salt, n, r, p, len(expectedHash))
		if err != nil {
			return false, errors.WrapIf(err, "failed to derive scrypt key during verification")
		}

		return subtle.ConstantTimeCompare(derived, expectedHash) == 1, nil
	}

	// Legacy format fallback: base64(salt || hash)
	hashBytes, err := base64.StdEncoding.DecodeString(hashStr)
	if err != nil {
		return false, errors.WrapIf(err, "failed to decode hash")
	}

	if len(hashBytes) <= h.saltLen || len(hashBytes) > MaxScryptMaterialLen*2 {
		return false, errors.New("invalid hash length for legacy format")
	}

	salt := hashBytes[:h.saltLen]
	expectedHash := hashBytes[h.saltLen:]

	computed, err := scrypt.Key([]byte(password), salt, h.n, h.r, h.p, len(expectedHash))
	if err != nil {
		return false, errors.WrapIf(err, "failed to derive scrypt key")
	}

	return subtle.ConstantTimeCompare(computed, expectedHash) == 1, nil
}
