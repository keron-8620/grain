package cryptoutil

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"emperror.dev/errors"
	"golang.org/x/crypto/scrypt"
)

// ScryptHasher scrypt hash implementation
type ScryptHasher struct {
	saltLen   int
	n         int
	r         int
	p         int
	keyLen    int
	encodeFmt string // "hex" or "base64"
}

func NewScryptHasher() Hasher {
	return &ScryptHasher{
		saltLen:   16,
		n:         32768, // 2^15
		r:         8,
		p:         1,
		keyLen:    32,
		encodeFmt: "base64",
	}
}

func NewScryptHasherWithParams(saltLen, n, r, p, keyLen int, encodeFmt string) Hasher {
	return &ScryptHasher{
		saltLen:   saltLen,
		n:         n,
		r:         r,
		p:         p,
		keyLen:    keyLen,
		encodeFmt: encodeFmt,
	}
}

func (h *ScryptHasher) Hash(ctx context.Context, data string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	// Generate random salt
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.WrapIf(err, "failed to generate salt")
	}

	// Generate hash
	hash, err := scrypt.Key([]byte(data), salt, h.n, h.r, h.p, h.keyLen)
	if err != nil {
		return "", errors.WrapIf(err, "failed to derive scrypt key")
	}

	// Combine salt and hash
	result := append(salt, hash...)

	// Encode according to specified format
	if h.encodeFmt == "hex" {
		return hex.EncodeToString(result), nil
	}
	return base64.StdEncoding.EncodeToString(result), nil
}

func (h *ScryptHasher) Verify(ctx context.Context, data, hash string) (bool, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return false, errors.WrapIf(ctx.Err(), "context cancelled")
	}

	// Decode hash
	var hashBytes []byte
	var err error

	if h.encodeFmt == "hex" {
		hashBytes, err = hex.DecodeString(hash)
	} else {
		hashBytes, err = base64.StdEncoding.DecodeString(hash)
	}

	if err != nil {
		return false, errors.WrapIf(err, "failed to decode hash")
	}

	// Extract salt and hash parts
	if len(hashBytes) <= h.saltLen {
		return false, errors.New("invalid hash format")
	}

	salt := hashBytes[:h.saltLen]
	expectedHash := hashBytes[h.saltLen:]

	// Recompute hash using the same parameters
	computedHash, err := scrypt.Key([]byte(data), salt, h.n, h.r, h.p, h.keyLen)
	if err != nil {
		return false, errors.WrapIf(err, "failed to derive scrypt key")
	}

	// Constant-time comparison to prevent timing attacks
	return SafeEqual(string(expectedHash), string(computedHash)), nil
}
