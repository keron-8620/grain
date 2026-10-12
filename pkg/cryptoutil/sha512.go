package cryptoutil

import (
	"context"
	"crypto/sha512"
	"encoding/hex"

	"emperror.dev/errors"
)

// SHA512Hasher SHA-512 hash implementation
type SHA512Hasher struct{}

func NewSHA512Hasher() Hasher {
	return &SHA512Hasher{}
}

func (h *SHA512Hasher) Hash(ctx context.Context, data string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	hash := sha512.Sum512([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

func (h *SHA512Hasher) Verify(ctx context.Context, data, hash string) (bool, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return false, errors.WrapIf(ctx.Err(), "context cancelled")
	}

	computedHash, err := h.Hash(ctx, data)
	if err != nil {
		return false, errors.WrapIf(err, "failed to verify hash")
	}
	return SafeEqual(computedHash, hash), nil
}
