package cryptoutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"emperror.dev/errors"
)

// SHA256Hasher SHA-256 hash implementation
type SHA256Hasher struct{}

func NewSHA256Hasher() Hasher {
	return &SHA256Hasher{}
}

func (h *SHA256Hasher) Hash(ctx context.Context, data string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

func (h *SHA256Hasher) Verify(ctx context.Context, data, hash string) (bool, error) {
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
