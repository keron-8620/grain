package cryptoutil

import (
	"context"

	"emperror.dev/errors"
	"golang.org/x/crypto/bcrypt"
)

// BcryptHasher bcrypt hash implementation
type BcryptHasher struct {
	cost int
}

func NewBcryptHasher(cost int) Hasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

func (h *BcryptHasher) Hash(ctx context.Context, data string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(data), h.cost)
	if err != nil {
		return "", errors.WrapIf(err, "failed to generate bcrypt hash")
	}
	return string(hashed), nil
}

func (h *BcryptHasher) Verify(ctx context.Context, data, hash string) (bool, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return false, errors.WrapIf(ctx.Err(), "context cancelled")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(data))
	if err != nil {
		return false, nil
	}
	return true, nil
}
