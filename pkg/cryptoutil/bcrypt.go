package cryptoutil

import (
	"emperror.dev/errors"
	"golang.org/x/crypto/bcrypt"
)

// BcryptHasher implements password hashing using bcrypt.
//
// Memory Sanitization Note:
// Go strings are immutable and cannot be safely wiped from memory. For sensitive credentials,
// prefer using Hash([]byte) and Verify([]byte, []byte), wiping the password byte slice with
// ZeroBytes() immediately after use.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a BcryptHasher instance with the specified cost (defaults to bcrypt.DefaultCost if 0).
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

// Hash hashes the input byte slice using bcrypt.
func (h *BcryptHasher) Hash(data []byte) ([]byte, error) {
	hashed, err := bcrypt.GenerateFromPassword(data, h.cost)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to generate bcrypt hash")
	}
	return hashed, nil
}

// Verify checks whether data matches the bcrypt hash.
func (h *BcryptHasher) Verify(data, hash []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hash, data)
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, errors.WrapIf(err, "invalid bcrypt hash format")
	}
	return true, nil
}

// HashString hashes a password string using bcrypt.
func (h *BcryptHasher) HashString(password string) (string, error) {
	hashed, err := h.Hash([]byte(password))
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// VerifyString checks whether a password string matches a bcrypt hash string.
func (h *BcryptHasher) VerifyString(password, hash string) (bool, error) {
	return h.Verify([]byte(password), []byte(hash))
}
