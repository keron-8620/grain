package cryptoutil

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	"emperror.dev/errors"
)

// HMACType represents the HMAC algorithm type
type HMACType string

const (
	// HMACSHA256 HMAC-SHA256 algorithm
	HMACSHA256 HMACType = "hmac-sha256"
	// HMACSHA512 HMAC-SHA512 algorithm
	HMACSHA512 HMACType = "hmac-sha512"
)

// HMACHasher HMAC hash implementation
type HMACHasher struct {
	key      []byte
	hmacType HMACType
}

// NewHMACHasher creates an HMAC hasher instance
func NewHMACHasher(key []byte, hmacType HMACType) *HMACHasher {
	if hmacType == "" {
		hmacType = HMACSHA256 // Default to SHA256
	}

	return &HMACHasher{
		key:      key,
		hmacType: hmacType,
	}
}

// Hash hashes data using HMAC
func (h *HMACHasher) Hash(ctx context.Context, data string) (string, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return "", errors.WrapIf(ctx.Err(), "context cancelled")
	}

	var mac []byte
	switch h.hmacType {
	case HMACSHA256:
		h := hmac.New(sha256.New, h.key)
		h.Write([]byte(data))
		mac = h.Sum(nil)
	case HMACSHA512:
		h := hmac.New(sha512.New, h.key)
		h.Write([]byte(data))
		mac = h.Sum(nil)
	default:
		return "", errors.Errorf("unsupported HMAC algorithm: %s", h.hmacType)
	}

	return hex.EncodeToString(mac), nil
}

// Verify checks whether data matches the HMAC value
func (h *HMACHasher) Verify(ctx context.Context, data, hash string) (bool, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return false, errors.WrapIf(ctx.Err(), "context cancelled")
	}

	computedHash, err := h.Hash(ctx, data)
	if err != nil {
		return false, errors.WrapIf(err, "failed to verify HMAC")
	}

	return SafeEqual(computedHash, hash), nil
}

// GenerateHMAC is a convenience function to generate an HMAC value
func GenerateHMAC(data string, key []byte, hmacType HMACType) (string, error) {
	hasher := NewHMACHasher(key, hmacType)
	return hasher.Hash(context.Background(), data)
}

// VerifyHMAC is a convenience function to verify an HMAC value
func VerifyHMAC(data, hash string, key []byte, hmacType HMACType) (bool, error) {
	hasher := NewHMACHasher(key, hmacType)
	return hasher.Verify(context.Background(), data, hash)
}
