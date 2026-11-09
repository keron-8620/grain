package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strings"

	"emperror.dev/errors"
)

// HMACType represents the HMAC algorithm type.
type HMACType string

const (
	// HMACSHA256 represents the HMAC-SHA256 algorithm.
	HMACSHA256 HMACType = "hmac-sha256"
	// HMACSHA512 represents the HMAC-SHA512 algorithm.
	HMACSHA512 HMACType = "hmac-sha512"
)

// HMACHasher provides HMAC computing and verification.
type HMACHasher struct {
	key      []byte
	hmacType HMACType
}

// NewHMACHasher creates an HMAC hasher instance and validates key size and algorithm.
// Defaults to HMAC-SHA256 if hmacType is empty.
func NewHMACHasher(key []byte, hmacType HMACType) (*HMACHasher, error) {
	if hmacType == "" {
		hmacType = HMACSHA256
	}

	if hmacType != HMACSHA256 && hmacType != HMACSHA512 {
		return nil, errors.Errorf("unsupported HMAC algorithm: %s", hmacType)
	}

	if err := ValidateKeySize(key, string(hmacType)); err != nil {
		return nil, err
	}

	return &HMACHasher{
		key:      key,
		hmacType: hmacType,
	}, nil
}

// NewHMACHasherUnchecked creates an HMAC hasher instance without key size validation.
// Use this only when non-standard key sizes are strictly required (e.g. legacy compatibility or test vectors).
func NewHMACHasherUnchecked(key []byte, hmacType HMACType) (*HMACHasher, error) {
	if hmacType == "" {
		hmacType = HMACSHA256
	}

	if hmacType != HMACSHA256 && hmacType != HMACSHA512 {
		return nil, errors.Errorf("unsupported HMAC algorithm: %s", hmacType)
	}

	return &HMACHasher{
		key:      key,
		hmacType: hmacType,
	}, nil
}

// Hash computes the HMAC digest for input data bytes.
func (h *HMACHasher) Hash(data []byte) ([]byte, error) {
	var mac hash.Hash
	switch h.hmacType {
	case HMACSHA256:
		mac = hmac.New(sha256.New, h.key)
	case HMACSHA512:
		mac = hmac.New(sha512.New, h.key)
	default:
		return nil, errors.Errorf("unsupported HMAC algorithm: %s", h.hmacType)
	}

	mac.Write(data)
	return mac.Sum(nil), nil
}

// Verify verifies whether data matches expectedMAC using constant-time comparison (crypto/hmac.Equal).
func (h *HMACHasher) Verify(data, expectedMAC []byte) (bool, error) {
	actualMAC, err := h.Hash(data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(actualMAC, expectedMAC), nil
}

// HashString computes the HMAC digest and returns a lower-case hexadecimal string.
func (h *HMACHasher) HashString(data string) (string, error) {
	return h.HashHex(data)
}

// HashHex computes the HMAC digest and returns a lower-case hexadecimal string.
func (h *HMACHasher) HashHex(data string) (string, error) {
	mac, err := h.Hash([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac), nil
}

// HashBase64 computes the HMAC digest and returns a standard base64 string.
func (h *HMACHasher) HashBase64(data string) (string, error) {
	mac, err := h.Hash([]byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(mac), nil
}

// VerifyString verifies whether data matches expectedHexMAC (case-insensitive hex).
func (h *HMACHasher) VerifyString(data, expectedHexMAC string) (bool, error) {
	return h.VerifyHex(data, expectedHexMAC)
}

// VerifyHex verifies whether data matches expectedHexMAC (case-insensitive hex).
func (h *HMACHasher) VerifyHex(data, expectedHexMAC string) (bool, error) {
	expectedBytes, err := hex.DecodeString(strings.TrimSpace(expectedHexMAC))
	if err != nil {
		return false, errors.WrapIf(err, "invalid hex string in expected HMAC")
	}
	return h.Verify([]byte(data), expectedBytes)
}

// VerifyBase64 verifies whether data matches expectedBase64MAC.
func (h *HMACHasher) VerifyBase64(data, expectedBase64MAC string) (bool, error) {
	expectedBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(expectedBase64MAC))
	if err != nil {
		expectedBytes, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(expectedBase64MAC))
		if err != nil {
			return false, errors.WrapIf(err, "invalid base64 string in expected HMAC")
		}
	}
	return h.Verify([]byte(data), expectedBytes)
}

// GenerateHMAC is a convenience function to generate a hex-encoded HMAC.
func GenerateHMAC(data string, key []byte, hmacType HMACType) (string, error) {
	hasher, err := NewHMACHasher(key, hmacType)
	if err != nil {
		return "", err
	}
	return hasher.HashString(data)
}

// VerifyHMAC is a convenience function to verify a hex-encoded HMAC.
func VerifyHMAC(data, hash string, key []byte, hmacType HMACType) (bool, error) {
	hasher, err := NewHMACHasher(key, hmacType)
	if err != nil {
		return false, err
	}
	return hasher.VerifyString(data, hash)
}
