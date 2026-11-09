package cryptoutil

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"emperror.dev/errors"
)

// SHA512Hasher implements Hasher for SHA-512.
type SHA512Hasher struct{}

// NewSHA512Hasher creates a SHA512Hasher instance.
func NewSHA512Hasher() *SHA512Hasher {
	return &SHA512Hasher{}
}

// Hash computes the SHA-512 digest of input data.
func (h *SHA512Hasher) Hash(data []byte) ([]byte, error) {
	digest := sha512.Sum512(data)
	return digest[:], nil
}

// Verify checks whether data matches the expected SHA-512 digest bytes in constant time.
func (h *SHA512Hasher) Verify(data, expectedHash []byte) (bool, error) {
	actualHash, err := h.Hash(data)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

// HashString computes the SHA-512 digest and returns a lower-case hexadecimal string.
func (h *SHA512Hasher) HashString(data string) (string, error) {
	return h.HashHex(data)
}

// HashHex computes the SHA-512 digest and returns a lower-case hexadecimal string.
func (h *SHA512Hasher) HashHex(data string) (string, error) {
	digest, err := h.Hash([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

// HashBase64 computes the SHA-512 digest and returns a standard base64 string.
func (h *SHA512Hasher) HashBase64(data string) (string, error) {
	digest, err := h.Hash([]byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(digest), nil
}

// VerifyString checks whether data matches a hex-encoded SHA-512 string (case-insensitive).
func (h *SHA512Hasher) VerifyString(data, expectedHex string) (bool, error) {
	return h.VerifyHex(data, expectedHex)
}

// VerifyHex checks whether data matches a hex-encoded SHA-512 string (case-insensitive).
func (h *SHA512Hasher) VerifyHex(data, expectedHex string) (bool, error) {
	expectedBytes, err := hex.DecodeString(strings.TrimSpace(expectedHex))
	if err != nil {
		return false, errors.WrapIf(err, "invalid hex format in expected hash")
	}
	return h.Verify([]byte(data), expectedBytes)
}

// VerifyBase64 checks whether data matches a base64-encoded SHA-512 string.
func (h *SHA512Hasher) VerifyBase64(data, expectedBase64 string) (bool, error) {
	expectedBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(expectedBase64))
	if err != nil {
		expectedBytes, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(expectedBase64))
		if err != nil {
			return false, errors.WrapIf(err, "invalid base64 format in expected hash")
		}
	}
	return h.Verify([]byte(data), expectedBytes)
}
