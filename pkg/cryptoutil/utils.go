package cryptoutil

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"runtime"

	"emperror.dev/errors"
)

// GenerateRandomBytes generates cryptographically secure random bytes of the specified length.
func GenerateRandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.Errorf("length cannot be negative: %d", length)
	}
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random bytes")
	}
	return b, nil
}

// GenerateRandomString generates a URL-safe base64-encoded random string derived from length random bytes.
func GenerateRandomString(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateRandomHex generates a hexadecimal random string derived from length random bytes (result length is 2*length).
func GenerateRandomHex(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const alphanumericCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateRandomAlphanumeric generates an alphanumeric string of exactly length characters.
// It uses batch CSPRNG reading with unbiased rejection sampling (threshold 248 = 62 * 4)
// to eliminate modulo bias and achieve zero per-character heap allocation.
func GenerateRandomAlphanumeric(length int) (string, error) {
	if length < 0 {
		return "", errors.Errorf("length cannot be negative: %d", length)
	}
	if length == 0 {
		return "", nil
	}

	result := make([]byte, length)
	// 62 * 4 = 248. Bytes >= 248 are discarded (rejection rate 8/256 = 3.125%).
	const (
		charsetLen = byte(len(alphanumericCharset))
		maxValid   = byte(248)
	)

	// Buffer size: allocate enough random bytes so that a single ReadFull suffices in >99.9% of cases.
	bufSize := length + length/16 + 8
	buf := make([]byte, bufSize)

	written := 0
	for written < length {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return "", errors.WrapIf(err, "failed to generate random bytes")
		}
		for _, b := range buf {
			if b < maxValid {
				result[written] = alphanumericCharset[b%charsetLen]
				written++
				if written == length {
					break
				}
			}
		}
	}

	return string(result), nil
}

// GenerateRandomInt generates a cryptographically secure random integer in the range [min, max].
func GenerateRandomInt(min, max int64) (int64, error) {
	if min > max {
		return 0, errors.Errorf("min (%d) cannot be greater than max (%d)", min, max)
	}
	if min == max {
		return min, nil
	}

	// Calculate range = max - min + 1 using big.Int to prevent int64 overflow
	minBig := new(big.Int).SetInt64(min)
	maxBig := new(big.Int).SetInt64(max)
	rangeBig := new(big.Int).Sub(maxBig, minBig)
	rangeBig.Add(rangeBig, big.NewInt(1))

	n, err := rand.Int(rand.Reader, rangeBig)
	if err != nil {
		return 0, errors.WrapIf(err, "failed to generate random integer")
	}

	resBig := new(big.Int).Add(n, minBig)
	return resBig.Int64(), nil
}

// EncodeBase64 encodes byte data to a standard base64 string.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a standard base64 string to byte data.
func DecodeBase64(data string) ([]byte, error) {
	res, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to decode base64")
	}
	return res, nil
}

// EncodeHex encodes byte data to a hexadecimal string.
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex decodes a hexadecimal string to byte data.
func DecodeHex(data string) ([]byte, error) {
	res, err := hex.DecodeString(data)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to decode hex")
	}
	return res, nil
}

// IsValidBase64 checks whether the string is valid standard base64 encoded.
func IsValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// IsValidHex checks whether the string is valid hexadecimal encoded.
func IsValidHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// PadRight pads the string on the right with the specified byte up to length bytes.
func PadRight(s string, pad byte, length int) string {
	if len(s) >= length {
		return s
	}
	padding := make([]byte, length-len(s))
	for i := range padding {
		padding[i] = pad
	}
	return s + string(padding)
}

// PadLeft pads the string on the left with the specified byte up to length bytes.
func PadLeft(s string, pad byte, length int) string {
	if len(s) >= length {
		return s
	}
	padding := make([]byte, length-len(s))
	for i := range padding {
		padding[i] = pad
	}
	return string(padding) + s
}

// TruncateString safely truncates a string to at most maxRunes Unicode characters without breaking UTF-8 runes.
func TruncateString(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes])
}

// SafeEqual compares two strings in constant time using crypto/subtle to prevent timing attacks.
func SafeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SafeEqualBytes compares two byte slices in constant time using crypto/subtle to prevent timing attacks.
func SafeEqualBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ZeroBytes securely wipes a byte slice by overwriting all elements with zero.
// A memory barrier via runtime.KeepAlive is applied to prevent dead-store elimination by the compiler.
//
// Security Rationale:
// Go strings are immutable byte slices managed by the garbage collector and cannot be zeroed in memory;
// string credentials may persist across heap copies or memory dumps. Whenever handling high-sensitivity
// secrets (passwords, encryption keys, decrypted plaintexts), callers should handle them as []byte
// and wipe them immediately after use:
//
//	pwdBytes := readPassword()
//	defer cryptoutil.ZeroBytes(pwdBytes)
//	hash, err := hasher.Hash(pwdBytes)
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	if len(b) > 0 {
		runtime.KeepAlive(&b[0])
	}
}
