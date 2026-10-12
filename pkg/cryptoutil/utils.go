package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"

	"emperror.dev/errors"
)

// GenerateRandomBytes generates random bytes of the specified length
func GenerateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random bytes")
	}
	return b, nil
}

// GenerateRandomString generates a random string of the specified length (base64 encoded)
func GenerateRandomString(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateRandomHex generates a random hexadecimal string of the specified length
func GenerateRandomHex(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateRandomInt generates a random integer in the specified range [min, max]
func GenerateRandomInt(min, max int64) (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return 0, errors.WrapIf(err, "failed to generate random integer")
	}
	return n.Int64() + min, nil
}

// EncodeBase64 encodes byte data to a base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a base64 string to byte data
func DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// EncodeHex encodes byte data to a hexadecimal string
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex decodes a hexadecimal string to byte data
func DecodeHex(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

// IsValidBase64 checks whether the string is valid base64 encoded
func IsValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// IsValidHex checks whether the string is valid hexadecimal encoded
func IsValidHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// PadRight pads the string on the right with the specified byte up to length
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

// PadLeft pads the string on the left with the specified byte up to length
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

// TruncateString truncates a string to the specified length
func TruncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}

// SafeEqual compares two strings in constant time (prevents timing attacks)
func SafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i] ^ b[i])
	}
	return result == 0
}
