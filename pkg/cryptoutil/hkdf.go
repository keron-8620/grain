package cryptoutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"

	"emperror.dev/errors"
	"golang.org/x/crypto/hkdf"
)

// HKDF derives keyLen bytes from a secret using the HMAC-based Extract-and-Expand Key
// Derivation Function (HKDF) specified in RFC 5869.
//
// Parameters:
//   - hashFunc: the HMAC hash constructor (e.g., sha256.New, sha512.New).
//   - secret: input keying material (IKM).
//   - salt: optional salt value (a non-secret random value); if nil or empty, a string of
//     hash.Size() zeros is used according to RFC 5869 Section 2.2.
//   - info: optional context and application-specific information (can be nil or empty).
//   - keyLen: length of output keying material (OKM) in bytes. Must satisfy 1 <= keyLen <= 255 * hash.Size().
func HKDF(hashFunc func() hash.Hash, secret, salt, info []byte, keyLen int) ([]byte, error) {
	if hashFunc == nil {
		return nil, errors.New("hash function cannot be nil")
	}
	h := hashFunc()
	if h == nil {
		return nil, errors.New("hash constructor returned nil")
	}
	if keyLen <= 0 {
		return nil, errors.Errorf("key length must be greater than 0, got %d", keyLen)
	}

	maxLen := 255 * h.Size()
	if keyLen > maxLen {
		return nil, errors.Errorf("requested key length %d exceeds HKDF maximum of %d bytes (255 * %d)", keyLen, maxLen, h.Size())
	}

	reader := hkdf.New(hashFunc, secret, salt, info)
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, errors.WrapIf(err, "failed to read HKDF stream")
	}

	return out, nil
}

// HKDFSHA256 performs one-shot HKDF key derivation using HMAC-SHA256 (RFC 5869).
func HKDFSHA256(secret, salt, info []byte, keyLen int) ([]byte, error) {
	return HKDF(sha256.New, secret, salt, info, keyLen)
}

// HKDFSHA512 performs one-shot HKDF key derivation using HMAC-SHA512 (RFC 5869).
func HKDFSHA512(secret, salt, info []byte, keyLen int) ([]byte, error) {
	return HKDF(sha512.New, secret, salt, info, keyLen)
}

// HKDFExtract performs the extract step of HKDF (RFC 5869 Section 2.2), returning
// a pseudorandom key (PRK) of length hash.Size().
// If salt is nil or empty, RFC 5869 mandates using a string of hash.Size() zeros.
func HKDFExtract(hashFunc func() hash.Hash, secret, salt []byte) ([]byte, error) {
	if hashFunc == nil {
		return nil, errors.New("hash function cannot be nil")
	}
	h := hashFunc()
	if h == nil {
		return nil, errors.New("hash constructor returned nil")
	}

	prk := hkdf.Extract(hashFunc, secret, salt)
	return prk, nil
}

// HKDFExpand performs the expand step of HKDF (RFC 5869 Section 2.3), expanding
// a pseudorandom key (PRK) of at least hash.Size() bytes into keyLen bytes of
// output keying material (OKM).
func HKDFExpand(hashFunc func() hash.Hash, prk, info []byte, keyLen int) ([]byte, error) {
	if hashFunc == nil {
		return nil, errors.New("hash function cannot be nil")
	}
	h := hashFunc()
	if h == nil {
		return nil, errors.New("hash constructor returned nil")
	}
	if keyLen <= 0 {
		return nil, errors.Errorf("key length must be greater than 0, got %d", keyLen)
	}

	maxLen := 255 * h.Size()
	if keyLen > maxLen {
		return nil, errors.Errorf("requested key length %d exceeds HKDF maximum of %d bytes (255 * %d)", keyLen, maxLen, h.Size())
	}

	if len(prk) < h.Size() {
		return nil, errors.Errorf("PRK length %d is less than hash size %d", len(prk), h.Size())
	}

	reader := hkdf.Expand(hashFunc, prk, info)
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, errors.WrapIf(err, "failed to read HKDF expand stream")
	}

	return out, nil
}

// HKDFExpandSHA256 expands a PRK into keyLen bytes of OKM using HMAC-SHA256.
func HKDFExpandSHA256(prk, info []byte, keyLen int) ([]byte, error) {
	return HKDFExpand(sha256.New, prk, info, keyLen)
}

// DeriveSubkeyHKDF derives an application or session subkey from a master key using HKDF-SHA256.
// If subkeyLen <= 0, 32 bytes (standard key size for AES-256 and XChaCha20-Poly1305) is derived by default.
func DeriveSubkeyHKDF(masterKey, salt, info []byte, subkeyLen int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("master key cannot be empty")
	}
	if subkeyLen <= 0 {
		subkeyLen = 32
	}
	return HKDFSHA256(masterKey, salt, info, subkeyLen)
}
