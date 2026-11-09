// Package cryptoutil provides cryptographic primitives, secure file streaming, and security utilities.
//
// Cryptographic Best Practices & Architecture Guidelines:
//
// 1. Symmetric Encryption:
//   - ALWAYS PREFER AEAD CIPHERS: AES-GCM (NewAESGCMCipher) or XChaCha20-Poly1305 (NewXChaCha20Poly1305Cipher)
//     for data at rest and in transit. Both provide Authenticated Encryption with Associated Data (AEAD),
//     ensuring both confidentiality and tamper-proof integrity.
//   - Nonce Boundary & Key Rotation (NIST SP 800-38D): With 96-bit random nonces, birthday
//     collisions become significant around 2^32 invocations under a single key. Rotate keys
//     periodically (e.g. every 90 days or after volume caps) or derive ephemeral subkeys via HKDF.
//   - High-Throughput & Stateless Environments: Use XChaCha20-Poly1305 (NewXChaCha20Poly1305Cipher).
//     Its extended 192-bit nonce permits safe random nonce generation without birthday collisions,
//     and its ARX construction guarantees constant-time execution on all CPU architectures without AES-NI.
//   - AES-CBC (NewAESCipher) should only be used when strictly required for backward
//     compatibility with legacy protocols or external systems.
//
// 2. Stream and File Encryption:
//   - ALWAYS use AESFileEncryptor (NewFileEncryptor) for files, blobs, and streams.
//     It chunks data in 64 KiB blocks using the Rogaway STREAM construction (chunk-index
//     and termination flag embedded into AAD), completely preventing chunk reordering,
//     block insertion, replay, and truncation attacks.
//   - Atomic temp-file swapping and strict 0600 file permissions are enforced by default in EncryptFile/DecryptFile.
//   - DecryptStream writes plaintext incrementally chunk-by-chunk. If the stream fails authentication
//     midway, dst retains partial plaintext. For files, always prefer DecryptFile for atomic rollback.
//
// 3. Password Hashing and Key Derivation:
//   - For Human Passwords: ALWAYS PREFER Argon2idHasher (NewArgon2idHasher) (RFC 9106 / PHC winner)
//     or ScryptHasher / BcryptHasher for storing authentication credentials. All three algorithms are
//     intentionally memory/CPU hard to thwart offline GPU/ASIC brute-force cracking.
//   - NEVER store passwords using plain digests like SHA-256 or SHA-512.
//   - For Master Secret & Session Subkey Derivation: Use HKDF (RFC 5869, HKDFSHA256, DeriveSubkeyHKDF)
//     to derive independent, cryptographically isolated subkeys for sessions, tenants, or data partitions.
//   - Use KeyManager (DeriveKeyFromBytes) for deriving cryptographic master keys from passphrases with proper salting.
//
// 4. Message Authentication and Integrity:
//   - Use HMACHasher (NewHMACHasher) with HMAC-SHA256 or HMAC-SHA512 for verifying data integrity
//     and message authenticity. Plain SHA digests without secret keys do not provide authenticity
//     and are vulnerable to length-extension attacks.
//
// 5. Memory Sanitization & Constant-Time Defense:
//   - Go strings are immutable and cannot be zeroed in memory. For maximum security, handle passwords,
//     keys, and decrypted plaintexts as []byte and wipe them immediately using ZeroBytes().
//   - ZeroBytes() applies a compiler memory barrier (runtime.KeepAlive) to prevent dead-store elimination.
//   - All hash and MAC verifications in this package employ constant-time comparisons (crypto/subtle)
//     to eliminate side-channel timing leaks.
package cryptoutil

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"emperror.dev/errors"
)

// Cipher defines the core symmetric encryption and decryption interface for byte slices.
type Cipher interface {
	// Encrypt encrypts plaintext bytes and returns the ciphertext bytes (including IV/nonce where applicable).
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext bytes and returns the original plaintext bytes.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// AEADCipher defines the authenticated symmetric cipher interface supporting Additional Authenticated Data (AAD).
type AEADCipher interface {
	Cipher

	// EncryptWithAAD encrypts plaintext bytes with additional authenticated data.
	EncryptWithAAD(plaintext, aad []byte) ([]byte, error)

	// DecryptWithAAD decrypts and authenticates ciphertext bytes with additional authenticated data.
	DecryptWithAAD(ciphertext, aad []byte) ([]byte, error)
}

// Hasher defines the contract for computing and verifying cryptographic hashes.
type Hasher interface {
	// Hash computes the hash of the input byte slice.
	Hash(data []byte) ([]byte, error)

	// Verify checks whether data matches the expected hash.
	Verify(data, hash []byte) (bool, error)
}

// EncryptString encrypts a plaintext string with the cipher and returns a base64-encoded ciphertext.
func EncryptString(c Cipher, plaintext string) (string, error) {
	if c == nil {
		return "", errors.New("cipher cannot be nil")
	}
	cipherBytes, err := c.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DecryptString decodes a base64-encoded ciphertext string and decrypts it with the cipher.
func DecryptString(c Cipher, ciphertext string) (string, error) {
	if c == nil {
		return "", errors.New("cipher cannot be nil")
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.WrapIf(err, "failed to decode base64 ciphertext")
	}
	plainBytes, err := c.Decrypt(cipherBytes)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

// HashString computes the hash of a string using hasher.
// If the hash is already in standard ASCII/PHC format (such as $scrypt$ or $2a$), it returns it as a string;
// otherwise, it returns a base64-encoded representation.
func HashString(h Hasher, data string) (string, error) {
	if h == nil {
		return "", errors.New("hasher cannot be nil")
	}
	hashBytes, err := h.Hash([]byte(data))
	if err != nil {
		return "", err
	}
	if len(hashBytes) > 0 && hashBytes[0] == '$' {
		return string(hashBytes), nil
	}
	return base64.StdEncoding.EncodeToString(hashBytes), nil
}

// HashHex computes the hash of a string and returns a lowercase hexadecimal encoded string.
func HashHex(h Hasher, data string) (string, error) {
	if h == nil {
		return "", errors.New("hasher cannot be nil")
	}
	hashBytes, err := h.Hash([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hashBytes), nil
}

// HashBase64 computes the hash of a string and returns a standard base64 encoded string.
func HashBase64(h Hasher, data string) (string, error) {
	if h == nil {
		return "", errors.New("hasher cannot be nil")
	}
	hashBytes, err := h.Hash([]byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hashBytes), nil
}

// isPureHex checks whether s contains only valid hexadecimal characters with even length.
func isPureHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

// VerifyString checks whether data matches the expected hash using heuristic encoding detection.
// It flexibly accepts PHC/Bcrypt formatted strings ($...$), hexadecimal digests, or Base64 strings.
//
// Best Practice & Strict Verification Notice:
// VerifyString is designed as a convenience helper for heterogeneous or user-supplied configuration
// inputs where the digest encoding is not known in advance. In strict, high-assurance production pipelines
// where the encoding format is predetermined by protocol, callers should ALWAYS PREFER calling
// VerifyHex or VerifyBase64 directly. This eliminates decoding ambiguity, prevents false-positive fallbacks,
// and reduces CPU overhead.
func VerifyString(h Hasher, data, hash string) (bool, error) {
	if h == nil {
		return false, errors.New("hasher cannot be nil")
	}
	trimmed := strings.TrimSpace(hash)
	if len(trimmed) == 0 {
		return false, errors.New("hash cannot be empty")
	}

	// 1. Direct formatted string (e.g. $scrypt$... or $2a$...)
	if strings.HasPrefix(trimmed, "$") {
		return h.Verify([]byte(data), []byte(trimmed))
	}

	// 2. Pure hex check (e.g. 64-character SHA-256 or 128-character SHA-512)
	pureHex := isPureHex(trimmed)
	var hexBytes []byte
	var errHex error
	if pureHex {
		hexBytes, errHex = hex.DecodeString(trimmed)
		if errHex == nil && len(hexBytes) > 0 {
			valid, err := h.Verify([]byte(data), hexBytes)
			if err == nil && valid {
				return true, nil
			}
			// If it's a standard hex digest (>= 32 hex chars / 16 bytes), do not fall through to base64
			if len(trimmed) >= 32 {
				return false, nil
			}
		}
	}

	// 3. Try Base64 decoding (standard or raw/unpadded)
	b64Bytes, errB64 := base64.StdEncoding.DecodeString(trimmed)
	if errB64 != nil {
		b64Bytes, errB64 = base64.RawStdEncoding.DecodeString(trimmed)
	}

	if errB64 == nil && len(b64Bytes) > 0 {
		valid, err := h.Verify([]byte(data), b64Bytes)
		if err == nil && valid {
			return true, nil
		}
	}

	// 4. Fallback for non-pure-hex strings that still decoded as hex
	if !pureHex {
		hexBytes, errHex = hex.DecodeString(trimmed)
		if errHex == nil && len(hexBytes) > 0 {
			valid, err := h.Verify([]byte(data), hexBytes)
			if err == nil && valid {
				return true, nil
			}
		}
	}

	if errHex != nil && errB64 != nil {
		return false, errors.WrapIf(errB64, "failed to decode hash as hex or base64")
	}

	return false, nil
}

// VerifyHex checks whether data matches a hex-encoded expected hash using hasher.
func VerifyHex(h Hasher, data, expectedHex string) (bool, error) {
	if h == nil {
		return false, errors.New("hasher cannot be nil")
	}
	hashBytes, err := hex.DecodeString(strings.TrimSpace(expectedHex))
	if err != nil {
		return false, errors.WrapIf(err, "failed to decode hex hash")
	}
	return h.Verify([]byte(data), hashBytes)
}

// VerifyBase64 checks whether data matches a base64-encoded expected hash using hasher.
func VerifyBase64(h Hasher, data, expectedBase64 string) (bool, error) {
	if h == nil {
		return false, errors.New("hasher cannot be nil")
	}
	hashBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(expectedBase64))
	if err != nil {
		hashBytes, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(expectedBase64))
		if err != nil {
			return false, errors.WrapIf(err, "failed to decode base64 hash")
		}
	}
	return h.Verify([]byte(data), hashBytes)
}

// pkcs7Padding applies PKCS#7 padding to data according to blockSize.
func pkcs7Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errors.Errorf("invalid block size: %d", blockSize)
	}
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...), nil
}

// pkcs7Unpadding validates and removes PKCS#7 padding from data in constant time.
func pkcs7Unpadding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errors.Errorf("invalid block size: %d", blockSize)
	}
	length := len(data)
	if length == 0 {
		return nil, errors.New("cannot unpad empty data")
	}
	if length%blockSize != 0 {
		return nil, errors.Errorf("data length %d is not a multiple of block size %d", length, blockSize)
	}

	padLen := int(data[length-1])

	// Constant-time range check: 1 <= padLen <= blockSize
	good := subtle.ConstantTimeLessOrEq(1, padLen) & subtle.ConstantTimeLessOrEq(padLen, blockSize)

	// Constant-time scan of the entire last block (exactly blockSize iterations unconditionally)
	lastBlock := data[length-blockSize:]
	for b := 0; b < blockSize; b++ {
		// b is the distance from the end: 0 is the last byte, blockSize-1 is the first byte of the block
		isPad := subtle.ConstantTimeLessOrEq(b+1, padLen)
		byteVal := lastBlock[blockSize-1-b]
		byteEq := subtle.ConstantTimeByteEq(byteVal, byte(padLen))
		good &= subtle.ConstantTimeSelect(isPad, byteEq, 1)
	}

	if good != 1 {
		return nil, errors.New("invalid PKCS#7 padding bytes")
	}

	return data[:length-padLen], nil
}
