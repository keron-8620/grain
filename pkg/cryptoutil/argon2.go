package cryptoutil

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"emperror.dev/errors"
	"golang.org/x/crypto/argon2"
)

const (
	// DefaultArgon2Memory is the default memory cost (64 MiB in KiB) recommended by RFC 9106.
	DefaultArgon2Memory uint32 = 64 * 1024
	// DefaultArgon2Time is the default iteration count recommended by RFC 9106.
	DefaultArgon2Time uint32 = 3
	// DefaultArgon2Threads is the default parallelism degree recommended by RFC 9106.
	DefaultArgon2Threads uint8 = 4
	// DefaultArgon2KeyLen is the default derived key length (32 bytes / 256 bits).
	DefaultArgon2KeyLen uint32 = 32
	// DefaultArgon2SaltLen is the default salt length (16 bytes / 128 bits).
	DefaultArgon2SaltLen int = 16

	// MaxArgon2Memory defines the maximum allowable memory cost (256 MiB in KiB) to prevent memory DoS.
	MaxArgon2Memory uint32 = 256 * 1024
	// MinArgon2Memory defines the minimum allowable memory cost (1 MiB in KiB).
	MinArgon2Memory uint32 = 1024
	// MaxArgon2Time defines the maximum allowable iterations to prevent CPU DoS.
	MaxArgon2Time uint32 = 10
	// MinArgon2Time defines the minimum allowable iteration count.
	MinArgon2Time uint32 = 1
	// MaxArgon2Threads defines the maximum allowable thread count.
	MaxArgon2Threads uint8 = 16
	// MinArgon2Threads defines the minimum allowable thread count.
	MinArgon2Threads uint8 = 1
	// MaxArgon2MaterialLen defines the maximum allowable length of salt or hash material.
	MaxArgon2MaterialLen = 1024
)

// Argon2idHasher implements password hashing using the Argon2id algorithm (RFC 9106),
// the winner of the Password Hashing Competition (PHC).
//
// Formatted hash: $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt-b64>$<hash-b64>
//
// Security & Memory Sanitization Note:
// Go strings are immutable and cannot be safely zeroed out in memory. For sensitive passwords,
// callers should prefer Hash([]byte) and Verify([]byte, []byte), wiping raw password buffers
// immediately with ZeroBytes() after invocation.
type Argon2idHasher struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
	saltLen int
}

var _ Hasher = (*Argon2idHasher)(nil)

// NewArgon2idHasher creates an Argon2idHasher instance using parameters recommended by RFC 9106:
// 64 MiB memory (m=65536), 3 iterations (t=3), 4 threads (p=4), 32-byte key, 16-byte salt.
func NewArgon2idHasher() *Argon2idHasher {
	return &Argon2idHasher{
		memory:  DefaultArgon2Memory,
		time:    DefaultArgon2Time,
		threads: DefaultArgon2Threads,
		keyLen:  DefaultArgon2KeyLen,
		saltLen: DefaultArgon2SaltLen,
	}
}

// NewArgon2idHasherWithParams creates an Argon2idHasher with custom parameters, validating DoS boundaries.
func NewArgon2idHasherWithParams(memory, time uint32, threads uint8, keyLen uint32, saltLen int) (*Argon2idHasher, error) {
	if memory < MinArgon2Memory || memory > MaxArgon2Memory {
		return nil, errors.Errorf("argon2 memory %d KiB out of acceptable range [%d, %d]", memory, MinArgon2Memory, MaxArgon2Memory)
	}
	if time < MinArgon2Time || time > MaxArgon2Time {
		return nil, errors.Errorf("argon2 iterations %d out of acceptable range [%d, %d]", time, MinArgon2Time, MaxArgon2Time)
	}
	if threads < MinArgon2Threads || threads > MaxArgon2Threads {
		return nil, errors.Errorf("argon2 threads %d out of acceptable range [%d, %d]", threads, MinArgon2Threads, MaxArgon2Threads)
	}
	if keyLen < 16 || keyLen > MaxArgon2MaterialLen {
		return nil, errors.Errorf("argon2 key length %d out of acceptable range [16, %d]", keyLen, MaxArgon2MaterialLen)
	}
	if saltLen < 8 || saltLen > MaxArgon2MaterialLen {
		return nil, errors.Errorf("argon2 salt length %d out of acceptable range [8, %d]", saltLen, MaxArgon2MaterialLen)
	}

	return &Argon2idHasher{
		memory:  memory,
		time:    time,
		threads: threads,
		keyLen:  keyLen,
		saltLen: saltLen,
	}, nil
}

// Hash hashes the input byte slice using Argon2id and returns the PHC-formatted hash bytes.
func (h *Argon2idHasher) Hash(data []byte) ([]byte, error) {
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, errors.WrapIf(err, "failed to generate random salt for argon2id")
	}

	hash := argon2.IDKey(data, salt, h.time, h.memory, h.threads, h.keyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, saltB64, hashB64)

	return []byte(phc), nil
}

// Verify checks whether data matches the PHC-formatted Argon2id hash bytes.
// It auto-parses parameters from the hash itself, allowing parameter upgrades over time.
func (h *Argon2idHasher) Verify(data, hash []byte) (bool, error) {
	return h.VerifyString(string(data), string(hash))
}

// HashString hashes a password string using Argon2id and returns a self-describing PHC string.
func (h *Argon2idHasher) HashString(password string) (string, error) {
	phc, err := h.Hash([]byte(password))
	if err != nil {
		return "", err
	}
	return string(phc), nil
}

// VerifyString checks whether a password matches the formatted Argon2id hash string.
func (h *Argon2idHasher) VerifyString(password, hashStr string) (bool, error) {
	hashStr = strings.TrimSpace(hashStr)

	if !strings.HasPrefix(hashStr, "$argon2id$") {
		return false, errors.New("invalid argon2id PHC format: missing $argon2id$ prefix")
	}

	parts := strings.Split(hashStr, "$")
	// Standard parts:
	// With v:    ["", "argon2id", "v=19", "m=65536,t=3,p=4", "<salt>", "<hash>"] -> len = 6
	// Without v: ["", "argon2id", "m=65536,t=3,p=4", "<salt>", "<hash>"]         -> len = 5

	var paramPart, saltPart, hashPart string
	var version uint32 = argon2.Version

	switch len(parts) {
	case 6:
		if strings.HasPrefix(parts[2], "v=") {
			vVal, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "v="), 10, 32)
			if err != nil {
				return false, errors.WrapIf(err, "invalid argon2 version parameter")
			}
			version = uint32(vVal)
		}
		paramPart = parts[3]
		saltPart = parts[4]
		hashPart = parts[5]
	case 5:
		paramPart = parts[2]
		saltPart = parts[3]
		hashPart = parts[4]
	default:
		return false, errors.New("invalid argon2id PHC segment count")
	}

	if version != argon2.Version {
		return false, errors.Errorf("unsupported argon2 version: %d (expected %d)", version, argon2.Version)
	}

	// Parse parameters: m=...,t=...,p=...
	params := strings.Split(paramPart, ",")
	var memory, time uint32
	var threads uint8

	for _, param := range params {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return false, errors.Errorf("malformed argon2 parameter: %s", param)
		}
		val, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return false, errors.WrapIf(err, "invalid parameter integer value")
		}
		switch kv[0] {
		case "m":
			memory = uint32(val)
		case "t":
			time = uint32(val)
		case "p":
			threads = uint8(val)
		}
	}

	// Enforce DoS bounds
	if memory < MinArgon2Memory || memory > MaxArgon2Memory {
		return false, errors.Errorf("argon2 memory %d KiB out of acceptable safety bounds [%d, %d]", memory, MinArgon2Memory, MaxArgon2Memory)
	}
	if time < MinArgon2Time || time > MaxArgon2Time {
		return false, errors.Errorf("argon2 iterations %d out of acceptable safety bounds [%d, %d]", time, MinArgon2Time, MaxArgon2Time)
	}
	if threads < MinArgon2Threads || threads > MaxArgon2Threads {
		return false, errors.Errorf("argon2 threads %d out of acceptable safety bounds [%d, %d]", threads, MinArgon2Threads, MaxArgon2Threads)
	}

	// Decode Salt
	salt, err := base64.RawStdEncoding.DecodeString(saltPart)
	if err != nil {
		salt, err = base64.StdEncoding.DecodeString(saltPart)
		if err != nil {
			return false, errors.WrapIf(err, "failed to decode argon2 salt")
		}
	}

	// Decode Hash
	expectedHash, err := base64.RawStdEncoding.DecodeString(hashPart)
	if err != nil {
		expectedHash, err = base64.StdEncoding.DecodeString(hashPart)
		if err != nil {
			return false, errors.WrapIf(err, "failed to decode argon2 expected hash")
		}
	}

	if len(salt) == 0 || len(salt) > MaxArgon2MaterialLen || len(expectedHash) == 0 || len(expectedHash) > MaxArgon2MaterialLen {
		return false, errors.New("argon2 salt or hash length is invalid or exceeds safety limits")
	}

	derived := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	return subtle.ConstantTimeCompare(derived, expectedHash) == 1, nil
}
