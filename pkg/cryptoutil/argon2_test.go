package cryptoutil

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2idHasher_Defaults(t *testing.T) {
	hasher := NewArgon2idHasher()
	require.NotNil(t, hasher)

	password := "CorrectHorseBatteryStaple!2026"
	hashStr, err := hasher.HashString(password)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hashStr, "$argon2id$v=19$m=65536,t=3,p=4$"))

	// Verify matching password
	valid, err := hasher.VerifyString(password, hashStr)
	require.NoError(t, err)
	assert.True(t, valid)

	// Verify mismatched password
	valid, err = hasher.VerifyString("WrongPassword", hashStr)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestArgon2idHasher_ByteInterface(t *testing.T) {
	hasher := NewArgon2idHasher()
	pwd := []byte("SensitiveBytePassword123")

	hashBytes, err := hasher.Hash(pwd)
	require.NoError(t, err)
	assert.True(t, len(hashBytes) > 0)

	valid, err := hasher.Verify(pwd, hashBytes)
	require.NoError(t, err)
	assert.True(t, valid)

	// Safe zeroing
	ZeroBytes(pwd)
	assert.Equal(t, make([]byte, len(pwd)), pwd)

	// After zeroing, it should no longer match original password
	valid, err = hasher.Verify(pwd, hashBytes)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestArgon2idHasher_CustomParamsAndAutoParsing(t *testing.T) {
	// Create with smaller custom params: 16 MiB, 2 iterations, 2 threads
	customHasher, err := NewArgon2idHasherWithParams(16*1024, 2, 2, 32, 16)
	require.NoError(t, err)

	password := "CustomParametersPassword"
	hashStr, err := customHasher.HashString(password)
	require.NoError(t, err)
	assert.Contains(t, hashStr, "m=16384,t=2,p=2")

	// Verify using standard default hasher instance (parameter self-describing)
	standardHasher := NewArgon2idHasher()
	valid, err := standardHasher.VerifyString(password, hashStr)
	require.NoError(t, err)
	assert.True(t, valid)

	// Invalid custom params bounds
	_, err = NewArgon2idHasherWithParams(512, 2, 2, 32, 16) // memory < 1024
	assert.Error(t, err)
	_, err = NewArgon2idHasherWithParams(16*1024, 0, 2, 32, 16) // time < 1
	assert.Error(t, err)
	_, err = NewArgon2idHasherWithParams(16*1024, 2, 0, 32, 16) // threads < 1
	assert.Error(t, err)
	_, err = NewArgon2idHasherWithParams(16*1024, 2, 2, 8, 16) // keyLen < 16
	assert.Error(t, err)
	_, err = NewArgon2idHasherWithParams(16*1024, 2, 2, 32, 4) // saltLen < 8
	assert.Error(t, err)
}

func TestArgon2idHasher_PHCVariants(t *testing.T) {
	hasher := NewArgon2idHasher()
	password := "VariantTestPassword"
	hashStr, err := hasher.HashString(password)
	require.NoError(t, err)

	// 1. Variant without optional v=19 segment
	withoutV := strings.Replace(hashStr, "$v=19$", "$", 1)
	valid, err := hasher.VerifyString(password, withoutV)
	require.NoError(t, err)
	assert.True(t, valid)

	// 2. Unsupported version
	unsupportedV := strings.Replace(hashStr, "$v=19$", "$v=20$", 1)
	valid, err = hasher.VerifyString(password, unsupportedV)
	assert.Error(t, err)
	assert.False(t, valid)

	// 3. Invalid prefix
	valid, err = hasher.VerifyString(password, "$bcrypt$something")
	assert.Error(t, err)
	assert.False(t, valid)

	// 4. Invalid segment count
	valid, err = hasher.VerifyString(password, "$argon2id$short")
	assert.Error(t, err)
	assert.False(t, valid)
}

func TestArgon2idHasher_DoSProtection(t *testing.T) {
	hasher := NewArgon2idHasher()

	// Memory exceeding safety limit (e.g. 512 MiB)
	maliciousMem := "$argon2id$v=19$m=524288,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g"
	valid, err := hasher.VerifyString("pass", maliciousMem)
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "safety bounds")

	// Iterations exceeding safety limit
	maliciousTime := "$argon2id$v=19$m=65536,t=50,p=4$c29tZXNhbHQ$c29tZWhhc2g"
	valid, err = hasher.VerifyString("pass", maliciousTime)
	assert.Error(t, err)
	assert.False(t, valid)

	// Threads exceeding safety limit
	maliciousThreads := "$argon2id$v=19$m=65536,t=3,p=32$c29tZXNhbHQ$c29tZWhhc2g"
	valid, err = hasher.VerifyString("pass", maliciousThreads)
	assert.Error(t, err)
	assert.False(t, valid)

	// Malformed parameter integer
	maliciousInt := "$argon2id$v=19$m=not-a-number,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g"
	valid, err = hasher.VerifyString("pass", maliciousInt)
	assert.Error(t, err)
	assert.False(t, valid)

	// Malformed parameter format
	maliciousFormat := "$argon2id$v=19$m,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g"
	valid, err = hasher.VerifyString("pass", maliciousFormat)
	assert.Error(t, err)
	assert.False(t, valid)

	// Oversized salt (exceeding MaxArgon2MaterialLen)
	hugeSalt := strings.Repeat("A", 2048)
	maliciousSalt := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$c29tZWhhc2g", hugeSalt)
	valid, err = hasher.VerifyString("pass", maliciousSalt)
	assert.Error(t, err)
	assert.False(t, valid)
}
