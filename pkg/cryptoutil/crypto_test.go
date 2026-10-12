package cryptoutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test AES-CBC mode
func TestAESCipher(t *testing.T) {
	ctx := context.Background()
	key := []byte("your-secret-key1") // 16 bytes for AES-128

	// Create AES cipher
	aesCipher, err := NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %+v", err)
	}

	// Test encryption and decryption
	plaintext := "Hello, World!"
	ciphertext, err := aesCipher.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("encryption error: %+v", err)
	}

	decrypted, err := aesCipher.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatalf("decryption error: %+v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
}

// Test SHA256 hash
func TestSHA256Hasher(t *testing.T) {
	ctx := context.Background()
	hasher := NewSHA256Hasher()

	// Test hash and verification
	data := "Hello, World!"
	hash, err := hasher.Hash(ctx, data)
	if err != nil {
		t.Fatalf("hash error: %+v", err)
	}

	valid, err := hasher.Verify(ctx, data, hash)
	if err != nil {
		t.Fatalf("verification error: %+v", err)
	}

	if !valid {
		t.Error("hash verification failed")
	}

	// Test verification failure
	invalidValid, err := hasher.Verify(ctx, "invalid data", hash)
	if err != nil {
		t.Fatalf("error verifying invalid data: %+v", err)
	}

	if invalidValid {
		t.Error("hash verification should fail for invalid data")
	}
}

// Test SHA512 hash
func TestSHA512Hasher(t *testing.T) {
	ctx := context.Background()
	hasher := NewSHA512Hasher()

	// Test hash and verification
	data := "Hello, World!"
	hash, err := hasher.Hash(ctx, data)
	if err != nil {
		t.Fatalf("hash error: %+v", err)
	}

	valid, err := hasher.Verify(ctx, data, hash)
	if err != nil {
		t.Fatalf("verification error: %+v", err)
	}

	if !valid {
		t.Error("hash verification failed")
	}
}

// Test Bcrypt hash
func TestBcryptHasher(t *testing.T) {
	ctx := context.Background()
	hasher := NewBcryptHasher(0) // Use default cost

	// Test hash and verification
	password := "my-secret-password"
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		t.Fatalf("hash error: %+v", err)
	}

	valid, err := hasher.Verify(ctx, password, hash)
	if err != nil {
		t.Fatalf("verification error: %+v", err)
	}

	if !valid {
		t.Error("hash verification failed")
	}

	// Test verification failure
	invalidValid, err := hasher.Verify(ctx, "invalid password", hash)
	if err != nil {
		t.Fatalf("error verifying invalid password: %+v", err)
	}

	if invalidValid {
		t.Error("hash verification should fail for invalid password")
	}
}

// Test Scrypt hash
func TestScryptHasher(t *testing.T) {
	ctx := context.Background()
	hasher := NewScryptHasher()

	// Test hash and verification
	data := "Hello, World!"
	hash, err := hasher.Hash(ctx, data)
	if err != nil {
		t.Fatalf("hash error: %+v", err)
	}

	valid, err := hasher.Verify(ctx, data, hash)
	if err != nil {
		t.Fatalf("verification error: %+v", err)
	}

	if !valid {
		t.Error("hash verification failed")
	}

	// Test verification failure
	invalidValid, err := hasher.Verify(ctx, "invalid data", hash)
	if err != nil {
		t.Fatalf("error verifying invalid data: %+v", err)
	}

	if invalidValid {
		t.Error("hash verification should fail for invalid data")
	}
}

// Test context cancellation
func TestContextCancellation(t *testing.T) {
	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Test AES encryption
	key := []byte("your-secret-key1")
	aesCipher, err := NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %+v", err)
	}

	_, err = aesCipher.Encrypt(ctx, "Hello, World!")
	if err == nil {
		t.Error("expected error on context cancellation, got nil")
	}

	// Test SHA256 hash
	hasher := NewSHA256Hasher()
	_, err = hasher.Hash(ctx, "Hello, World!")
	if err == nil {
		t.Error("expected error on context cancellation, got nil")
	}
}

// Test AES-GCM mode
func TestAESGCMCipher(t *testing.T) {
	ctx := context.Background()
	key := []byte("your-secret-key12345678901234567") // 32 bytes for AES-256

	// Create AES-GCM cipher
	aesGCMCipher, err := NewAESGCMCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES-GCM cipher: %+v", err)
	}

	// Test encryption and decryption
	plaintext := "Hello, World!"
	ciphertext, err := aesGCMCipher.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("encryption error: %+v", err)
	}

	decrypted, err := aesGCMCipher.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatalf("decryption error: %+v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
}

// Test key management functions
func TestKeyManager(t *testing.T) {
	// Create key manager
	km := NewKeyManager()

	// Test key derivation from password
	password := "my-secret-password"
	key, err := km.DeriveKey(password, nil)
	if err != nil {
		t.Fatalf("key derivation error: %+v", err)
	}

	if len(key) != 32 {
		t.Errorf("derived key length mismatch: got %d, want %d", len(key), 32)
	}

	// Test generating random key
	randomKey, err := km.GenerateRandomKey()
	if err != nil {
		t.Fatalf("error generating random key: %+v", err)
	}

	if len(randomKey) != 32 {
		t.Errorf("random key length mismatch: got %d, want %d", len(randomKey), 32)
	}

	// Test key format conversion
	keyStr := KeyToBase64(key)
	decodedKey, err := KeyFromBase64(keyStr)
	if err != nil {
		t.Fatalf("error decoding key from base64: %+v", err)
	}

	if string(decodedKey) != string(key) {
		t.Error("decoded key does not match original")
	}

	// Test key size validation
	err = ValidateKeySize(key, "aes")
	if err != nil {
		t.Fatalf("error validating AES key size: %+v", err)
	}
}

// Test HMAC functions
func TestHMACHasher(t *testing.T) {
	ctx := context.Background()
	key := []byte("my-secret-key")

	// Test HMAC-SHA256
	hmacHasher := NewHMACHasher(key, HMACSHA256)

	// Test hash and verification
	data := "Hello, World!"
	hash, err := hmacHasher.Hash(ctx, data)
	if err != nil {
		t.Fatalf("hash error: %+v", err)
	}

	valid, err := hmacHasher.Verify(ctx, data, hash)
	if err != nil {
		t.Fatalf("verification error: %+v", err)
	}

	if !valid {
		t.Error("HMAC verification failed")
	}

	// Test verification failure
	invalidValid, err := hmacHasher.Verify(ctx, "invalid data", hash)
	if err != nil {
		t.Fatalf("error verifying invalid data: %+v", err)
	}

	if invalidValid {
		t.Error("HMAC verification should fail for invalid data")
	}

	// Test HMAC-SHA512
	hmacHasher512 := NewHMACHasher(key, HMACSHA512)
	hash512, err := hmacHasher512.Hash(ctx, data)
	if err != nil {
		t.Fatalf("hash error using SHA512: %+v", err)
	}

	if len(hash512) == len(hash) {
		t.Error("HMAC-SHA512 hash length should differ from HMAC-SHA256")
	}
}

// Test file encryption/decryption functions
func TestFileEncryptor(t *testing.T) {
	ctx := context.Background()
	key := []byte("your-secret-key1") // 16 bytes for AES-128

	// Create AES cipher
	aesCipher, err := NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %+v", err)
	}

	// Create file encryptor
	fileEncryptor := NewAESFileEncryptor(aesCipher)

	// Create test file
	testContent := "Hello, File Encryption!"
	srcPath := "/tmp/test.txt"
	dstPath := "/tmp/test.encrypted"
	decryptedPath := "/tmp/test.decrypted"

	// Ensure test file is cleaned up after test
	defer func() {
		_ = os.Remove(srcPath)
		_ = os.Remove(dstPath)
		_ = os.Remove(decryptedPath)
	}()

	// Write test content
	err = os.WriteFile(srcPath, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("error writing test file: %+v", err)
	}

	// Test encrypting file
	err = fileEncryptor.EncryptFile(ctx, srcPath, dstPath)
	if err != nil {
		t.Fatalf("error encrypting file: %+v", err)
	}

	// Test decrypting file
	err = fileEncryptor.DecryptFile(ctx, dstPath, decryptedPath)
	if err != nil {
		t.Fatalf("error decrypting file: %+v", err)
	}

	// Read decrypted content
	decryptedContent, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("error reading decrypted file: %+v", err)
	}

	if string(decryptedContent) != testContent {
		t.Errorf("decrypted file content does not match original: got %s, want %s", string(decryptedContent), testContent)
	}
}

// Test utility functions
func TestUtils(t *testing.T) {
	// Test random byte generation
	randomBytes, err := GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("error generating random bytes: %+v", err)
	}

	if len(randomBytes) != 16 {
		t.Errorf("random bytes length mismatch: got %d, want %d", len(randomBytes), 16)
	}

	// Test random string generation
	randomString, err := GenerateRandomString(16)
	if err != nil {
		t.Fatalf("error generating random string: %+v", err)
	}

	if len(randomString) == 0 {
		t.Error("generated random string is empty")
	}

	// Test random integer generation
	randomInt, err := GenerateRandomInt(1, 100)
	if err != nil {
		t.Fatalf("error generating random integer: %+v", err)
	}

	if randomInt < 1 || randomInt > 100 {
		t.Errorf("generated random integer out of range: got %d", randomInt)
	}

	// Test encoding/decoding
	testData := []byte("Hello, World!")
	base64Str := EncodeBase64(testData)
	decodedData, err := DecodeBase64(base64Str)
	if err != nil {
		t.Fatalf("error decoding base64: %+v", err)
	}

	if string(decodedData) != string(testData) {
		t.Error("decoded base64 data does not match original")
	}

	// Test safe comparison
	if !SafeEqual("test", "test") {
		t.Error("SafeEqual should return true for equal strings")
	}

	if SafeEqual("test", "test1") {
		t.Error("SafeEqual should return false for unequal strings")
	}
}

// Test edge cases
func TestEdgeCases(t *testing.T) {
	ctx := context.Background()

	// Test empty string encryption
	key := []byte("your-secret-key1") // 16 bytes for AES-128
	aesCipher, err := NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %+v", err)
	}

	emptyString := ""
	encrypted, err := aesCipher.Encrypt(ctx, emptyString)
	if err != nil {
		t.Fatalf("error encrypting empty string: %+v", err)
	}

	decrypted, err := aesCipher.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatalf("error decrypting empty string: %+v", err)
	}

	if decrypted != emptyString {
		t.Error("decrypted empty string does not match original")
	}

	// Test context cancellation
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	_, err = aesCipher.Encrypt(cancelCtx, "Hello")
	if err == nil {
		t.Error("expected error on context cancellation, got nil")
	}
}

// Test utility functions
func TestUtilsFull(t *testing.T) {
	// Test random byte generation
	randomBytes, err := GenerateRandomBytes(16)
	assert.NoError(t, err)
	assert.Len(t, randomBytes, 16)

	// Test random string generation
	randomString, err := GenerateRandomString(16)
	assert.NoError(t, err)
	assert.Greater(t, len(randomString), 0)

	// Test random hex generation
	randomHex, err := GenerateRandomHex(16)
	assert.NoError(t, err)
	assert.Len(t, randomHex, 32) // 16 bytes = 32 hex chars

	// Test random integer generation
	randomInt, err := GenerateRandomInt(1, 100)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, randomInt, int64(1))
	assert.LessOrEqual(t, randomInt, int64(100))

	// Test encoding/decoding
	testData := []byte("Hello, World!")
	base64Str := EncodeBase64(testData)
	decodedData, err := DecodeBase64(base64Str)
	assert.NoError(t, err)
	assert.Equal(t, testData, decodedData)

	// Test hex encoding/decoding
	hexStr := EncodeHex(testData)
	decodedHex, err := DecodeHex(hexStr)
	assert.NoError(t, err)
	assert.Equal(t, testData, decodedHex)

	// Test validity check
	assert.True(t, IsValidBase64(base64Str))
	assert.False(t, IsValidBase64("invalid-base64"))
	assert.True(t, IsValidHex(hexStr))
	assert.False(t, IsValidHex("invalid-hex"))

	// Test string manipulation
	paddedRight := PadRight("test", 'x', 10)
	assert.Len(t, paddedRight, 10)
	assert.Equal(t, "testxxxxxx", paddedRight)

	paddedLeft := PadLeft("test", 'x', 10)
	assert.Len(t, paddedLeft, 10)
	assert.Equal(t, "xxxxxxtest", paddedLeft)

	truncated := TruncateString("Hello, World!", 5)
	assert.Len(t, truncated, 5)
	assert.Equal(t, "Hello", truncated)

	// Test safe comparison
	assert.True(t, SafeEqual("test", "test"))
	assert.False(t, SafeEqual("test", "test1"))
}

// Test key management
func TestKeyManagerFull(t *testing.T) {
	// Create key manager
	km := NewKeyManager()

	// Test key derivation from password
	password := "my-secret-password"
	key, err := km.DeriveKey(password, nil)
	assert.NoError(t, err)
	assert.Len(t, key, 32)

	// Test generating random key
	randomKey, err := km.GenerateRandomKey()
	assert.NoError(t, err)
	assert.Len(t, randomKey, 32)

	// Test generating random key of specified size
	randomKey16, err := GenerateRandomKeyWithSize(16)
	assert.NoError(t, err)
	assert.Len(t, randomKey16, 16)

	// Test key format conversion
	keyStr := KeyToBase64(key)
	decodedKey, err := KeyFromBase64(keyStr)
	assert.NoError(t, err)
	assert.Equal(t, key, decodedKey)

	keyHex := KeyToHex(key)
	decodedKeyHex, err := KeyFromHex(keyHex)
	assert.NoError(t, err)
	assert.Equal(t, key, decodedKeyHex)

	// Test key size validation
	err = ValidateKeySize(key, "aes")
	assert.NoError(t, err)

	// Test invalid key size
	smallKey := make([]byte, 15)
	err = ValidateKeySize(smallKey, "aes")
	assert.Error(t, err)

	// Test key manager with parameters
	kmp := NewKeyManagerWithParams(16, 16384, 8, 1, 32)
	keyFromParams, err := kmp.DeriveKey(password, nil)
	assert.NoError(t, err)
	assert.Len(t, keyFromParams, 32)
}

// Test HMAC functions
func TestHMACFull(t *testing.T) {
	ctx := context.Background()
	key := []byte("my-secret-key")

	// Test HMAC-SHA256
	hmacHasher := NewHMACHasher(key, HMACSHA256)

	// Test hash and verification
	data := "Hello, World!"
	hash, err := hmacHasher.Hash(ctx, data)
	assert.NoError(t, err)

	valid, err := hmacHasher.Verify(ctx, data, hash)
	assert.NoError(t, err)
	assert.True(t, valid)

	// Test verification failure
	invalidValid, err := hmacHasher.Verify(ctx, "invalid data", hash)
	assert.NoError(t, err)
	assert.False(t, invalidValid)

	// Test HMAC-SHA512
	hmacHasher512 := NewHMACHasher(key, HMACSHA512)
	_, err = hmacHasher512.Hash(ctx, data)
	assert.NoError(t, err)

	// Test underlying HMAC functions
	hmacResult, err := GenerateHMAC(data, key, HMACSHA256)
	assert.NoError(t, err)
	assert.NotEmpty(t, hmacResult)

	validHMAC, err := VerifyHMAC(data, hmacResult, key, HMACSHA256)
	assert.NoError(t, err)
	assert.True(t, validHMAC)

	invalidHMAC, err := VerifyHMAC("invalid data", hmacResult, key, HMACSHA256)
	assert.NoError(t, err)
	assert.False(t, invalidHMAC)
}

// Test Scrypt hash
func TestScryptFull(t *testing.T) {
	ctx := context.Background()

	// Test default parameters
	hasher := NewScryptHasher()
	data := "Hello, World!"
	hash, err := hasher.Hash(ctx, data)
	assert.NoError(t, err)

	valid, err := hasher.Verify(ctx, data, hash)
	assert.NoError(t, err)
	assert.True(t, valid)

	// Test Scrypt hasher with parameters
	hasherWithParams := NewScryptHasherWithParams(16, 16384, 8, 1, 32, "base64")
	hashWithParams, err := hasherWithParams.Hash(ctx, data)
	assert.NoError(t, err)

	validWithParams, err := hasherWithParams.Verify(ctx, data, hashWithParams)
	assert.NoError(t, err)
	assert.True(t, validWithParams)
}

// Test file encryption/decryption
func TestFileEncryptorFull(t *testing.T) {
	ctx := context.Background()
	key := []byte("your-secret-key12345678901234567") // 32 bytes for AES-256

	// Create AES-GCM cipher
	aesGCMCipher, err := NewAESGCMCipher(key)
	assert.NoError(t, err)

	// Create file encryptor
	fileEncryptor := NewAESFileEncryptor(aesGCMCipher)

	// Create test file
	testContent := "Hello, File Encryption!"
	tempDir := t.TempDir()
	srcPath := filepath.Join(tempDir, "test.txt")
	dstPath := filepath.Join(tempDir, "test.encrypted")
	decryptedPath := filepath.Join(tempDir, "test.decrypted")

	// Write test content
	err = os.WriteFile(srcPath, []byte(testContent), 0644)
	assert.NoError(t, err)

	// Test encrypting file
	err = fileEncryptor.EncryptFile(ctx, srcPath, dstPath)
	assert.NoError(t, err)
	assert.FileExists(t, dstPath)

	// Test decrypting file
	err = fileEncryptor.DecryptFile(ctx, dstPath, decryptedPath)
	assert.NoError(t, err)
	assert.FileExists(t, decryptedPath)

	// Read decrypted content
	decryptedContent, err := os.ReadFile(decryptedPath)
	assert.NoError(t, err)
	assert.Equal(t, testContent, string(decryptedContent))
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	ctx := context.Background()

	// Test invalid AES key
	_, err := NewAESCipher([]byte("short-key"))
	assert.Error(t, err)

	// Test invalid AES-GCM key
	_, err = NewAESGCMCipher([]byte("short-key"))
	assert.Error(t, err)

	// Test invalid HMAC hasher
	hasher := NewHMACHasher([]byte("key"), "invalid-algorithm")
	_, err = hasher.Hash(ctx, "test")
	assert.Error(t, err)

	// Test empty string encryption
	key := []byte("your-secret-key1")
	aesCipher, err := NewAESCipher(key)
	assert.NoError(t, err)

	emptyString := ""
	encrypted, err := aesCipher.Encrypt(ctx, emptyString)
	assert.NoError(t, err)

	decrypted, err := aesCipher.Decrypt(ctx, encrypted)
	assert.NoError(t, err)
	assert.Equal(t, emptyString, decrypted)

	// Test context cancellation
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	_, err = aesCipher.Encrypt(cancelCtx, "Hello")
	assert.Error(t, err)
}

// Benchmark tests
func BenchmarkAESCipher(b *testing.B) {
	ctx := context.Background()
	key := []byte("your-secret-key1") // 16 bytes for AES-128
	aesCipher, err := NewAESCipher(key)
	if err != nil {
		b.Fatalf("failed to create AES cipher: %+v", err)
	}

	testData := "Hello, World!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesCipher.Encrypt(ctx, testData)
		if err != nil {
			b.Fatalf("encryption error: %+v", err)
		}
	}
}

func BenchmarkAESGCMCipher(b *testing.B) {
	ctx := context.Background()
	key := []byte("your-secret-key12345678901234567") // 32 bytes for AES-256
	aesGCMCipher, err := NewAESGCMCipher(key)
	if err != nil {
		b.Fatalf("failed to create AES-GCM cipher: %+v", err)
	}

	testData := "Hello, World!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesGCMCipher.Encrypt(ctx, testData)
		if err != nil {
			b.Fatalf("encryption error: %+v", err)
		}
	}
}

func BenchmarkSHA256Hasher(b *testing.B) {
	ctx := context.Background()
	hasher := NewSHA256Hasher()

	testData := "Hello, World!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.Hash(ctx, testData)
		if err != nil {
			b.Fatalf("hash error: %+v", err)
		}
	}
}

func BenchmarkHMACHasher(b *testing.B) {
	ctx := context.Background()
	key := []byte("my-secret-key")
	hasher := NewHMACHasher(key, HMACSHA256)

	testData := "Hello, World!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.Hash(ctx, testData)
		if err != nil {
			b.Fatalf("hash error: %+v", err)
		}
	}
}
