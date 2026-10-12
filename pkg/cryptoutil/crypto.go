package cryptoutil

import (
	"bytes"
	"context"
	"encoding/base64"

	"emperror.dev/errors"
)

// Hasher defines the hashing interface (for one-way hashing)
type Hasher interface {
	// Hash hashes the input data
	Hash(ctx context.Context, data string) (string, error)

	// Verify checks whether the data matches the hash
	Verify(ctx context.Context, data, hash string) (bool, error)
}

// Cipher defines the encryption and decryption interface
type Cipher interface {
	// Encrypt encrypts data
	Encrypt(ctx context.Context, plaintext string) (string, error)

	// Decrypt decrypts data
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

// BaseCipher provides basic encoding and decoding functionality
type BaseCipher struct{}

// EncodeToString encodes byte data to a string
func (c *BaseCipher) EncodeToString(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeString decodes a string to byte data
func (c *BaseCipher) DecodeString(data string) ([]byte, error) {
	dataBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to decode base64")
	}
	return dataBytes, nil
}

// pkcs7Padding applies PKCS7 padding
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	if padding < 1 || padding > 255 {
		padding = 1
	}
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpadding removes PKCS7 padding
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size: data is empty")
	}

	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.Errorf("invalid padding size: %d is greater than data length %d", unpadding, length)
	}

	return data[:(length - unpadding)], nil
}
