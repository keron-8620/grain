package cryptoutil

import (
	"context"
	"io"
	"os"

	"emperror.dev/errors"
)

// FileEncryptor defines the file encryptor interface
type FileEncryptor interface {
	// EncryptFile encrypts a file
	EncryptFile(ctx context.Context, srcPath, dstPath string) error
	// DecryptFile decrypts a file
	DecryptFile(ctx context.Context, srcPath, dstPath string) error
}

// AESFileEncryptor AES file encryptor
type AESFileEncryptor struct {
	cipher Cipher
}

// NewAESFileEncryptor creates an AES file encryptor
func NewAESFileEncryptor(cipher Cipher) *AESFileEncryptor {
	return &AESFileEncryptor{
		cipher: cipher,
	}
}

// EncryptFile encrypts a file
func (fe *AESFileEncryptor) EncryptFile(ctx context.Context, srcPath, dstPath string) error {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return errors.WrapIf(ctx.Err(), "context cancelled")
	}

	// Open source file
	srcFile, err := os.Open(srcPath) // #nosec G304
	if err != nil {
		return errors.WrapIf(err, "failed to open source file")
	}
	defer func() { _ = srcFile.Close() }()

	// Read file content
	content, err := io.ReadAll(srcFile)
	if err != nil {
		return errors.WrapIf(err, "failed to read file content")
	}

	// Encrypt content
	encryptedContent, err := fe.cipher.Encrypt(ctx, string(content))
	if err != nil {
		return errors.WrapIf(err, "failed to encrypt file content")
	}

	// Write to destination file
	dstFile, err := os.Create(dstPath) // #nosec G304
	if err != nil {
		return errors.WrapIf(err, "failed to create destination file")
	}
	defer func() { _ = dstFile.Close() }()

	_, err = dstFile.WriteString(encryptedContent)
	if err != nil {
		return errors.WrapIf(err, "failed to write encrypted content")
	}

	return nil
}

// DecryptFile decrypts a file
func (fe *AESFileEncryptor) DecryptFile(ctx context.Context, srcPath, dstPath string) error {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return errors.WrapIf(ctx.Err(), "context cancelled")
	}

	// Open source file
	srcFile, err := os.Open(srcPath) // #nosec G304
	if err != nil {
		return errors.WrapIf(err, "failed to open source file")
	}
	defer func() { _ = srcFile.Close() }()

	// Read file content
	content, err := io.ReadAll(srcFile)
	if err != nil {
		return errors.WrapIf(err, "failed to read file content")
	}

	// Decrypt content
	decryptedContent, err := fe.cipher.Decrypt(ctx, string(content))
	if err != nil {
		return errors.WrapIf(err, "failed to decrypt file content")
	}

	// Write to destination file
	dstFile, err := os.Create(dstPath) // #nosec G304
	if err != nil {
		return errors.WrapIf(err, "failed to create destination file")
	}
	defer func() { _ = dstFile.Close() }()

	_, err = dstFile.WriteString(decryptedContent)
	if err != nil {
		return errors.WrapIf(err, "failed to write decrypted content")
	}

	return nil
}

// EncryptFile is a convenience function to encrypt a file
func EncryptFile(ctx context.Context, cipher Cipher, srcPath, dstPath string) error {
	encryptor := NewAESFileEncryptor(cipher)
	return encryptor.EncryptFile(ctx, srcPath, dstPath)
}

// DecryptFile is a convenience function to decrypt a file
func DecryptFile(ctx context.Context, cipher Cipher, srcPath, dstPath string) error {
	encryptor := NewAESFileEncryptor(cipher)
	return encryptor.DecryptFile(ctx, srcPath, dstPath)
}
