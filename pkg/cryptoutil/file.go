package cryptoutil

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"

	"emperror.dev/errors"
)

const (
	// FileChunkSize defines the chunk size (64 KiB) for streaming file encryption.
	FileChunkSize = 64 * 1024
	// FileMagic represents the 4-byte header identifier for Grain encrypted files.
	FileMagic = "GRNC"
	// FileVersionV1 represents legacy single-key AES-GCM streaming format (17-byte header).
	FileVersionV1 byte = 0x01
	// FileVersionV2 represents HKDF-SHA256 derived per-file ephemeral subkey format (33-byte header).
	FileVersionV2 byte = 0x02
	// FileVersion represents the current default format version byte (FileVersionV2).
	FileVersion byte = FileVersionV2

	// FileSaltLen is the salt length (16 bytes / 128 bits) used for per-file HKDF key derivation.
	FileSaltLen = 16
	// FileBaseNonceLen is the base nonce length (12 bytes / 96 bits) used for stream chunk nonces.
	FileBaseNonceLen = 12

	// FileHeaderSizeV1 is the header length for V1 streams (4B Magic + 1B Version + 12B Nonce).
	FileHeaderSizeV1 = 17
	// FileHeaderSizeV2 is the header length for V2 streams (4B Magic + 1B Version + 16B Salt + 12B Nonce).
	FileHeaderSizeV2 = 33
	// FileHeaderSize is the default header size for newly created streams.
	FileHeaderSize = FileHeaderSizeV2

	// fileEncryptionV2Info is the HKDF info context string for deriving V2 file keys.
	fileEncryptionV2Info = "grain-file-encryption-v2"
)

// BlockProvider provides access to an underlying AES block cipher.
type BlockProvider interface {
	Block() cipher.Block
}

// StreamEncryptor defines streaming encryption across io.Reader and io.Writer.
type StreamEncryptor interface {
	EncryptStream(ctx context.Context, src io.Reader, dst io.Writer) error

	// DecryptStream reads and verifies an authenticated encrypted stream from src and writes plaintext to dst.
	//
	// Security & Partial Data Flush Notice:
	// DecryptStream verifies and writes plaintext incrementally chunk-by-chunk (64 KiB per block).
	// If the stream is truncated, tampered with midway, or aborted via context cancellation, all chunks
	// verified up to that point WILL remain written in dst. Callers writing to non-rollback destinations
	// (such as external network sockets or existing files) must be prepared to handle partial plaintext
	// or use a transactional wrapper. For file operations, always prefer FileEncryptor.DecryptFile,
	// which guarantees atomic rollback on any failure.
	DecryptStream(ctx context.Context, src io.Reader, dst io.Writer) error
}

// FileEncryptor defines file-level encryption and decryption.
type FileEncryptor interface {
	EncryptFile(ctx context.Context, srcPath, dstPath string) error
	DecryptFile(ctx context.Context, srcPath, dstPath string) error
}

// AESFileEncryptor implements authenticated streaming encryption for files using AES-GCM chunking.
// In FileVersionV2 (default), it generates a unique salt per file/stream and derives an isolated 256-bit
// subkey via HKDF-SHA256, eliminating AES-GCM multi-file nonce collision risks under a single master key.
type AESFileEncryptor struct {
	masterKey []byte
	aead      cipher.AEAD
	version   byte
}

// NewAESFileEncryptor creates an AESFileEncryptor.
// target may be a []byte key (16, 24, or 32 bytes) or a cipher implementing BlockProvider.
func NewAESFileEncryptor(target any) (*AESFileEncryptor, error) {
	switch v := target.(type) {
	case []byte:
		if err := ValidateKeySize(v, "aes"); err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(v)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to create AES cipher from key")
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to create GCM AEAD")
		}
		masterKey := append([]byte(nil), v...)
		return &AESFileEncryptor{
			masterKey: masterKey,
			aead:      aead,
			version:   FileVersionV2,
		}, nil
	case BlockProvider:
		aead, err := cipher.NewGCM(v.Block())
		if err != nil {
			return nil, errors.WrapIf(err, "failed to create GCM AEAD from block cipher")
		}
		return &AESFileEncryptor{
			aead:    aead,
			version: FileVersionV1, // BlockProvider does not expose raw key material, so fall back to V1
		}, nil
	default:
		return nil, errors.New("target must be a []byte key or a cipher supporting BlockProvider")
	}
}

// NewFileEncryptor creates an AESFileEncryptor with a raw key.
func NewFileEncryptor(key []byte) (*AESFileEncryptor, error) {
	return NewAESFileEncryptor(key)
}

// SetVersion configures the format version for subsequent stream encryptions (FileVersionV1 or FileVersionV2).
func (fe *AESFileEncryptor) SetVersion(v byte) error {
	if v != FileVersionV1 && v != FileVersionV2 {
		return errors.Errorf("unsupported file version: %d", v)
	}
	if v == FileVersionV2 && len(fe.masterKey) == 0 {
		return errors.New("cannot set version 2: master key not available")
	}
	fe.version = v
	return nil
}

// Zero sanitizes the stored master key memory with ZeroBytes.
func (fe *AESFileEncryptor) Zero() {
	if fe.masterKey != nil {
		ZeroBytes(fe.masterKey)
		fe.masterKey = nil
	}
}

// computeChunkNonceInto populates dst (minimum 12 bytes) with the derived nonce for chunkIndex.
func computeChunkNonceInto(dst, baseNonce []byte, chunkIndex uint64) {
	copy(dst[:12], baseNonce[:12])
	orig := binary.BigEndian.Uint64(dst[4:12])
	binary.BigEndian.PutUint64(dst[4:12], orig^chunkIndex)
}

// computeChunkAADInto populates dst (minimum 9 bytes) with the STREAM AAD for chunkIndex and isLast flag.
func computeChunkAADInto(dst []byte, chunkIndex uint64, isLast byte) {
	binary.BigEndian.PutUint64(dst[:8], chunkIndex)
	dst[8] = isLast
}

// EncryptStream streams and encrypts data from src to dst in authenticated 64 KiB chunks.
// In FileVersionV2 (default), it derives an ephemeral 256-bit subkey via HKDF-SHA256 from a fresh 16-byte random salt.
// It uses pre-allocated buffers inside the stream context to achieve zero per-chunk heap allocations.
func (fe *AESFileEncryptor) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	targetVersion := fe.version
	if targetVersion == 0 {
		if len(fe.masterKey) > 0 {
			targetVersion = FileVersionV2
		} else {
			targetVersion = FileVersionV1
		}
	}

	var (
		activeAEAD cipher.AEAD
		baseNonce  = make([]byte, FileBaseNonceLen)
		header     []byte
	)

	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return errors.WrapIf(err, "failed to generate base nonce")
	}

	if targetVersion == FileVersionV2 {
		if len(fe.masterKey) == 0 {
			return errors.New("master key required for file encryption version 2")
		}

		salt := make([]byte, FileSaltLen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return errors.WrapIf(err, "failed to generate HKDF salt")
		}

		// Derive 32B fileKey via HKDF-SHA256
		fileKey, err := HKDFSHA256(fe.masterKey, salt, []byte(fileEncryptionV2Info), 32)
		if err != nil {
			return errors.WrapIf(err, "failed to derive file subkey via HKDF")
		}

		block, err := aes.NewCipher(fileKey)
		ZeroBytes(fileKey) // Zero derived fileKey immediately after initializing block cipher
		if err != nil {
			return errors.WrapIf(err, "failed to create AES cipher from derived file key")
		}

		derivedAEAD, err := cipher.NewGCM(block)
		if err != nil {
			return errors.WrapIf(err, "failed to create GCM AEAD from derived file key")
		}
		activeAEAD = derivedAEAD

		// Header V2: Magic (4B) + Version (1B) + Salt (16B) + BaseNonce (12B) = 33B
		header = make([]byte, FileHeaderSizeV2)
		copy(header[:4], FileMagic)
		header[4] = FileVersionV2
		copy(header[5:21], salt)
		copy(header[21:33], baseNonce)
	} else {
		// Header V1: Magic (4B) + Version (1B) + BaseNonce (12B) = 17B
		if fe.aead == nil {
			return errors.New("master AEAD cipher required for file encryption version 1")
		}
		activeAEAD = fe.aead
		header = make([]byte, FileHeaderSizeV1)
		copy(header[:4], FileMagic)
		header[4] = FileVersionV1
		copy(header[5:17], baseNonce)
	}

	if _, err := dst.Write(header); err != nil {
		return errors.WrapIf(err, "failed to write stream header")
	}

	bufA := make([]byte, FileChunkSize)
	bufB := make([]byte, FileChunkSize)

	nA, errA := io.ReadFull(src, bufA)
	if errA != nil && errA != io.EOF && errA != io.ErrUnexpectedEOF {
		return errors.WrapIf(errA, "failed to read source stream")
	}

	// Reusable stack buffers to avoid per-chunk heap allocations
	var (
		nonceBuf       [12]byte
		aadBuf         [9]byte
		frameHeaderBuf [5]byte
	)
	nonce := nonceBuf[:]
	aad := aadBuf[:]
	frameHeader := frameHeaderBuf[:]
	encBuf := make([]byte, 0, FileChunkSize+activeAEAD.Overhead())

	var chunkIndex uint64
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		nB, errB := io.ReadFull(src, bufB)
		if errB != nil && errB != io.EOF && errB != io.ErrUnexpectedEOF {
			return errors.WrapIf(errB, "failed to read source stream")
		}

		isLast := byte(0x00)
		if nB == 0 {
			isLast = 0x01
		}

		computeChunkNonceInto(nonce, baseNonce, chunkIndex)
		computeChunkAADInto(aad, chunkIndex, isLast)

		encryptedChunk := activeAEAD.Seal(encBuf[:0], nonce, bufA[:nA], aad)

		// Framing: isLast (1B) + chunkLen (4B) + encrypted payload
		frameHeader[0] = isLast
		binary.BigEndian.PutUint32(frameHeader[1:], uint32(len(encryptedChunk)))

		if _, err := dst.Write(frameHeader); err != nil {
			return errors.WrapIf(err, "failed to write frame header")
		}
		if _, err := dst.Write(encryptedChunk); err != nil {
			return errors.WrapIf(err, "failed to write encrypted frame")
		}

		if isLast == 0x01 {
			break
		}

		chunkIndex++
		nA = nB
		copy(bufA, bufB[:nB])
	}

	return nil
}

// DecryptStream reads and verifies an authenticated encrypted stream from src and writes plaintext to dst.
// It automatically detects and supports both FileVersionV1 (legacy master AEAD) and FileVersionV2 (HKDF envelope encryption).
//
// Security & Partial Data Flush Notice:
// DecryptStream operates incrementally: as each 64 KiB block passes AEAD authentication, it is immediately
// written to dst. If decryption encounters an authentication failure, corrupted chunk, mid-stream truncation,
// or context cancellation, previously authenticated chunks remain written in dst. Callers writing to non-rollback
// destinations should buffer plaintext or ensure transactional guarantees.
// For files, DecryptFile is strongly recommended as it writes to an atomic temporary file and cleans up on failure.
func (fe *AESFileEncryptor) DecryptStream(ctx context.Context, src io.Reader, dst io.Writer) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 1. Read first 5 bytes (Magic 4B + Version 1B)
	magicVer := make([]byte, 5)
	if _, err := io.ReadFull(src, magicVer); err != nil {
		return errors.WrapIf(err, "failed to read stream header")
	}

	if string(magicVer[:4]) != FileMagic {
		return errors.New("invalid file header: not a valid encrypted file")
	}

	version := magicVer[4]
	var (
		activeAEAD cipher.AEAD
		baseNonce  []byte
	)

	switch version {
	case FileVersionV1:
		// Read 12-byte base nonce
		baseNonce = make([]byte, FileBaseNonceLen)
		if _, err := io.ReadFull(src, baseNonce); err != nil {
			return errors.WrapIf(err, "failed to read stream header base nonce")
		}
		if fe.aead == nil {
			return errors.New("cannot decrypt v1 stream: master AEAD not available")
		}
		activeAEAD = fe.aead

	case FileVersionV2:
		// Read 16-byte salt + 12-byte base nonce (28 bytes)
		saltAndNonce := make([]byte, FileSaltLen+FileBaseNonceLen)
		if _, err := io.ReadFull(src, saltAndNonce); err != nil {
			return errors.WrapIf(err, "failed to read stream header salt and nonce")
		}
		salt := saltAndNonce[:FileSaltLen]
		baseNonce = saltAndNonce[FileSaltLen:]

		if len(fe.masterKey) == 0 {
			return errors.New("cannot decrypt v2 envelope stream: master key not available")
		}

		fileKey, err := HKDFSHA256(fe.masterKey, salt, []byte(fileEncryptionV2Info), 32)
		if err != nil {
			return errors.WrapIf(err, "failed to derive file subkey via HKDF")
		}

		block, err := aes.NewCipher(fileKey)
		ZeroBytes(fileKey) // Zero immediately after cipher creation
		if err != nil {
			return errors.WrapIf(err, "failed to create AES cipher from derived file key")
		}

		derivedAEAD, err := cipher.NewGCM(block)
		if err != nil {
			return errors.WrapIf(err, "failed to create GCM AEAD from derived file key")
		}
		activeAEAD = derivedAEAD

	default:
		return errors.Errorf("unsupported file version: %d", version)
	}

	// Reusable stack buffers and slice capacity to eliminate per-chunk heap allocations
	var (
		nonceBuf       [12]byte
		aadBuf         [9]byte
		frameHeaderBuf [5]byte
	)
	nonce := nonceBuf[:]
	aad := aadBuf[:]
	frameHeader := frameHeaderBuf[:]

	maxEncChunkLen := FileChunkSize + activeAEAD.Overhead()
	encBuf := make([]byte, maxEncChunkLen)
	plainBuf := make([]byte, 0, FileChunkSize)

	var chunkIndex uint64
	sawLast := false

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		_, err := io.ReadFull(src, frameHeader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if !sawLast {
					return errors.New("stream ended prematurely: truncated ciphertext")
				}
				break
			}
			return errors.WrapIf(err, "failed to read frame header")
		}

		isLast := frameHeader[0]
		chunkLen := binary.BigEndian.Uint32(frameHeader[1:])
		if chunkLen > uint32(maxEncChunkLen) {
			return errors.Errorf("invalid frame length: %d exceeds maximum chunk size", chunkLen)
		}

		encryptedChunk := encBuf[:chunkLen]
		if _, err := io.ReadFull(src, encryptedChunk); err != nil {
			return errors.WrapIf(err, "failed to read encrypted frame payload")
		}

		computeChunkNonceInto(nonce, baseNonce, chunkIndex)
		computeChunkAADInto(aad, chunkIndex, isLast)

		plainChunk, err := activeAEAD.Open(plainBuf[:0], nonce, encryptedChunk, aad)
		if err != nil {
			return errors.WrapIf(err, "failed to authenticate or decrypt chunk")
		}

		if _, err := dst.Write(plainChunk); err != nil {
			return errors.WrapIf(err, "failed to write decrypted data")
		}

		if isLast == 0x01 {
			sawLast = true
			break
		}
		chunkIndex++
	}

	if !sawLast {
		return errors.New("stream incomplete: missing final authenticated block")
	}

	return nil
}

// EncryptFile encrypts srcPath to dstPath with atomic temporary file writes and strict 0600 permissions.
func (fe *AESFileEncryptor) EncryptFile(ctx context.Context, srcPath, dstPath string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	srcFile, err := os.Open(srcPath) // #nosec G304
	if err != nil {
		return errors.WrapIf(err, "failed to open source file")
	}
	var srcClosed bool
	closeSrc := func() {
		if !srcClosed {
			_ = srcFile.Close()
			srcClosed = true
		}
	}
	defer closeSrc()

	dstDir := filepath.Dir(dstPath)
	tmpFile, err := os.CreateTemp(dstDir, ".grain-enc-tmp-*")
	if err != nil {
		return errors.WrapIf(err, "failed to create temporary file")
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// Ensure secure permissions (owner read/write only)
	if err := tmpFile.Chmod(0600); err != nil {
		return errors.WrapIf(err, "failed to set temporary file permissions")
	}

	if err := fe.EncryptStream(ctx, srcFile, tmpFile); err != nil {
		return errors.WrapIf(err, "stream encryption failed")
	}

	// Explicitly close source file before renaming to support in-place encryption (srcPath == dstPath)
	// and prevent file-locking conflicts on Windows.
	closeSrc()

	if err := tmpFile.Sync(); err != nil {
		return errors.WrapIf(err, "failed to flush file to disk")
	}
	if err := tmpFile.Close(); err != nil {
		return errors.WrapIf(err, "failed to close temporary file")
	}

	if err := os.Rename(tmpPath, dstPath); err != nil {
		return errors.WrapIf(err, "failed to atomically rename encrypted file")
	}

	cleanup = false
	return nil
}

// DecryptFile decrypts srcPath to dstPath with atomic temporary file writes and strict 0600 permissions.
func (fe *AESFileEncryptor) DecryptFile(ctx context.Context, srcPath, dstPath string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	srcFile, err := os.Open(srcPath) // #nosec G304
	if err != nil {
		return errors.WrapIf(err, "failed to open source file")
	}
	var srcClosed bool
	closeSrc := func() {
		if !srcClosed {
			_ = srcFile.Close()
			srcClosed = true
		}
	}
	defer closeSrc()

	dstDir := filepath.Dir(dstPath)
	tmpFile, err := os.CreateTemp(dstDir, ".grain-dec-tmp-*")
	if err != nil {
		return errors.WrapIf(err, "failed to create temporary file")
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		return errors.WrapIf(err, "failed to set temporary file permissions")
	}

	if err := fe.DecryptStream(ctx, srcFile, tmpFile); err != nil {
		return errors.WrapIf(err, "stream decryption failed")
	}

	// Explicitly close source file before renaming to support in-place decryption (srcPath == dstPath)
	// and prevent file-locking conflicts on Windows.
	closeSrc()

	if err := tmpFile.Sync(); err != nil {
		return errors.WrapIf(err, "failed to flush file to disk")
	}
	if err := tmpFile.Close(); err != nil {
		return errors.WrapIf(err, "failed to close temporary file")
	}

	if err := os.Rename(tmpPath, dstPath); err != nil {
		return errors.WrapIf(err, "failed to atomically rename decrypted file")
	}

	cleanup = false
	return nil
}

// EncryptFile is a convenience function to encrypt a file with a key.
func EncryptFile(ctx context.Context, key []byte, srcPath, dstPath string) error {
	encryptor, err := NewFileEncryptor(key)
	if err != nil {
		return err
	}
	return encryptor.EncryptFile(ctx, srcPath, dstPath)
}

// DecryptFile is a convenience function to decrypt a file with a key.
func DecryptFile(ctx context.Context, key []byte, srcPath, dstPath string) error {
	encryptor, err := NewFileEncryptor(key)
	if err != nil {
		return err
	}
	return encryptor.DecryptFile(ctx, srcPath, dstPath)
}
