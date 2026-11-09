package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"os"
	"strings"

	"emperror.dev/errors"
)

// MinRSABits is the minimum recommended RSA key length (2048 bits for NIST SP 800-57 compliance).
const MinRSABits = 2048

// GenerateRSAKeyPair generates an RSA private and public key pair of the specified bit length.
// If bits <= 0, it defaults to 2048 bits. A minimum of 2048 bits is enforced.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits <= 0 {
		bits = MinRSABits
	}
	if bits < MinRSABits {
		return nil, nil, errors.Errorf("RSA key size %d bits is too weak: minimum is %d bits", bits, MinRSABits)
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, errors.WrapIf(err, "failed to generate RSA key pair")
	}
	return priv, &priv.PublicKey, nil
}

// GenerateECDSAKeyPair generates an ECDSA key pair using the specified elliptic curve.
// If curve is nil, elliptic.P256() is used by default.
func GenerateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	if curve == nil {
		curve = elliptic.P256()
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, errors.WrapIf(err, "failed to generate ECDSA key pair")
	}
	return priv, &priv.PublicKey, nil
}

// GenerateEd25519KeyPair generates an Ed25519 key pair for high-performance Edwards-curve digital signatures.
func GenerateEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.WrapIf(err, "failed to generate Ed25519 key pair")
	}
	return priv, pub, nil
}

// ExtractPublicKey extracts the public key from a supported private key (RSA, ECDSA, or Ed25519).
func ExtractPublicKey(key crypto.PrivateKey) (crypto.PublicKey, error) {
	if key == nil {
		return nil, errors.New("private key cannot be nil")
	}

	if signer, ok := key.(crypto.Signer); ok {
		return signer.Public(), nil
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, errors.Errorf("unsupported private key type for public key extraction: %T", key)
	}
}

// PublicFromPrivate is an alias to ExtractPublicKey for compatibility.
func PublicFromPrivate(key crypto.PrivateKey) (crypto.PublicKey, error) {
	return ExtractPublicKey(key)
}

// EncodePEM wraps DER-encoded bytes in a standard PEM block.
func EncodePEM(blockType string, derBytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	})
}

// DecodePEM decodes the first PEM block from pemBytes.
func DecodePEM(pemBytes []byte) (*pem.Block, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("data is not valid PEM format")
	}
	return block, nil
}

// MarshalPrivateKeyPKCS8PEM serializes an RSA, ECDSA, or Ed25519 private key into standard PKCS#8 PEM format ("PRIVATE KEY").
func MarshalPrivateKeyPKCS8PEM(key crypto.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("private key cannot be nil")
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to marshal private key to PKCS#8 DER")
	}
	return EncodePEM("PRIVATE KEY", der), nil
}

// ParsePrivateKeyPEM parses a PEM-encoded private key.
// It supports PKCS#8 ("PRIVATE KEY"), PKCS#1 ("RSA PRIVATE KEY"), and SEC1 ("EC PRIVATE KEY").
func ParsePrivateKeyPEM(pemBytes []byte) (crypto.PrivateKey, error) {
	block, err := DecodePEM(pemBytes)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse PKCS#8 private key")
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse PKCS#1 RSA private key")
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse SEC1 EC private key")
		}
		return key, nil
	default:
		// Attempt fallback parsing
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errors.Errorf("unsupported private key PEM type: %s", block.Type)
	}
}

// MarshalPublicKeyPKIXPEM serializes a public key into standard PKIX PEM format ("PUBLIC KEY").
func MarshalPublicKeyPKIXPEM(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key cannot be nil")
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to marshal public key to PKIX DER")
	}
	return EncodePEM("PUBLIC KEY", der), nil
}

// ParsePublicKeyPEM parses a PEM-encoded public key.
// It supports standard PKIX ("PUBLIC KEY") and PKCS#1 ("RSA PUBLIC KEY").
func ParsePublicKeyPEM(pemBytes []byte) (crypto.PublicKey, error) {
	block, err := DecodePEM(pemBytes)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse PKIX public key")
		}
		return pub, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse PKCS#1 RSA public key")
		}
		return pub, nil
	default:
		// Fallback attempts
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			return pub, nil
		}
		if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			return pub, nil
		}
		return nil, errors.Errorf("unsupported public key PEM type: %s", block.Type)
	}
}

// ResolveKeyBytes resolves key material provided either as an inline PEM string or a file path on disk.
func ResolveKeyBytes(material string) ([]byte, error) {
	trimmed := strings.TrimSpace(material)
	if trimmed == "" {
		return nil, errors.New("key material cannot be empty")
	}
	if strings.Contains(trimmed, "-----BEGIN") {
		return []byte(trimmed), nil
	}
	data, err := os.ReadFile(trimmed) // #nosec G304
	if err != nil {
		return nil, errors.WrapIf(err, "failed to read key file")
	}
	return data, nil
}

// LoadPrivateKey parses a private key from either an inline PEM string or a file path.
func LoadPrivateKey(material string) (crypto.PrivateKey, error) {
	data, err := ResolveKeyBytes(material)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(data)
}

// LoadPublicKey parses a public key from either an inline PEM string or a file path.
func LoadPublicKey(material string) (crypto.PublicKey, error) {
	data, err := ResolveKeyBytes(material)
	if err != nil {
		return nil, err
	}
	return ParsePublicKeyPEM(data)
}

// SignPKCS1v15 signs a pre-hashed digest using RSA PKCS#1 v1.5.
func SignPKCS1v15(priv *rsa.PrivateKey, hash crypto.Hash, digest []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("RSA private key cannot be nil")
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, hash, digest)
	if err != nil {
		return nil, errors.WrapIf(err, "RSA PKCS#1 v1.5 signing failed")
	}
	return sig, nil
}

// VerifyPKCS1v15 verifies an RSA PKCS#1 v1.5 signature over a pre-hashed digest.
func VerifyPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, digest, sig []byte) (bool, error) {
	if pub == nil {
		return false, errors.New("RSA public key cannot be nil")
	}
	err := rsa.VerifyPKCS1v15(pub, hash, digest, sig)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// SignPSS signs a pre-hashed digest using RSA-PSS.
func SignPSS(priv *rsa.PrivateKey, hash crypto.Hash, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("RSA private key cannot be nil")
	}
	sig, err := rsa.SignPSS(rand.Reader, priv, hash, digest, opts)
	if err != nil {
		return nil, errors.WrapIf(err, "RSA-PSS signing failed")
	}
	return sig, nil
}

// VerifyPSS verifies an RSA-PSS signature over a pre-hashed digest.
func VerifyPSS(pub *rsa.PublicKey, hash crypto.Hash, digest, sig []byte, opts *rsa.PSSOptions) (bool, error) {
	if pub == nil {
		return false, errors.New("RSA public key cannot be nil")
	}
	err := rsa.VerifyPSS(pub, hash, digest, sig, opts)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// SignECDSA signs a pre-hashed digest using ECDSA, returning an ASN.1 DER-encoded signature.
func SignECDSA(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("ECDSA private key cannot be nil")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		return nil, errors.WrapIf(err, "ECDSA ASN.1 signing failed")
	}
	return sig, nil
}

// VerifyECDSA verifies an ASN.1 DER-encoded ECDSA signature over a pre-hashed digest.
func VerifyECDSA(pub *ecdsa.PublicKey, digest, sig []byte) (bool, error) {
	if pub == nil {
		return false, errors.New("ECDSA public key cannot be nil")
	}
	return ecdsa.VerifyASN1(pub, digest, sig), nil
}

// SignEd25519 signs a message using Ed25519 (Ed25519 signs the raw message directly).
func SignEd25519(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// VerifyEd25519 verifies an Ed25519 signature over a message.
func VerifyEd25519(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}

// RSAScheme represents the RSA signature scheme.
type RSAScheme string

const (
	// RSASchemePSS represents the RSA Probabilistic Signature Scheme (PKCS#1 v2.1 / RFC 8017), the modern standard.
	RSASchemePSS RSAScheme = "PSS"
	// RSASchemePKCS1v15 represents the legacy RSA PKCS#1 v1.5 deterministic signature scheme.
	RSASchemePKCS1v15 RSAScheme = "PKCS1v15"
)

// DefaultRSASaltLength defines the default salt length for RSA-PSS signing.
// rsa.PSSSaltLengthEqualsHash causes the salt length to match the output length of the hash function (e.g. 32 bytes for SHA-256), conforming to RFC 8017 Section 8.1.
const DefaultRSASaltLength = rsa.PSSSaltLengthEqualsHash

// RSASignatureOptions configures RSA signature generation and verification.
type RSASignatureOptions struct {
	// Scheme specifies whether to use PSS or PKCS#1 v1.5. If empty, defaults to RSASchemePSS for signing.
	Scheme RSAScheme
	// SaltLength controls the PSS salt length. Defaults to rsa.PSSSaltLengthEqualsHash.
	// Can also be set to rsa.PSSSaltLengthAuto or a custom positive integer.
	SaltLength int
}

// DefaultRSASignatureOptions returns default options (RSA-PSS with SaltLength matching hash size).
func DefaultRSASignatureOptions() *RSASignatureOptions {
	return &RSASignatureOptions{
		Scheme:     RSASchemePSS,
		SaltLength: DefaultRSASaltLength,
	}
}

// Sign is a high-level digital signature function supporting RSA (RSA-PSS by default, RFC 8017), ECDSA (ASN.1), Ed25519,
// and any key implementing crypto.Signer (e.g. cloud KMS, Vault, or hardware HSM).
// For RSA and ECDSA, digest should be the pre-computed hash. For Ed25519, digest represents the message content.
// Optional RSASignatureOptions can be supplied to select RSASchemePKCS1v15 or custom PSS salt lengths.
func Sign(priv crypto.PrivateKey, hash crypto.Hash, digest []byte, opts ...*RSASignatureOptions) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key cannot be nil")
	}

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if len(opts) > 0 && opts[0] != nil && opts[0].Scheme == RSASchemePKCS1v15 {
			return SignPKCS1v15(k, hash, digest)
		}
		saltLen := DefaultRSASaltLength
		if len(opts) > 0 && opts[0] != nil && opts[0].SaltLength != 0 {
			saltLen = opts[0].SaltLength
		}
		return SignPSS(k, hash, digest, &rsa.PSSOptions{SaltLength: saltLen, Hash: hash})
	case *ecdsa.PrivateKey:
		return SignECDSA(k, digest)
	case ed25519.PrivateKey:
		return SignEd25519(k, digest), nil
	default:
		if signer, ok := priv.(crypto.Signer); ok {
			pub := signer.Public()
			switch pub.(type) {
			case *rsa.PublicKey:
				var signerOpts crypto.SignerOpts = hash
				if len(opts) == 0 || opts[0] == nil || opts[0].Scheme != RSASchemePKCS1v15 {
					saltLen := DefaultRSASaltLength
					if len(opts) > 0 && opts[0] != nil && opts[0].SaltLength != 0 {
						saltLen = opts[0].SaltLength
					}
					signerOpts = &rsa.PSSOptions{SaltLength: saltLen, Hash: hash}
				}
				sig, err := signer.Sign(rand.Reader, digest, signerOpts)
				if err != nil {
					return nil, errors.WrapIf(err, "crypto.Signer RSA signing failed")
				}
				return sig, nil
			case *ecdsa.PublicKey:
				sig, err := signer.Sign(rand.Reader, digest, hash)
				if err != nil {
					return nil, errors.WrapIf(err, "crypto.Signer ECDSA signing failed")
				}
				return sig, nil
			case ed25519.PublicKey:
				sig, err := signer.Sign(rand.Reader, digest, crypto.Hash(0))
				if err != nil {
					return nil, errors.WrapIf(err, "crypto.Signer Ed25519 signing failed")
				}
				return sig, nil
			default:
				sig, err := signer.Sign(rand.Reader, digest, hash)
				if err != nil {
					return nil, errors.WrapIf(err, "crypto.Signer signing failed")
				}
				return sig, nil
			}
		}
		return nil, errors.Errorf("unsupported private key type for signing: %T", priv)
	}
}

// isEd25519Key reports whether a private key is an Ed25519 key (either concrete or via crypto.Signer).
func isEd25519Key(priv crypto.PrivateKey) bool {
	if _, ok := priv.(ed25519.PrivateKey); ok {
		return true
	}
	if signer, ok := priv.(crypto.Signer); ok {
		if _, ok := signer.Public().(ed25519.PublicKey); ok {
			return true
		}
	}
	return false
}

// SignMessage hashes the message using hash and computes a digital signature with priv.
// For Ed25519, the message is signed directly without pre-hashing.
// Optional RSASignatureOptions can be supplied for RSA private keys.
func SignMessage(priv crypto.PrivateKey, hash crypto.Hash, message []byte, opts ...*RSASignatureOptions) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key cannot be nil")
	}

	if isEd25519Key(priv) {
		return Sign(priv, crypto.Hash(0), message, opts...)
	}

	if !hash.Available() {
		return nil, errors.Errorf("requested hash algorithm %s is not available", hash.String())
	}
	h := hash.New()
	h.Write(message)
	digest := h.Sum(nil)

	return Sign(priv, hash, digest, opts...)
}

// VerifySignature is a high-level digital signature verification function supporting RSA, ECDSA, and Ed25519.
// For RSA, it performs dual-verification: RSA-PSS is attempted first with auto-detected salt length;
// if PSS verification fails, it seamlessly falls back to PKCS#1 v1.5 verification.
// Optional RSASignatureOptions can be supplied to enforce a specific scheme.
func VerifySignature(pub crypto.PublicKey, hash crypto.Hash, digest, sig []byte, opts ...*RSASignatureOptions) (bool, error) {
	if pub == nil {
		return false, errors.New("public key cannot be nil")
	}

	switch k := pub.(type) {
	case *rsa.PublicKey:
		if len(opts) > 0 && opts[0] != nil {
			if opts[0].Scheme == RSASchemePKCS1v15 {
				return VerifyPKCS1v15(k, hash, digest, sig)
			}
			if opts[0].Scheme == RSASchemePSS {
				saltLen := rsa.PSSSaltLengthAuto
				if opts[0].SaltLength != 0 {
					saltLen = opts[0].SaltLength
				}
				return VerifyPSS(k, hash, digest, sig, &rsa.PSSOptions{SaltLength: saltLen, Hash: hash})
			}
		}
		// Dual verification: attempt PSS first, fallback to PKCS#1 v1.5
		valid, err := VerifyPSS(k, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash})
		if err == nil && valid {
			return true, nil
		}
		return VerifyPKCS1v15(k, hash, digest, sig)
	case *ecdsa.PublicKey:
		return VerifyECDSA(k, digest, sig)
	case ed25519.PublicKey:
		return VerifyEd25519(k, digest, sig), nil
	default:
		return false, errors.Errorf("unsupported public key type for verification: %T", pub)
	}
}

// VerifyMessageSignature hashes the message and verifies the digital signature against pub.
// Optional RSASignatureOptions can be supplied for RSA public keys.
func VerifyMessageSignature(pub crypto.PublicKey, hash crypto.Hash, message, sig []byte, opts ...*RSASignatureOptions) (bool, error) {
	if pub == nil {
		return false, errors.New("public key cannot be nil")
	}

	if _, ok := pub.(ed25519.PublicKey); ok {
		return VerifySignature(pub, crypto.Hash(0), message, sig, opts...)
	}

	if !hash.Available() {
		return false, errors.Errorf("requested hash algorithm %s is not available", hash.String())
	}
	h := hash.New()
	h.Write(message)
	digest := h.Sum(nil)

	return VerifySignature(pub, hash, digest, sig, opts...)
}

// SignString computes a digital signature over a data string and returns a base64-encoded signature.
// Optional RSASignatureOptions can be supplied for RSA private keys.
func SignString(priv crypto.PrivateKey, hash crypto.Hash, data string, opts ...*RSASignatureOptions) (string, error) {
	sig, err := SignMessage(priv, hash, []byte(data), opts...)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyStringSignature verifies a base64-encoded digital signature over a data string.
// Optional RSASignatureOptions can be supplied for RSA public keys.
func VerifyStringSignature(pub crypto.PublicKey, hash crypto.Hash, data string, sigBase64 string, opts ...*RSASignatureOptions) (bool, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigBase64))
	if err != nil {
		sigBytes, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(sigBase64))
		if err != nil {
			return false, errors.WrapIf(err, "failed to decode base64 signature")
		}
	}
	return VerifyMessageSignature(pub, hash, []byte(data), sigBytes, opts...)
}

// hashToCryptoHash maps an initialized hash.Hash to its standard crypto.Hash identifier.
func hashToCryptoHash(h hash.Hash) crypto.Hash {
	switch h.Size() {
	case 32:
		return crypto.SHA256
	case 64:
		return crypto.SHA512
	case 48:
		return crypto.SHA384
	case 28:
		return crypto.SHA224
	case 20:
		return crypto.SHA1
	default:
		return crypto.SHA256
	}
}

// EncryptOAEP encrypts plaintext using RSA-OAEP (RFC 8017 / PKCS#1 v2.2) with the specified hash constructor and label.
// If hashFunc is nil, sha256.New is used by default.
func EncryptOAEP(pub *rsa.PublicKey, hashFunc func() hash.Hash, plaintext, label []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("RSA public key cannot be nil")
	}
	if hashFunc == nil {
		hashFunc = sha256.New
	}
	h := hashFunc()
	if h == nil {
		return nil, errors.New("hash constructor returned nil")
	}

	maxPlaintext := pub.Size() - 2*h.Size() - 2
	if len(plaintext) > maxPlaintext {
		return nil, errors.Errorf("plaintext size %d exceeds RSA-OAEP maximum allowable %d bytes for key size %d bits and hash size %d bytes",
			len(plaintext), maxPlaintext, pub.N.BitLen(), h.Size())
	}

	ciphertext, err := rsa.EncryptOAEP(h, rand.Reader, pub, plaintext, label)
	if err != nil {
		return nil, errors.WrapIf(err, "RSA-OAEP encryption failed")
	}
	return ciphertext, nil
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP (RFC 8017 / PKCS#1 v2.2) with the specified hash constructor and label.
// priv can be *rsa.PrivateKey or any crypto.Decrypter (e.g. cloud KMS, HSM, or Vault).
// If hashFunc is nil, sha256.New is used by default.
func DecryptOAEP(priv crypto.PrivateKey, hashFunc func() hash.Hash, ciphertext, label []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if hashFunc == nil {
		hashFunc = sha256.New
	}
	h := hashFunc()
	if h == nil {
		return nil, errors.New("hash constructor returned nil")
	}

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		plaintext, err := rsa.DecryptOAEP(h, rand.Reader, k, ciphertext, label)
		if err != nil {
			return nil, errors.WrapIf(err, "RSA-OAEP decryption failed")
		}
		return plaintext, nil
	default:
		if decrypter, ok := priv.(crypto.Decrypter); ok {
			opts := &rsa.OAEPOptions{
				Hash:  hashToCryptoHash(h),
				Label: label,
			}
			plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, opts)
			if err != nil {
				return nil, errors.WrapIf(err, "crypto.Decrypter RSA-OAEP decryption failed")
			}
			return plaintext, nil
		}
		return nil, errors.Errorf("unsupported private key type for RSA-OAEP decryption: %T", priv)
	}
}

// EncryptOAEPString encrypts a plaintext string using RSA-OAEP (SHA-256) and returns standard Base64-encoded ciphertext.
// An optional label can be provided.
func EncryptOAEPString(pub *rsa.PublicKey, plaintext string, label ...[]byte) (string, error) {
	var l []byte
	if len(label) > 0 {
		l = label[0]
	}
	ciphertext, err := EncryptOAEP(pub, sha256.New, []byte(plaintext), l)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptOAEPString decodes a Base64-encoded ciphertext and decrypts it using RSA-OAEP (SHA-256).
// priv can be *rsa.PrivateKey or any crypto.Decrypter. An optional label can be provided.
func DecryptOAEPString(priv crypto.PrivateKey, ciphertextBase64 string, label ...[]byte) (string, error) {
	var l []byte
	if len(label) > 0 {
		l = label[0]
	}
	rawCiphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertextBase64))
	if err != nil {
		rawCiphertext, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(ciphertextBase64))
		if err != nil {
			return "", errors.WrapIf(err, "failed to decode base64 ciphertext")
		}
	}
	plaintext, err := DecryptOAEP(priv, sha256.New, rawCiphertext, l)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
