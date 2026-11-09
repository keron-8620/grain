package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSAKeyPair(t *testing.T) {
	// Default 2048 bits
	priv, pub, err := GenerateRSAKeyPair(0)
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
	assert.Equal(t, 2048, priv.N.BitLen())

	// Explicit 2048 bits
	priv2, pub2, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	assert.Equal(t, 2048, priv2.N.BitLen())
	assert.Equal(t, &priv2.PublicKey, pub2)

	// Weak RSA key (< 2048 bits) must fail
	_, _, err = GenerateRSAKeyPair(1024)
	assert.Error(t, err)
}

func TestECDSAKeyPair(t *testing.T) {
	// Default curve (P-256)
	priv, pub, err := GenerateECDSAKeyPair(nil)
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
	assert.Equal(t, elliptic.P256(), priv.Curve)

	// P-384
	priv384, pub384, err := GenerateECDSAKeyPair(elliptic.P384())
	require.NoError(t, err)
	assert.Equal(t, elliptic.P384(), priv384.Curve)
	assert.Equal(t, &priv384.PublicKey, pub384)

	// P-521
	priv521, pub521, err := GenerateECDSAKeyPair(elliptic.P521())
	require.NoError(t, err)
	assert.Equal(t, elliptic.P521(), priv521.Curve)
	assert.Equal(t, &priv521.PublicKey, pub521)
}

func TestEd25519KeyPair(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	require.NoError(t, err)
	assert.Len(t, priv, ed25519.PrivateKeySize)
	assert.Len(t, pub, ed25519.PublicKeySize)
}

func TestExtractPublicKey(t *testing.T) {
	// RSA
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	extractedRSA, err := ExtractPublicKey(rsaPriv)
	require.NoError(t, err)
	assert.Equal(t, rsaPub, extractedRSA)

	// ECDSA
	ecPriv, ecPub, err := GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	extractedEC, err := ExtractPublicKey(ecPriv)
	require.NoError(t, err)
	assert.Equal(t, ecPub, extractedEC)

	// Ed25519
	edPriv, edPub, err := GenerateEd25519KeyPair()
	require.NoError(t, err)
	extractedEd, err := ExtractPublicKey(edPriv)
	require.NoError(t, err)
	assert.Equal(t, edPub, extractedEd)

	// PublicFromPrivate alias
	aliasPub, err := PublicFromPrivate(edPriv)
	require.NoError(t, err)
	assert.Equal(t, edPub, aliasPub)

	// Nil / unsupported key
	_, err = ExtractPublicKey(nil)
	assert.Error(t, err)

	_, err = ExtractPublicKey("not-a-key")
	assert.Error(t, err)
}

func TestPEMEncodingAndParsing(t *testing.T) {
	// RSA PKCS#8 private key & PKIX public key
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privPEM, err := MarshalPrivateKeyPKCS8PEM(rsaPriv)
	require.NoError(t, err)
	assert.Contains(t, string(privPEM), "-----BEGIN PRIVATE KEY-----")

	parsedPriv, err := ParsePrivateKeyPEM(privPEM)
	require.NoError(t, err)
	parsedRSA, ok := parsedPriv.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, rsaPriv.N, parsedRSA.N)

	pubPEM, err := MarshalPublicKeyPKIXPEM(rsaPub)
	require.NoError(t, err)
	assert.Contains(t, string(pubPEM), "-----BEGIN PUBLIC KEY-----")

	parsedPub, err := ParsePublicKeyPEM(pubPEM)
	require.NoError(t, err)
	parsedRSAPub, ok := parsedPub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, rsaPub.N, parsedRSAPub.N)

	// RSA PKCS#1 format compatibility
	pkcs1Der := x509.MarshalPKCS1PrivateKey(rsaPriv)
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1Der})
	parsedPKCS1, err := ParsePrivateKeyPEM(pkcs1PEM)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, parsedPKCS1)

	pkcs1PubDer := x509.MarshalPKCS1PublicKey(rsaPub)
	pkcs1PubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1PubDer})
	parsedPKCS1Pub, err := ParsePublicKeyPEM(pkcs1PubPEM)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, parsedPKCS1Pub)

	// ECDSA SEC1 format compatibility
	ecPriv, _, err := GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	sec1Der, err := x509.MarshalECPrivateKey(ecPriv)
	require.NoError(t, err)
	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1Der})
	parsedSEC1, err := ParsePrivateKeyPEM(sec1PEM)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, parsedSEC1)

	// Ed25519 PKCS#8 & PKIX
	edPriv, edPub, err := GenerateEd25519KeyPair()
	require.NoError(t, err)
	edPrivPEM, err := MarshalPrivateKeyPKCS8PEM(edPriv)
	require.NoError(t, err)
	parsedEdPriv, err := ParsePrivateKeyPEM(edPrivPEM)
	require.NoError(t, err)
	assert.Equal(t, edPriv, parsedEdPriv)

	edPubPEM, err := MarshalPublicKeyPKIXPEM(edPub)
	require.NoError(t, err)
	parsedEdPub, err := ParsePublicKeyPEM(edPubPEM)
	require.NoError(t, err)
	assert.Equal(t, edPub, parsedEdPub)

	// Custom/unknown PEM block type with fallback parsing
	customPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "CUSTOM PRIVATE KEY", Bytes: pkcs1Der})
	parsedCustomPriv, err := ParsePrivateKeyPEM(customPrivPEM)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, parsedCustomPriv)

	customPubPEM := pem.EncodeToMemory(&pem.Block{Type: "CUSTOM PUBLIC KEY", Bytes: pkcs1PubDer})
	parsedCustomPub, err := ParsePublicKeyPEM(customPubPEM)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, parsedCustomPub)

	// Completely invalid DER in unknown block type
	badBlockPEM := pem.EncodeToMemory(&pem.Block{Type: "CORRUPT KEY", Bytes: []byte("corrupt-der-bytes")})
	_, err = ParsePrivateKeyPEM(badBlockPEM)
	assert.Error(t, err)
	_, err = ParsePublicKeyPEM(badBlockPEM)
	assert.Error(t, err)

	// Error cases
	_, err = MarshalPrivateKeyPKCS8PEM(nil)
	assert.Error(t, err)

	_, err = MarshalPublicKeyPKIXPEM(nil)
	assert.Error(t, err)

	_, err = ParsePrivateKeyPEM([]byte("invalid pem data"))
	assert.Error(t, err)

	_, err = ParsePublicKeyPEM([]byte("invalid pem data"))
	assert.Error(t, err)
}

func TestLoadKeyMaterial(t *testing.T) {
	tempDir := t.TempDir()
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	privPEM, err := MarshalPrivateKeyPKCS8PEM(rsaPriv)
	require.NoError(t, err)
	pubPEM, err := MarshalPublicKeyPKIXPEM(rsaPub)
	require.NoError(t, err)

	privPath := filepath.Join(tempDir, "rsa_private.pem")
	pubPath := filepath.Join(tempDir, "rsa_public.pem")

	require.NoError(t, os.WriteFile(privPath, privPEM, 0600))
	require.NoError(t, os.WriteFile(pubPath, pubPEM, 0644))

	// Load from inline string
	loadedPrivStr, err := LoadPrivateKey(string(privPEM))
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, loadedPrivStr)

	loadedPubStr, err := LoadPublicKey(string(pubPEM))
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, loadedPubStr)

	// Load from file path
	loadedPrivFile, err := LoadPrivateKey(privPath)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, loadedPrivFile)

	loadedPubFile, err := LoadPublicKey(pubPath)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, loadedPubFile)

	// Empty string or non-existent file
	_, err = LoadPrivateKey("")
	assert.Error(t, err)

	_, err = LoadPrivateKey(filepath.Join(tempDir, "non_existent.pem"))
	assert.Error(t, err)

	_, err = LoadPublicKey("")
	assert.Error(t, err)

	_, err = LoadPublicKey(filepath.Join(tempDir, "non_existent_pub.pem"))
	assert.Error(t, err)
}

func TestDigitalSignatures_RSA(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	message := []byte("Sensitive business payload to be digitally signed")
	hash := crypto.SHA256
	h := hash.New()
	h.Write(message)
	digest := h.Sum(nil)

	// PKCS#1 v1.5
	sig, err := SignPKCS1v15(priv, hash, digest)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := VerifyPKCS1v15(pub, hash, digest, sig)
	require.NoError(t, err)
	assert.True(t, valid)

	// Tampered digest
	corruptDigest := append([]byte(nil), digest...)
	corruptDigest[0] ^= 0xFF
	valid, err = VerifyPKCS1v15(pub, hash, corruptDigest, sig)
	require.NoError(t, err)
	assert.False(t, valid)

	// Tampered signature
	corruptSig := append([]byte(nil), sig...)
	corruptSig[0] ^= 0xFF
	valid, err = VerifyPKCS1v15(pub, hash, digest, corruptSig)
	require.NoError(t, err)
	assert.False(t, valid)

	// RSA-PSS
	pssSig, err := SignPSS(priv, hash, digest, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, pssSig)

	validPSS, err := VerifyPSS(pub, hash, digest, pssSig, nil)
	require.NoError(t, err)
	assert.True(t, validPSS)

	// Tampered PSS
	validPSS, err = VerifyPSS(pub, hash, corruptDigest, pssSig, nil)
	require.NoError(t, err)
	assert.False(t, validPSS)
}

func TestDigitalSignatures_ECDSA(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	message := []byte("ECDSA signed document content")

	for _, curve := range curves {
		priv, pub, err := GenerateECDSAKeyPair(curve)
		require.NoError(t, err)

		h := sha256.Sum256(message)
		digest := h[:]

		sig, err := SignECDSA(priv, digest)
		require.NoError(t, err)
		assert.NotEmpty(t, sig)

		valid, err := VerifyECDSA(pub, digest, sig)
		require.NoError(t, err)
		assert.True(t, valid)

		// Tampered digest
		corruptDigest := append([]byte(nil), digest...)
		corruptDigest[len(corruptDigest)-1] ^= 0x01
		valid, err = VerifyECDSA(pub, corruptDigest, sig)
		require.NoError(t, err)
		assert.False(t, valid)
	}
}

func TestDigitalSignatures_Ed25519(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	require.NoError(t, err)

	message := []byte("High speed Ed25519 signature payload")
	sig := SignEd25519(priv, message)
	assert.Len(t, sig, ed25519.SignatureSize)

	valid := VerifyEd25519(pub, message, sig)
	assert.True(t, valid)

	// Tampered message
	valid = VerifyEd25519(pub, []byte("Tampered message"), sig)
	assert.False(t, valid)

	// Tampered signature
	corruptSig := append([]byte(nil), sig...)
	corruptSig[0] ^= 0x01
	valid = VerifyEd25519(pub, message, corruptSig)
	assert.False(t, valid)
}

func TestHighLevelSignAndVerify(t *testing.T) {
	message := []byte("Universal message payload")
	hash := crypto.SHA256

	// RSA
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	rsaSig, err := SignMessage(rsaPriv, hash, message)
	require.NoError(t, err)
	valid, err := VerifyMessageSignature(rsaPub, hash, message, rsaSig)
	require.NoError(t, err)
	assert.True(t, valid)

	// ECDSA
	ecPriv, ecPub, err := GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)

	ecSig, err := SignMessage(ecPriv, hash, message)
	require.NoError(t, err)
	valid, err = VerifyMessageSignature(ecPub, hash, message, ecSig)
	require.NoError(t, err)
	assert.True(t, valid)

	// Ed25519
	edPriv, edPub, err := GenerateEd25519KeyPair()
	require.NoError(t, err)

	edSig, err := SignMessage(edPriv, crypto.Hash(0), message)
	require.NoError(t, err)
	valid, err = VerifyMessageSignature(edPub, crypto.Hash(0), message, edSig)
	require.NoError(t, err)
	assert.True(t, valid)

	// String level
	text := "Order #100293 Approved by Manager"
	b64Sig, err := SignString(rsaPriv, hash, text)
	require.NoError(t, err)
	assert.True(t, IsValidBase64(b64Sig))

	validStr, err := VerifyStringSignature(rsaPub, hash, text, b64Sig)
	require.NoError(t, err)
	assert.True(t, validStr)

	// String wrong data
	validStr, err = VerifyStringSignature(rsaPub, hash, "Order #99999", b64Sig)
	require.NoError(t, err)
	assert.False(t, validStr)

	// Ed25519 String
	edB64Sig, err := SignString(edPriv, crypto.Hash(0), text)
	require.NoError(t, err)
	validEdStr, err := VerifyStringSignature(edPub, crypto.Hash(0), text, edB64Sig)
	require.NoError(t, err)
	assert.True(t, validEdStr)

	// String invalid base64 signature
	_, err = VerifyStringSignature(rsaPub, hash, text, "not-valid-base64???")
	assert.Error(t, err)

	// Nil and invalid parameter error checks
	_, err = Sign(nil, hash, []byte("digest"))
	assert.Error(t, err)

	_, err = Sign("unsupported-priv-key", hash, []byte("digest"))
	assert.Error(t, err)

	_, err = VerifySignature(nil, hash, []byte("digest"), []byte("sig"))
	assert.Error(t, err)

	_, err = VerifySignature("unsupported-pub-key", hash, []byte("digest"), []byte("sig"))
	assert.Error(t, err)

	_, err = SignMessage(nil, hash, message)
	assert.Error(t, err)

	_, err = VerifyMessageSignature(nil, hash, message, rsaSig)
	assert.Error(t, err)

	unavailableHash := crypto.Hash(9999)
	_, err = SignMessage(rsaPriv, unavailableHash, message)
	assert.Error(t, err)

	validMsg, err := VerifyMessageSignature(rsaPub, unavailableHash, message, rsaSig)
	assert.False(t, validMsg)
	assert.Error(t, err)

	// Low-level function nil checks
	_, err = SignPKCS1v15(nil, hash, []byte("digest"))
	assert.Error(t, err)
	validLow, err := VerifyPKCS1v15(nil, hash, []byte("digest"), []byte("sig"))
	assert.False(t, validLow)
	assert.Error(t, err)

	_, err = SignPSS(nil, hash, []byte("digest"), nil)
	assert.Error(t, err)
	validPSSNil, err := VerifyPSS(nil, hash, []byte("digest"), []byte("sig"), nil)
	assert.False(t, validPSSNil)
	assert.Error(t, err)

	_, err = SignECDSA(nil, []byte("digest"))
	assert.Error(t, err)
	validECNil, err := VerifyECDSA(nil, []byte("digest"), []byte("sig"))
	assert.False(t, validECNil)
	assert.Error(t, err)
}

func TestDigitalSignatures_RSAPSSDefaultAndDualVerification(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	message := []byte("Modernized RSA-PSS signature test payload")
	hash := crypto.SHA256
	h := hash.New()
	h.Write(message)
	digest := h.Sum(nil)

	// 1. SignMessage defaults to RSA-PSS
	pssSig, err := SignMessage(priv, hash, message)
	require.NoError(t, err)
	assert.NotEmpty(t, pssSig)

	// Must verify under VerifyPSS
	validPSS, err := VerifyPSS(pub, hash, digest, pssSig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	require.NoError(t, err)
	assert.True(t, validPSS, "SignMessage default should produce a valid RSA-PSS signature")

	// Must fail under VerifyPKCS1v15
	validPKCS, err := VerifyPKCS1v15(pub, hash, digest, pssSig)
	require.NoError(t, err)
	assert.False(t, validPKCS, "RSA-PSS signature should not verify as PKCS#1 v1.5")

	// Must verify under high-level VerifyMessageSignature
	validHigh, err := VerifyMessageSignature(pub, hash, message, pssSig)
	require.NoError(t, err)
	assert.True(t, validHigh)

	// 2. Dual verification backward compatibility: legacy PKCS#1 v1.5 signature
	legacySig, err := SignPKCS1v15(priv, hash, digest)
	require.NoError(t, err)

	// Direct PSS fails on PKCS#1 v1.5
	validPSSLegacy, err := VerifyPSS(pub, hash, digest, legacySig, nil)
	require.NoError(t, err)
	assert.False(t, validPSSLegacy)

	// High-level VerifySignature automatically falls back to PKCS#1 v1.5
	validDual, err := VerifySignature(pub, hash, digest, legacySig)
	require.NoError(t, err)
	assert.True(t, validDual, "Dual verification should verify legacy PKCS#1 v1.5 signatures")

	validMsgDual, err := VerifyMessageSignature(pub, hash, message, legacySig)
	require.NoError(t, err)
	assert.True(t, validMsgDual)

	// String dual verification
	legacyB64 := EncodeBase64(legacySig)
	validStrDual, err := VerifyStringSignature(pub, hash, string(message), legacyB64)
	require.NoError(t, err)
	assert.True(t, validStrDual)

	// 3. Explicit options
	// Explicit PKCS#1 v1.5 option for Sign
	pkcsSigOpt, err := Sign(priv, hash, digest, &RSASignatureOptions{Scheme: RSASchemePKCS1v15})
	require.NoError(t, err)
	validPKCSOpt, err := VerifyPKCS1v15(pub, hash, digest, pkcsSigOpt)
	require.NoError(t, err)
	assert.True(t, validPKCSOpt)

	// Explicit PSS option for Sign with custom salt length
	pssSigOpt, err := Sign(priv, hash, digest, &RSASignatureOptions{Scheme: RSASchemePSS, SaltLength: 32})
	require.NoError(t, err)
	validPSSOpt, err := VerifyPSS(pub, hash, digest, pssSigOpt, &rsa.PSSOptions{SaltLength: 32})
	require.NoError(t, err)
	assert.True(t, validPSSOpt)

	// DefaultRSASignatureOptions helper
	defOpts := DefaultRSASignatureOptions()
	assert.Equal(t, RSASchemePSS, defOpts.Scheme)
	assert.Equal(t, DefaultRSASaltLength, defOpts.SaltLength)

	// Enforce scheme in VerifySignature:
	// Verify with RSASchemePSS enforced should reject legacy PKCS#1 v1.5 signature
	enforcedPSSValid, err := VerifySignature(pub, hash, digest, legacySig, &RSASignatureOptions{Scheme: RSASchemePSS})
	require.NoError(t, err)
	assert.False(t, enforcedPSSValid, "Enforcing RSASchemePSS must reject PKCS#1 v1.5 signature")

	// Verify with RSASchemePKCS1v15 enforced should verify legacy signature
	enforcedPKCSValid, err := VerifySignature(pub, hash, digest, legacySig, &RSASignatureOptions{Scheme: RSASchemePKCS1v15})
	require.NoError(t, err)
	assert.True(t, enforcedPKCSValid)

	// 4. Tampering & Wrong key
	tamperedSig := append([]byte(nil), pssSig...)
	tamperedSig[0] ^= 0xFF
	tamperedValid, err := VerifyMessageSignature(pub, hash, message, tamperedSig)
	require.NoError(t, err)
	assert.False(t, tamperedValid)

	_, otherPub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	wrongKeyValid, err := VerifyMessageSignature(otherPub, hash, message, pssSig)
	require.NoError(t, err)
	assert.False(t, wrongKeyValid)
}

// mockSigner mocks a cloud KMS or HSM signer implementing crypto.Signer.
type mockSigner struct {
	pub      crypto.PublicKey
	signFunc func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

func (m *mockSigner) Public() crypto.PublicKey {
	return m.pub
}

func (m *mockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return m.signFunc(rand, digest, opts)
}

func TestCryptoSigner_KMSCompatibility(t *testing.T) {
	// 1. RSA KMS Signer
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	rsaKMS := &mockSigner{
		pub: rsaPub,
		signFunc: func(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
			return rsaPriv.Sign(r, digest, opts)
		},
	}

	msg := []byte("Message signed via mock KMS/HSM")
	sigRSA, err := SignMessage(rsaKMS, crypto.SHA256, msg)
	require.NoError(t, err)

	validRSA, err := VerifyMessageSignature(rsaPub, crypto.SHA256, msg, sigRSA)
	require.NoError(t, err)
	assert.True(t, validRSA)

	// Test RSA PKCS#1 v1.5 through crypto.Signer
	sigPKCS1, err := SignMessage(rsaKMS, crypto.SHA256, msg, &RSASignatureOptions{Scheme: RSASchemePKCS1v15})
	require.NoError(t, err)
	validPKCS1, err := VerifyMessageSignature(rsaPub, crypto.SHA256, msg, sigPKCS1, &RSASignatureOptions{Scheme: RSASchemePKCS1v15})
	require.NoError(t, err)
	assert.True(t, validPKCS1)

	// 2. ECDSA KMS Signer
	ecPriv, ecPub, err := GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)

	ecKMS := &mockSigner{
		pub: ecPub,
		signFunc: func(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
			return ecPriv.Sign(r, digest, opts)
		},
	}

	sigEC, err := SignMessage(ecKMS, crypto.SHA256, msg)
	require.NoError(t, err)

	validEC, err := VerifyMessageSignature(ecPub, crypto.SHA256, msg, sigEC)
	require.NoError(t, err)
	assert.True(t, validEC)

	// 3. Ed25519 KMS Signer
	edPriv, edPub, err := GenerateEd25519KeyPair()
	require.NoError(t, err)

	edKMS := &mockSigner{
		pub: edPub,
		signFunc: func(r io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
			return edPriv.Sign(r, message, opts)
		},
	}

	sigEd, err := SignMessage(edKMS, crypto.Hash(0), msg)
	require.NoError(t, err)

	validEd, err := VerifyMessageSignature(edPub, crypto.Hash(0), msg, sigEd)
	require.NoError(t, err)
	assert.True(t, validEd)
}

// mockDecrypter mocks a cloud KMS or HSM decrypter implementing crypto.Decrypter.
type mockDecrypter struct {
	pub         crypto.PublicKey
	decryptFunc func(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

func (m *mockDecrypter) Public() crypto.PublicKey {
	return m.pub
}

func (m *mockDecrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return m.decryptFunc(rand, msg, opts)
}

func TestRSA_OAEP(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	plaintext := []byte("Super secret payload to be encrypted via RSA-OAEP")
	label := []byte("grain-session-context")

	// 1. Basic round-trip with default SHA-256 and label
	ciphertext, err := EncryptOAEP(pub, nil, plaintext, label)
	require.NoError(t, err)
	assert.Equal(t, pub.Size(), len(ciphertext))

	decrypted, err := DecryptOAEP(priv, nil, ciphertext, label)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 2. Mismatched label must fail decryption
	_, err = DecryptOAEP(priv, nil, ciphertext, []byte("wrong-label"))
	assert.Error(t, err)

	// 3. Tampered ciphertext must fail decryption
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-5] ^= 0xFF
	_, err = DecryptOAEP(priv, nil, tampered, label)
	assert.Error(t, err)

	// 4. Custom hash function (SHA-512)
	ct512, err := EncryptOAEP(pub, sha512.New, plaintext, nil)
	require.NoError(t, err)
	dec512, err := DecryptOAEP(priv, sha512.New, ct512, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec512)

	// 5. String helpers (Base64)
	textMsg := "Credentials to protect"
	b64Cipher, err := EncryptOAEPString(pub, textMsg, label)
	require.NoError(t, err)
	assert.True(t, IsValidBase64(b64Cipher))

	plainText, err := DecryptOAEPString(priv, b64Cipher, label)
	require.NoError(t, err)
	assert.Equal(t, textMsg, plainText)

	// String helper invalid base64
	_, err = DecryptOAEPString(priv, "not-valid-base64???")
	assert.Error(t, err)

	// 6. Plaintext size exceeding bounds check
	// For 2048-bit RSA (256 bytes) and SHA-256 (32 bytes), max plaintext is 256 - 64 - 2 = 190 bytes
	oversized := make([]byte, 191)
	_, err = EncryptOAEP(pub, sha256.New, oversized, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds RSA-OAEP maximum allowable")

	// 7. Nil parameter error checks
	_, err = EncryptOAEP(nil, nil, plaintext, nil)
	assert.Error(t, err)

	_, err = DecryptOAEP(nil, nil, ciphertext, nil)
	assert.Error(t, err)

	_, err = DecryptOAEP("invalid-key-type", nil, ciphertext, nil)
	assert.Error(t, err)

	// 8. crypto.Decrypter interface support (KMS / HSM)
	kmsDecrypter := &mockDecrypter{
		pub: pub,
		decryptFunc: func(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
			return priv.Decrypt(r, msg, opts)
		},
	}

	decryptedViaKMS, err := DecryptOAEP(kmsDecrypter, nil, ciphertext, label)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedViaKMS)

	decryptedStringViaKMS, err := DecryptOAEPString(kmsDecrypter, b64Cipher, label)
	require.NoError(t, err)
	assert.Equal(t, textMsg, decryptedStringViaKMS)
}
