package auth

import (
	"crypto"
	"strings"

	"emperror.dev/errors"
	"grain/pkg/cryptoutil"
)

// minRSABits is the minimum strength for RSA signing keys (corresponding to the 112-bit security strength in NIST SP 800-57).
const minRSABits = cryptoutil.MinRSABits

// MinRSABits defines the minimum strength for RSA keys (2048 bits).
const MinRSABits = cryptoutil.MinRSABits

// LoadPublicKey parses a PEM public key from inline PEM data or a file path.
// It supports PKIX ("PUBLIC KEY") and PKCS#1 ("RSA PUBLIC KEY"), and validates
// that RSA keys meet the minimum key size (MinRSABits).
func LoadPublicKey(material string) (crypto.PublicKey, error) {
	pemBytes, err := cryptoutil.ResolveKeyBytes(material)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(pemBytes)
}

// MinServiceTokenLength is the minimum length for service-to-service bearer tokens
// (policy snapshot and diagnostics endpoints).
const MinServiceTokenLength = 32

// IsKnownPlaceholderSecret reports whether s is a documented example/placeholder secret
// (for example the change-me-* values in .env.example), so deployments cannot copy the
// sample value and run with a publicly known secret.
func IsKnownPlaceholderSecret(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	switch lower {
	case "change-me", "changeme", "secret", "password", "toor", "123456", "your-secret", "your-secret-key":
		return true
	}
	if strings.HasPrefix(lower, "change-me-") || strings.HasPrefix(lower, "replace-me") || strings.HasPrefix(lower, "replace_me") {
		return true
	}
	return strings.Contains(lower, "placeholder") || strings.Contains(lower, "example-token")
}

// ValidateServiceToken validates a service-to-service bearer token. An empty value is allowed
// (the endpoints then reject every request, fail-closed); a configured value must be at least
// MinServiceTokenLength bytes and must not be a documented placeholder.
func ValidateServiceToken(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) < MinServiceTokenLength {
		return errors.Errorf("%s must be at least %d bytes, got %d", name, MinServiceTokenLength, len(value))
	}
	if IsKnownPlaceholderSecret(value) {
		return errors.Errorf("%s must not use the documented placeholder value; generate one with: openssl rand -base64 32", name)
	}
	return nil
}
