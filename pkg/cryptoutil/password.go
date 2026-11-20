package cryptoutil

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	passwordLowerChars   = "abcdefghijkmnopqrstuvwxyz"
	passwordUpperChars   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	passwordDigitChars   = "23456789"
	passwordSymbolChars  = "!@#$%^&*()-_=+[]{}"
	passwordAllChars     = passwordLowerChars + passwordUpperChars + passwordDigitChars + passwordSymbolChars
	minGeneratedPassword = 12
)

// GeneratePassword returns a cryptographically random password that satisfies
// the strictest built-in password policy (level 3): it always contains at
// least one lowercase letter, one uppercase letter, one digit and one symbol.
// It is used by the admin bootstrap command so operators never have to invent
// (or reuse) an initial credential.
func GeneratePassword(length int) (string, error) {
	if length < minGeneratedPassword {
		return "", fmt.Errorf("generated password length must be at least %d, got %d", minGeneratedPassword, length)
	}

	// Guarantee one character of each class, then fill the remainder from the
	// full alphabet and shuffle so the mandatory characters are not positional.
	result := make([]byte, 0, length)
	for _, class := range []string{passwordLowerChars, passwordUpperChars, passwordDigitChars, passwordSymbolChars} {
		ch, err := randomChar(class)
		if err != nil {
			return "", err
		}
		result = append(result, ch)
	}
	for len(result) < length {
		ch, err := randomChar(passwordAllChars)
		if err != nil {
			return "", err
		}
		result = append(result, ch)
	}
	if err := shuffleBytes(result); err != nil {
		return "", err
	}
	return string(result), nil
}

func randomChar(alphabet string) (byte, error) {
	if alphabet == "" {
		return 0, fmt.Errorf("empty alphabet")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
	if err != nil {
		return 0, fmt.Errorf("generate random character: %w", err)
	}
	return alphabet[n.Int64()], nil
}

func shuffleBytes(buf []byte) error {
	for i := len(buf) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("shuffle password: %w", err)
		}
		j := int(n.Int64())
		buf[i], buf[j] = buf[j], buf[i]
	}
	return nil
}
