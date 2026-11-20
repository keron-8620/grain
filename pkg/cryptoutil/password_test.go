package cryptoutil

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePassword(t *testing.T) {
	t.Run("rejects short length", func(t *testing.T) {
		_, err := GeneratePassword(11)
		require.Error(t, err)
	})

	t.Run("satisfies the strictest policy", func(t *testing.T) {
		for i := 0; i < 64; i++ {
			password, err := GeneratePassword(24)
			require.NoError(t, err)
			require.Len(t, password, 24)

			var lower, upper, digit, symbol bool
			for _, r := range password {
				switch {
				case unicode.IsLower(r):
					lower = true
				case unicode.IsUpper(r):
					upper = true
				case unicode.IsDigit(r):
					digit = true
				default:
					symbol = true
				}
				assert.False(t, unicode.IsSpace(r), "password must not contain whitespace")
			}
			assert.True(t, lower, "password %q must contain a lowercase letter", password)
			assert.True(t, upper, "password %q must contain an uppercase letter", password)
			assert.True(t, digit, "password %q must contain a digit", password)
			assert.True(t, symbol, "password %q must contain a symbol", password)
		}
	})

	t.Run("does not repeat values", func(t *testing.T) {
		seen := make(map[string]struct{}, 32)
		for i := 0; i < 32; i++ {
			password, err := GeneratePassword(24)
			require.NoError(t, err)
			require.NotContains(t, seen, password)
			seen[password] = struct{}{}
		}
	})

	t.Run("avoids ambiguous characters", func(t *testing.T) {
		for i := 0; i < 32; i++ {
			password, err := GeneratePassword(24)
			require.NoError(t, err)
			assert.NotContains(t, password, "0")
			assert.NotContains(t, password, "O")
			assert.NotContains(t, password, "1")
			assert.NotContains(t, password, "l")
			assert.NotEqual(t, strings.Repeat(" ", len(password)), password)
		}
	})
}
