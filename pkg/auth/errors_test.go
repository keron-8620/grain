package auth

import (
	"fmt"
	"testing"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthErrors(t *testing.T) {
	t.Run("wrapAuthError with details and stack", func(t *testing.T) {
		cause := errors.New("underlying jwt failure")
		err := wrapAuthError(ErrTokenExpired, cause, "invalid token", "user_id", uint64(101), "action", "verify")
		require.Error(t, err)

		// 1. Check formatted string
		assert.Equal(t, "invalid token: underlying jwt failure", err.Error())

		// 2. errors.Is specific sentinel
		assert.True(t, errors.Is(err, ErrTokenExpired))
		assert.True(t, IsTokenExpired(err))

		// 3. errors.Is umbrella ErrTokenInvalid
		assert.True(t, errors.Is(err, ErrTokenInvalid))
		assert.True(t, IsTokenInvalid(err))

		// 4. errors.Is underlying cause
		assert.True(t, errors.Is(err, cause))

		// 5. Unrelated errors do not match
		assert.False(t, errors.Is(err, ErrTokenSignatureInvalid))
		assert.False(t, errors.Is(err, ErrTokenRevoked))

		// 6. Extract structured details
		details := errors.GetDetails(err)
		require.Len(t, details, 4)
		assert.Equal(t, "user_id", details[0])
		assert.Equal(t, uint64(101), details[1])
		assert.Equal(t, "action", details[2])
		assert.Equal(t, "verify", details[3])

		// 7. Verify stack trace presence in %+v formatting
		stackStr := fmt.Sprintf("%+v", err)
		assert.Contains(t, stackStr, "errors_test.go")
	})

	t.Run("wrapAuthError without cause", func(t *testing.T) {
		err := wrapAuthError(ErrTokenEmpty, nil, "token must not be empty")
		assert.Equal(t, "token must not be empty", err.Error())
		assert.True(t, errors.Is(err, ErrTokenEmpty))
		assert.True(t, errors.Is(err, ErrTokenInvalid))
		assert.False(t, errors.Is(err, ErrTokenExpired))
		assert.Equal(t, ErrTokenEmpty, errors.Cause(err))
	})

	t.Run("classifyJWTError mappings", func(t *testing.T) {
		assert.Equal(t, ErrTokenExpired, classifyJWTError(jwt.ErrTokenExpired))
		assert.Equal(t, ErrTokenNotValidYet, classifyJWTError(jwt.ErrTokenNotValidYet))
		assert.Equal(t, ErrTokenSignatureInvalid, classifyJWTError(jwt.ErrTokenSignatureInvalid))
		assert.Equal(t, ErrTokenSignatureInvalid, classifyJWTError(jwt.ErrSignatureInvalid))
		assert.Equal(t, ErrTokenMalformed, classifyJWTError(jwt.ErrTokenMalformed))
		assert.Equal(t, ErrTokenInvalidIssuer, classifyJWTError(jwt.ErrTokenInvalidIssuer))
		assert.Equal(t, ErrTokenInvalidAudience, classifyJWTError(jwt.ErrTokenInvalidAudience))
		assert.Equal(t, ErrTokenAlgorithmMismatch, classifyJWTError(errors.New("signing algorithm mismatch: HS256 != RS256")))
		assert.Equal(t, ErrTokenAlgorithmMismatch, classifyJWTError(errors.New("token has no signing method")))
		assert.Equal(t, ErrTokenSignatureInvalid, classifyJWTError(errors.New("unknown key id 12345")))
		assert.Equal(t, ErrTokenMalformed, classifyJWTError(errors.New("token contains an invalid number of segments")))
		assert.Equal(t, ErrTokenInvalid, classifyJWTError(errors.New("generic jwt failure")))
		assert.Equal(t, ErrTokenInvalid, classifyJWTError(nil))
	})

	t.Run("sentinel helpers", func(t *testing.T) {
		expiredErr := wrapAuthError(ErrTokenExpired, nil, "token expired")
		assert.True(t, IsTokenExpired(expiredErr))
		assert.False(t, IsTokenRevoked(expiredErr))

		revokedErr := wrapAuthError(ErrTokenRevoked, nil, "token revoked")
		assert.True(t, IsTokenRevoked(revokedErr))
		assert.True(t, IsTokenInvalid(revokedErr))

		famRevokedErr := wrapAuthError(ErrTokenFamilyRevoked, nil, "session family revoked")
		assert.True(t, IsTokenFamilyRevoked(famRevokedErr))
		assert.True(t, IsTokenRevoked(famRevokedErr)) // backward compatible: family revocation matches ErrTokenRevoked
		assert.True(t, IsTokenInvalid(famRevokedErr)) // umbrella error matches ErrTokenInvalid
		assert.True(t, errors.Is(famRevokedErr, ErrTokenFamilyRevoked))
		assert.True(t, errors.Is(famRevokedErr, ErrTokenRevoked))
		assert.True(t, errors.Is(famRevokedErr, ErrTokenInvalid))

		sigErr := wrapAuthError(ErrTokenSignatureInvalid, nil, "bad signature")
		assert.True(t, IsTokenSignatureInvalid(sigErr))

		malformedErr := wrapAuthError(ErrTokenMalformed, nil, "malformed")
		assert.True(t, IsTokenMalformed(malformedErr))

		typeMismatchErr := wrapAuthError(ErrTokenTypeMismatch, nil, "type mismatch")
		assert.True(t, IsTokenTypeMismatch(typeMismatchErr))

		versionUnavailErr := wrapAuthError(ErrTokenVersionUnavailable, nil, "redis down")
		assert.True(t, IsTokenVersionUnavailable(versionUnavailErr))
		assert.False(t, IsTokenInvalid(versionUnavailErr)) // Infrastructure failure, not a token validation failure
	})

	t.Run("AuthError edge methods", func(t *testing.T) {
		e := &AuthError{sentinel: ErrTokenExpired}
		assert.Equal(t, "token is expired", e.Error())
		assert.Equal(t, ErrTokenExpired, e.Unwrap())
		assert.Equal(t, ErrTokenExpired, e.Cause())
		assert.False(t, e.Is(nil))

		eWithMsgAndCause := &AuthError{
			sentinel: ErrTokenSignatureInvalid,
			cause:    errors.New("key revoked"),
			msg:      "invalid token",
		}
		assert.Equal(t, "invalid token: key revoked", eWithMsgAndCause.Error())
		assert.Equal(t, errors.New("key revoked").Error(), eWithMsgAndCause.Unwrap().Error())
	})
}
