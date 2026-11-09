package auth

import (
	"strings"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"
)

// Sentinel error definitions for the auth package.
var (
	// ErrTokenInvalid is the general umbrella sentinel error for any token validation failure.
	// All specific token-related sentinel errors match ErrTokenInvalid via errors.Is.
	ErrTokenInvalid = errors.Sentinel("invalid token")

	// ErrTokenEmpty occurs when the token string is empty or contains only whitespace.
	ErrTokenEmpty = errors.Sentinel("token must not be empty")

	// ErrTokenExpired occurs when the token's exp claim is in the past beyond the allowed leeway.
	ErrTokenExpired = errors.Sentinel("token is expired")

	// ErrTokenNotValidYet occurs when the token's nbf claim is in the future beyond the allowed leeway.
	ErrTokenNotValidYet = errors.Sentinel("token is not valid yet")

	// ErrTokenSignatureInvalid occurs when the signature cannot be verified with any available public key.
	ErrTokenSignatureInvalid = errors.Sentinel("token signature is invalid")

	// ErrTokenMalformed occurs when the token string structure is syntactically invalid.
	ErrTokenMalformed = errors.Sentinel("token format is malformed")

	// ErrTokenAlgorithmMismatch occurs when the token algorithm does not match the configured algorithm.
	ErrTokenAlgorithmMismatch = errors.Sentinel("token signing algorithm mismatch")

	// ErrTokenInvalidIssuer occurs when the token's iss claim does not match the configured issuer.
	ErrTokenInvalidIssuer = errors.Sentinel("token issuer is invalid")

	// ErrTokenInvalidAudience occurs when the token's aud claim does not match the configured audience.
	ErrTokenInvalidAudience = errors.Sentinel("token audience is invalid")

	// ErrTokenTypeMismatch occurs when the token type is not "access" (e.g. a refresh token was passed).
	ErrTokenTypeMismatch = errors.Sentinel("token type must be access")

	// ErrTokenClaimsInvalid occurs when required claims (uid, un, jti, sub) are missing or inconsistent.
	ErrTokenClaimsInvalid = errors.Sentinel("token claims are invalid")

	// ErrTokenRevoked occurs when the token's version does not match the active server token version.
	ErrTokenRevoked = errors.Sentinel("token has been revoked")

	// ErrTokenFamilyRevoked occurs when the session family (fid) has been explicitly revoked (e.g. single-device logout or refresh replay).
	ErrTokenFamilyRevoked = errors.Sentinel("session family has been revoked")

	// ErrTokenVersionUnavailable occurs when the token revocation status cannot be verified (store unconfigured, missing baseline, etc.).
	ErrTokenVersionUnavailable = errors.Sentinel("token version check unavailable")

	// ErrAuthConfigInvalid occurs when the authenticator lacks required configuration (key, method, etc.).
	ErrAuthConfigInvalid = errors.Sentinel("authenticator is not properly configured")
)

// AuthError represents a structured authentication error carrying a sentinel classification,
// the underlying cause, and contextual error message.
type AuthError struct {
	sentinel error
	cause    error
	msg      string
}

// Error formats the error string, preserving the prefix message and the underlying cause message.
func (e *AuthError) Error() string {
	if e.msg != "" {
		if e.cause != nil && e.cause.Error() != e.msg {
			return e.msg + ": " + e.cause.Error()
		}
		return e.msg
	}
	if e.cause != nil {
		return e.sentinel.Error() + ": " + e.cause.Error()
	}
	return e.sentinel.Error()
}

// Unwrap exposes the underlying cause error, falling back to sentinel if no cause is set.
func (e *AuthError) Unwrap() error {
	if e.cause != nil {
		return e.cause
	}
	return e.sentinel
}

// Cause returns the underlying root cause or the sentinel itself.
func (e *AuthError) Cause() error {
	if e.cause != nil {
		return e.cause
	}
	return e.sentinel
}

// Is reports whether e matches target, supporting sentinel matching, ErrTokenInvalid umbrella matching,
// and delegation to the underlying cause.
func (e *AuthError) Is(target error) bool {
	if target == nil {
		return false
	}
	if e.sentinel == target || errors.Is(e.sentinel, target) {
		return true
	}
	if target == ErrTokenRevoked && e.sentinel == ErrTokenFamilyRevoked {
		return true
	}
	if target == ErrTokenInvalid && isTokenSpecificError(e.sentinel) {
		return true
	}
	if e.cause != nil && errors.Is(e.cause, target) {
		return true
	}
	return false
}

// isTokenSpecificError reports whether a sentinel is a token-specific validation error.
func isTokenSpecificError(err error) bool {
	switch err {
	case ErrTokenEmpty,
		ErrTokenExpired,
		ErrTokenNotValidYet,
		ErrTokenSignatureInvalid,
		ErrTokenMalformed,
		ErrTokenAlgorithmMismatch,
		ErrTokenInvalidIssuer,
		ErrTokenInvalidAudience,
		ErrTokenTypeMismatch,
		ErrTokenClaimsInvalid,
		ErrTokenRevoked,
		ErrTokenFamilyRevoked:
		return true
	default:
		return false
	}
}

// wrapAuthError constructs an error annotated with call-site stack trace and structured details using emperror.dev/errors.
func wrapAuthError(sentinel error, cause error, msg string, details ...any) error {
	var err error = &AuthError{
		sentinel: sentinel,
		cause:    cause,
		msg:      msg,
	}
	// Annotate error with stack trace at the call site using emperror.dev/errors
	err = errors.WithStack(err)
	if len(details) > 0 {
		err = errors.WithDetails(err, details...)
	}
	return err
}

// classifyJWTError categorizes errors from jwt.ParseWithClaims into specific auth sentinel errors.
func classifyJWTError(err error) error {
	if err == nil {
		return ErrTokenInvalid
	}
	if errors.Is(err, jwt.ErrTokenExpired) {
		return ErrTokenExpired
	}
	if errors.Is(err, jwt.ErrTokenNotValidYet) {
		return ErrTokenNotValidYet
	}
	if errors.Is(err, jwt.ErrTokenSignatureInvalid) || errors.Is(err, jwt.ErrSignatureInvalid) || isSignatureFailure(err) {
		return ErrTokenSignatureInvalid
	}
	if errors.Is(err, jwt.ErrTokenMalformed) {
		return ErrTokenMalformed
	}
	if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		return ErrTokenInvalidIssuer
	}
	if errors.Is(err, jwt.ErrTokenInvalidAudience) {
		return ErrTokenInvalidAudience
	}
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "signing algorithm mismatch") || strings.Contains(errMsg, "token has no signing method") {
		return ErrTokenAlgorithmMismatch
	}
	if strings.Contains(errMsg, "unknown key id") {
		return ErrTokenSignatureInvalid
	}
	if strings.Contains(errMsg, "token contains an invalid number of segments") || strings.Contains(errMsg, "illegal base64 data") {
		return ErrTokenMalformed
	}
	return ErrTokenInvalid
}

// IsTokenExpired reports whether err is due to token expiration.
func IsTokenExpired(err error) bool { return errors.Is(err, ErrTokenExpired) }

// IsTokenRevoked reports whether err is due to token revocation (including user token version and session family revocation).
func IsTokenRevoked(err error) bool { return errors.Is(err, ErrTokenRevoked) }

// IsTokenFamilyRevoked reports whether err is due to session family revocation.
func IsTokenFamilyRevoked(err error) bool { return errors.Is(err, ErrTokenFamilyRevoked) }

// IsTokenInvalid reports whether err represents any invalid token error.
func IsTokenInvalid(err error) bool { return errors.Is(err, ErrTokenInvalid) }

// IsTokenSignatureInvalid reports whether err is due to invalid token signature.
func IsTokenSignatureInvalid(err error) bool { return errors.Is(err, ErrTokenSignatureInvalid) }

// IsTokenMalformed reports whether err is due to malformed token string.
func IsTokenMalformed(err error) bool { return errors.Is(err, ErrTokenMalformed) }

// IsTokenTypeMismatch reports whether err is due to token type mismatch.
func IsTokenTypeMismatch(err error) bool { return errors.Is(err, ErrTokenTypeMismatch) }

// IsTokenVersionUnavailable reports whether err is due to token version store unavailability.
func IsTokenVersionUnavailable(err error) bool { return errors.Is(err, ErrTokenVersionUnavailable) }
