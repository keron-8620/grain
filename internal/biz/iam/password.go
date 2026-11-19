package iam

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"grain/pkg/errorx"
)

// PasswordPolicy enforces the configured password strength level.
//
// Levels:
//
//	0 - minimum 6 characters (legacy default)
//	1 - minimum 8 characters
//	2 - minimum 8 characters and both letters and digits
//	3 - minimum 12 characters, upper/lowercase letters, digits and a symbol
type PasswordPolicy struct {
	StrengthLevel int
}

// ValidateLevel checks that the configured level is supported.
func (p PasswordPolicy) ValidateLevel() error {
	if p.StrengthLevel < 0 || p.StrengthLevel > 3 {
		return fmt.Errorf("password.strength_level must be between 0 and 3, got %d", p.StrengthLevel)
	}
	return nil
}

// Validate returns a CodePasswordStrengthFailed error when the password does
// not satisfy the configured policy. It also caps passwords at 72 bytes, the
// effective bcrypt input limit.
func (p PasswordPolicy) Validate(password string) error {
	if err := p.ValidateLevel(); err != nil {
		return errorx.Wrap(err, errorx.CodeConfigError, "密码策略配置无效")
	}

	minLength := 6
	switch p.StrengthLevel {
	case 1, 2:
		minLength = 8
	case 3:
		minLength = 12
	}
	if utf8.RuneCountInString(password) < minLength {
		return errorx.CodePasswordStrengthFailed.Error(fmt.Sprintf("密码长度不能少于%d位", minLength))
	}
	if len(password) > 72 {
		return errorx.CodePasswordStrengthFailed.Error("密码长度不能超过72字节")
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errorx.CodePasswordStrengthFailed.Error("密码不能包含空白或控制字符")
		}
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsLetter(r):
			// Unclassified letters (e.g. CJK) count as letters but not case.
		default:
			hasSymbol = true
		}
	}

	switch p.StrengthLevel {
	case 2:
		if (!hasUpper && !hasLower) || !hasDigit {
			return errorx.CodePasswordStrengthFailed.Error("密码必须同时包含字母和数字")
		}
	case 3:
		if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
			return errorx.CodePasswordStrengthFailed.Error("密码必须同时包含大写字母、小写字母、数字和特殊字符")
		}
	}
	return nil
}
