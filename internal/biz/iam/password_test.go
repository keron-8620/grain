package iam

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/errorx"
)

func TestPasswordPolicy_Validate(t *testing.T) {
	tests := []struct {
		name     string
		level    int
		password string
		wantErr  bool
	}{
		{name: "level0 short", level: 0, password: "12345", wantErr: true},
		{name: "level0 ok", level: 0, password: "123456", wantErr: false},
		{name: "level1 short", level: 1, password: "1234567", wantErr: true},
		{name: "level1 ok", level: 1, password: "12345678", wantErr: false},
		{name: "level2 missing digit", level: 2, password: "abcdefgh", wantErr: true},
		{name: "level2 missing letter", level: 2, password: "12345678", wantErr: true},
		{name: "level2 ok", level: 2, password: "abcd1234", wantErr: false},
		{name: "level3 too short", level: 3, password: "Abcdefg1!x", wantErr: true},
		{name: "level3 missing upper", level: 3, password: "abcdefg1!xyz", wantErr: true},
		{name: "level3 missing lower", level: 3, password: "ABCDEFG1!XYZ", wantErr: true},
		{name: "level3 missing digit", level: 3, password: "Abcdefgh!XYZ", wantErr: true},
		{name: "level3 missing symbol", level: 3, password: "Abcdefgh12XY", wantErr: true},
		{name: "level3 ok", level: 3, password: "Abcdefg1!xyz", wantErr: false},
		{name: "over bcrypt limit", level: 0, password: strings.Repeat("a", 73), wantErr: true},
		{name: "whitespace rejected", level: 1, password: "abcd 1234", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (PasswordPolicy{StrengthLevel: tt.level}).Validate(tt.password)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPasswordPolicy_ValidateLevel(t *testing.T) {
	require.NoError(t, (PasswordPolicy{StrengthLevel: 0}).ValidateLevel())
	require.NoError(t, (PasswordPolicy{StrengthLevel: 3}).ValidateLevel())
	assert.Error(t, (PasswordPolicy{StrengthLevel: -1}).ValidateLevel())
	assert.Error(t, (PasswordPolicy{StrengthLevel: 4}).ValidateLevel())
}
