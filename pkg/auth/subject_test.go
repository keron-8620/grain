package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSubjectGrammar pins the authorization subject language: <authority>:<kind>:<id>. It is part of
// the public contract between IAM and every consumer, and a drift here silently turns into "deny
// everything" or, worse, an alias for another role's permissions.
func TestSubjectGrammar(t *testing.T) {
	role, err := RoleSubject(7)
	require.NoError(t, err)
	assert.Equal(t, "iam:role:7", role)

	api, err := APISubject(12)
	require.NoError(t, err)
	assert.Equal(t, "iam:api:12", api)

	menu, err := MenuSubject(3)
	require.NoError(t, err)
	assert.Equal(t, "iam:menu:3", menu)

	button, err := ButtonSubject(8)
	require.NoError(t, err)
	assert.Equal(t, "iam:button:8", button)

	// Round-trip through the parser, including the kind check.
	id, ok := ParseRoleSubject(role)
	require.True(t, ok)
	assert.Equal(t, uint64(7), id)

	parsed, ok := ParseSubject(role)
	require.True(t, ok)
	assert.Equal(t, Subject{Authority: AuthorityIAM, Kind: KindRole, ID: 7}, parsed)
	assert.True(t, parsed.IsIAM())
	assert.Equal(t, role, parsed.String())

	_, ok = ParseAPISubject(role)
	assert.False(t, ok, "a role subject must not parse as an API subject")

	// 64-bit range round-trip (exceeding uint32 max)
	bigID := uint64(1) << 40
	bigRole, err := RoleSubject(bigID)
	require.NoError(t, err)
	parsedBigID, ok := ParseRoleSubject(bigRole)
	require.True(t, ok)
	assert.Equal(t, bigID, parsedBigID)
}

// TestSubjectGrammar_RejectsNonSubjects pins what must NOT be treated as a principal: zero ids, other
// authorities, route templates and free-form strings. Route templates in particular are legitimate
// Casbin objects and must not be mistaken for identities.
func TestSubjectGrammar_RejectsNonSubjects(t *testing.T) {
	for _, value := range []string{
		"", "iam:role:", "iam:role:0", "iam:role:-1", "iam:role:x",
		"role_7",                // the pre-namespace form is deliberately gone (see the migration)
		"iam:role:7:extra",      // too many segments
		"iam::7",                // missing kind
		":role:7",               // missing authority
		"/api/v1/iam/role/{id}", // a route template, not a principal
		"llm:key:3",             // a consumer authority is parseable but not an IAM subject
	} {
		_, ok := ParseSubject(value)
		if value == "llm:key:3" {
			require.True(t, ok, "a consumer authority is well-formed")
			_, isRole := ParseRoleSubject(value)
			assert.False(t, isRole, "but it is not an IAM role subject")
			continue
		}
		assert.False(t, ok, "%q must not parse as a subject", value)
	}

	// Other authorities are deliberately representable: they are how a consumer names its own
	// principals so they can never alias an IAM role.
	consumer, err := FormatSubject("llm", "key", 12)
	require.NoError(t, err)
	assert.Equal(t, "llm:key:12", consumer)
	parsed, ok := ParseSubject(consumer)
	require.True(t, ok)
	assert.False(t, parsed.IsIAM())
}

func TestFormatSubject_RejectsInvalidInput(t *testing.T) {
	for name, call := range map[string]func() (string, error){
		"empty authority":          func() (string, error) { return FormatSubject("", KindRole, 1) },
		"authority with separator": func() (string, error) { return FormatSubject("i:am", KindRole, 1) },
		"empty kind":               func() (string, error) { return FormatSubject(AuthorityIAM, "", 1) },
		"kind with separator":      func() (string, error) { return FormatSubject(AuthorityIAM, "ro:le", 1) },
		"zero id":                  func() (string, error) { return RoleSubject(0) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			require.Error(t, err)
		})
	}
}

func TestSubjectHelpersAndParsers(t *testing.T) {
	menuID, ok := ParseMenuSubject("iam:menu:10")
	assert.True(t, ok)
	assert.Equal(t, uint64(10), menuID)

	btnID, ok := ParseButtonSubject("iam:button:20")
	assert.True(t, ok)
	assert.Equal(t, uint64(20), btnID)

	assert.Equal(t, "iam:api:100", APIToSubject(100))
	assert.Equal(t, "iam:api:0", APIToSubject(0))

	assert.Equal(t, "iam:menu:200", MenuToSubject(200))
	assert.Equal(t, "iam:menu:0", MenuToSubject(0))

	assert.Equal(t, "iam:button:300", ButtonToSubject(300))
	assert.Equal(t, "iam:button:0", ButtonToSubject(0))

	assert.Equal(t, "iam:role:400", RoleToSubject(400))
	assert.Equal(t, "iam:role:0", RoleToSubject(0))
}
