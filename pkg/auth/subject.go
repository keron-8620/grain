// Package auth exposes the JWT and authorization vocabulary of IAM to its consumers.
//
// The subject grammar is defined here, once, because it is shared with the issuer: a service that
// re-implements "<prefix><id>" on its own will eventually disagree with IAM, and a mismatch in an
// authorization subject is a silent "deny everything" or, worse, an alias for somebody else's
// permissions. Consumers must obtain subjects through this package and never build them from
// request input.
package auth

import (
	"fmt"
	"strconv"
	"strings"
)

// Subject grammar: <authority>:<kind>:<id>
//
//	iam:role:7     a role, the subject an access token or an API key is authorized as
//	iam:api:12     a route/method pair from the catalog (the object of a p rule)
//	iam:menu:3     a menu (inheritance edge and grantable object)
//	iam:button:8   a button (inherits its menu)
//
// The authority names who owns the identity. "iam" is the platform authority, and rules carrying
// it are derived from IAM's relational model; a consumer that wants to authorize its own principals
// must use its own authority (for example llm:key:12) so it can never alias an IAM role by
// formatting a local string. IAM's policy reconciler only ever owns the "iam" authority, so a
// consumer namespace can never be misread as drift and deleted.
const (
	// AuthorityIAM is the platform authority: roles, APIs, menus and buttons owned by IAM.
	AuthorityIAM = "iam"

	// Subject prefixes are kept for documentation and for call sites that need to render a subject
	// prefix in messages; the authoritative rendering is the SDK's Subject.String().
	APISubjectPrefix    = AuthorityIAM + ":api:"
	MenuSubjectPrefix   = AuthorityIAM + ":menu:"
	ButtonSubjectPrefix = AuthorityIAM + ":button:"
	RoleSubjectPrefix   = AuthorityIAM + ":role:"

	// KindRole, KindAPI, KindMenu and KindButton are the subject kinds IAM owns.
	KindRole   = "role"
	KindAPI    = "api"
	KindMenu   = "menu"
	KindButton = "button"
)

// subjectSeparator is ':' — a character that cannot appear in an authority or a kind, and that is
// valid inside a Casbin subject (Casbin treats the value as an opaque string).
const subjectSeparator = ":"

// Subject is a parsed authorization subject.
type Subject struct {
	// Authority is the identity owner ("iam" for everything IAM mints).
	Authority string
	// Kind is one of the Kind* constants.
	Kind string
	// ID is the numeric identifier within that kind.
	ID uint64
}

// String renders the subject in its canonical form.
func (s Subject) String() string {
	return s.Authority + subjectSeparator + s.Kind + subjectSeparator + strconv.FormatUint(s.ID, 10)
}

// IsIAM reports whether the subject belongs to the platform authority IAM owns.
func (s Subject) IsIAM() bool { return s.Authority == AuthorityIAM }

// FormatSubject renders a subject, rejecting a zero ID (which could only ever be a programming
// error: no row in any of the tables has id 0).
func FormatSubject(authority, kind string, id uint64) (string, error) {
	if strings.TrimSpace(authority) == "" {
		return "", fmt.Errorf("subject authority must not be empty")
	}
	if strings.Contains(authority, subjectSeparator) {
		return "", fmt.Errorf("subject authority %q must not contain %q", authority, subjectSeparator)
	}
	if strings.TrimSpace(kind) == "" {
		return "", fmt.Errorf("subject kind must not be empty")
	}
	if strings.Contains(kind, subjectSeparator) {
		return "", fmt.Errorf("subject kind %q must not contain %q", kind, subjectSeparator)
	}
	if id == 0 {
		return "", fmt.Errorf("subject %s:%s must have a non-zero id", authority, kind)
	}
	return Subject{Authority: authority, Kind: kind, ID: id}.String(), nil
}

// ParseSubject parses any well-formed subject. It reports false for values that are not subjects —
// most importantly for route templates and other free-form strings, which are legitimate Casbin
// objects but are not principals.
func ParseSubject(value string) (Subject, bool) {
	trimmed := strings.TrimSpace(value)
	parts := strings.Split(trimmed, subjectSeparator)
	if len(parts) != 3 {
		return Subject{}, false
	}
	if parts[0] == "" || parts[1] == "" {
		return Subject{}, false
	}
	id, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || id == 0 {
		return Subject{}, false
	}
	return Subject{Authority: parts[0], Kind: parts[1], ID: id}, true
}

// ParseSubjectKind parses a subject and requires it to be an IAM subject of the given kind.
func ParseSubjectKind(value, kind string) (uint64, bool) {
	subject, ok := ParseSubject(value)
	if !ok || !subject.IsIAM() || subject.Kind != kind {
		return 0, false
	}
	return subject.ID, true
}

// RoleSubject renders the subject of an IAM role. It is the only supported way to obtain one: a
// subject built by hand from request input is how a consumer would alias somebody else's role.
func RoleSubject(roleID uint64) (string, error) {
	return FormatSubject(AuthorityIAM, KindRole, roleID)
}

// ParseRoleSubject parses "iam:role:<id>".
func ParseRoleSubject(value string) (uint64, bool) { return ParseSubjectKind(value, KindRole) }

// APISubject renders the subject of an IAM API catalog entry.
func APISubject(apiID uint64) (string, error) {
	return FormatSubject(AuthorityIAM, KindAPI, apiID)
}

// ParseAPISubject parses "iam:api:<id>".
func ParseAPISubject(value string) (uint64, bool) { return ParseSubjectKind(value, KindAPI) }

// MenuSubject renders the subject of an IAM menu.
func MenuSubject(menuID uint64) (string, error) {
	return FormatSubject(AuthorityIAM, KindMenu, menuID)
}

// ParseMenuSubject parses "iam:menu:<id>".
func ParseMenuSubject(value string) (uint64, bool) { return ParseSubjectKind(value, KindMenu) }

// ButtonSubject renders the subject of an IAM button.
func ButtonSubject(buttonID uint64) (string, error) {
	return FormatSubject(AuthorityIAM, KindButton, buttonID)
}

// ParseButtonSubject parses "iam:button:<id>".
func ParseButtonSubject(value string) (uint64, bool) { return ParseSubjectKind(value, KindButton) }

// APIToSubject converts an API ID to the corresponding Casbin subject.
func APIToSubject(pk uint64) string {
	subject, err := APISubject(pk)
	if err != nil {
		// A zero ID can only come from a programming error upstream; returning the canonical form of
		// the zero value keeps the failure visible in the rule set instead of silently inventing a
		// subject that could match something else.
		return fmt.Sprintf("%s%d", APISubjectPrefix, pk)
	}
	return subject
}

// ApiToSubject is an alias for APIToSubject for backward compatibility.
func ApiToSubject(pk uint64) string {
	return APIToSubject(pk)
}

// MenuToSubject converts a menu ID to the corresponding Casbin subject.
func MenuToSubject(pk uint64) string {
	subject, err := MenuSubject(pk)
	if err != nil {
		return fmt.Sprintf("%s%d", MenuSubjectPrefix, pk)
	}
	return subject
}

// ButtonToSubject converts a button ID to the corresponding Casbin subject.
func ButtonToSubject(pk uint64) string {
	subject, err := ButtonSubject(pk)
	if err != nil {
		return fmt.Sprintf("%s%d", ButtonSubjectPrefix, pk)
	}
	return subject
}

// RoleToSubject converts a role ID to the corresponding Casbin subject.
func RoleToSubject(pk uint64) string {
	subject, err := RoleSubject(pk)
	if err != nil {
		return fmt.Sprintf("%s%d", RoleSubjectPrefix, pk)
	}
	return subject
}
