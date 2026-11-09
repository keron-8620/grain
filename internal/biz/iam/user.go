package iam

import (
	"context"
	"time"

	"grain/pkg/db"
)

// User is the user domain object (Domain Object - DO)
type User struct {
	ID           uint64
	Username     string
	Password     string
	IsActive     bool
	RoleID       uint64
	Role         *Role
	TokenVersion uint64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Sanitize clears sensitive credential fields (such as the password hash) to avoid leaking them to upper layers
func (u *User) Sanitize() *User {
	if u != nil {
		u.Password = ""
	}
	return u
}

// UserListOptions are the user list query options
type UserListOptions struct {
	Offset   int
	PageSize int
	Filters  []db.ListFilter
	OrderBy  string
}

// UserRepo is the user repo interface contract
type UserRepo interface {
	Create(ctx context.Context, user *User) (*User, error)
	Update(ctx context.Context, user *User) (*User, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*User, error)
	FindByUsername(ctx context.Context, username string, preloads ...string) (*User, error)
	List(ctx context.Context, opts UserListOptions) ([]*User, int64, error)
	ListIDsByRole(ctx context.Context, roleID uint64) ([]uint64, error)

	// Token version and session revocation
	IncrementTokenVersion(ctx context.Context, userID uint64) error
	IncrementTokenVersionBatch(ctx context.Context, userIDs []uint64) error
	GetTokenVersion(ctx context.Context, userID uint64) (uint64, error)
	EnsureTokenVersionCache(ctx context.Context, userID uint64, version uint64) error
	ConsumeRefreshToken(ctx context.Context, jti string, ttl time.Duration) (bool, error)
	RotateRefreshTokenFamily(ctx context.Context, familyID, oldJTI, newJTI string, userID uint64, ttl time.Duration) (RotateFamilyResult, error)
}

// RotateFamilyResult represents the outcome of a token family rotation operation.
type RotateFamilyResult int

const (
	RotateFamilySuccess RotateFamilyResult = iota
	RotateFamilyCompromised
	RotateFamilyFailed
)
