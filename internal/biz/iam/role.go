package iam

import (
	"context"
	"time"

	"grain/pkg/db"
)

// Role is the role domain object (Domain Object - DO)
type Role struct {
	ID        uint64
	Name      string
	Descr     string
	ApiIDs    []uint64
	Apis      []*Api
	MenuIDs   []uint64
	Menus     []*Menu
	ButtonIDs []uint64
	Buttons   []*Button
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RoleListOptions are the role list query options
type RoleListOptions struct {
	Offset   int
	PageSize int
	Filters  []db.ListFilter
	OrderBy  string
}

// RoleRepo is the role repo interface contract
type RoleRepo interface {
	Create(ctx context.Context, role *Role) (*Role, error)
	Update(ctx context.Context, role *Role) (*Role, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*Role, error)
	FindByName(ctx context.Context, name string) (*Role, error)
	List(ctx context.Context, opts RoleListOptions) ([]*Role, int64, error)
	ListAllWithRelations(ctx context.Context) ([]*Role, error)
	CountUsersByRoleID(ctx context.Context, roleID uint64) (int64, error)

	// Casbin grouping policies
	AddGroupPolicy(ctx context.Context, role *Role) error
	RemoveGroupPolicy(ctx context.Context, role *Role) error
}
