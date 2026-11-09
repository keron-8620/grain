package iam

import (
	"context"
	"time"

	"grain/pkg/db"
)

// Button is the button domain model (Domain Object - DO).
type Button struct {
	ID        uint64
	Name      string
	Sort      uint32
	IsActive  bool
	Descr     string
	MenuID    uint64
	Menu      *Menu
	ApiIDs    []uint64
	Apis      []*Api
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ButtonListOptions defines the button list query conditions.
type ButtonListOptions struct {
	Offset   int
	PageSize int
	Filters  []db.ListFilter
	OrderBy  string
}

// ButtonRepo is the button repository interface contract.
type ButtonRepo interface {
	Create(ctx context.Context, button *Button) (*Button, error)
	Update(ctx context.Context, button *Button) (*Button, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*Button, error)
	FindByIDs(ctx context.Context, ids []uint64, preloads ...string) ([]*Button, error)
	FindByName(ctx context.Context, name string) (*Button, error)
	List(ctx context.Context, opts ButtonListOptions) ([]*Button, int64, error)
	ListAllWithApis(ctx context.Context) ([]*Button, error)

	// Casbin grouping policies
	AddGroupPolicy(ctx context.Context, button *Button) error
	RemoveGroupPolicy(ctx context.Context, button *Button, removeInherited bool) error
}
