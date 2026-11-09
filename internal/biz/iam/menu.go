package iam

import (
	"context"
	"grain/pkg/db"
	"time"
)

// MenuMeta is menu metadata (a pure domain object).
type MenuMeta struct {
	Title string
	Icon  string
}

// Menu is the menu domain model (Domain Object - DO).
type Menu struct {
	ID        uint64
	Path      string
	Component string
	Name      string
	Meta      MenuMeta
	Sort      uint32
	IsActive  bool
	Descr     string
	ParentID  *uint64
	Parent    *Menu
	ApiIDs    []uint64
	Apis      []*Api
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MenuListOptions defines the menu list query conditions.
type MenuListOptions struct {
	Offset   int
	PageSize int
	Filters  []db.ListFilter
	OrderBy  string
}

// MenuRepo is the menu repository interface contract.
type MenuRepo interface {
	Create(ctx context.Context, menu *Menu) (*Menu, error)
	Update(ctx context.Context, menu *Menu) (*Menu, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*Menu, error)
	FindByIDs(ctx context.Context, ids []uint64, preloads ...string) ([]*Menu, error)
	FindByName(ctx context.Context, name string) (*Menu, error)
	FindByPath(ctx context.Context, path string) (*Menu, error)
	List(ctx context.Context, opts MenuListOptions) ([]*Menu, int64, error)
	ListAllWithApis(ctx context.Context) ([]*Menu, error)

	// Casbin grouping policies
	AddGroupPolicy(ctx context.Context, menu *Menu) error
	RemoveGroupPolicy(ctx context.Context, menu *Menu, removeInherited bool) error
}
