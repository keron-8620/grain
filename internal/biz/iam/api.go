package iam

import (
	"context"
	"time"

	"grain/pkg/db/filter"
)

// Api is the API domain model (Domain Object - DO); it carries no storage driver tags such as gorm or json.
type Api struct {
	ID        uint64
	URL       string
	Method    string
	Label     string
	Descr     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ApiListOptions defines the API list query conditions.
type ApiListOptions struct {
	Offset   int
	PageSize int
	Filters  []filter.ListFilter
	OrderBy  string
}

// ApiRoute is a record synced from an actual registered route into the API catalog (the object source for Casbin authorization).
type ApiRoute struct {
	URL    string
	Method string
	Label  string
	Descr  string
}

// ApiRepo is the API repository interface contract.
type ApiRepo interface {
	Create(ctx context.Context, api *Api) (*Api, error)
	Update(ctx context.Context, api *Api) (*Api, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64) (*Api, error)
	FindByIDs(ctx context.Context, ids []uint64) ([]*Api, error)
	FindByURLAndMethod(ctx context.Context, url, method string) (*Api, error)
	List(ctx context.Context, opts ApiListOptions) ([]*Api, int64, error)
	SyncRoutes(ctx context.Context, routes []ApiRoute) (int, error)

	// Casbin policy management
	AddPolicy(ctx context.Context, api *Api) error
	UpdatePolicy(ctx context.Context, oldApi, newApi *Api) error
	RemovePolicy(ctx context.Context, api *Api, removeInherited bool) error
}
