package iam

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"grain/pkg/db/filter"
	"grain/pkg/errorx"
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
	FindByRoutes(ctx context.Context, routes []ApiRoute) ([]*Api, error)
	List(ctx context.Context, opts ApiListOptions) ([]*Api, int64, error)
	SyncRoutes(ctx context.Context, routes []ApiRoute) (int, error)

	// Casbin policy management
	AddPolicy(ctx context.Context, api *Api) error
	AddPolicies(ctx context.Context, apis []*Api) error
	UpdatePolicy(ctx context.Context, oldApi, newApi *Api) error
	RemovePolicy(ctx context.Context, api *Api, removeInherited bool) error
}

// ApiUseCase handles API management and access policy synchronization.
type ApiUseCase struct {
	repo   ApiRepo
	logger *slog.Logger
}

// NewApiUseCase creates a new ApiUseCase instance.
func NewApiUseCase(repo ApiRepo, logger *slog.Logger) *ApiUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	return &ApiUseCase{
		repo:   repo,
		logger: logger,
	}
}

// Create creates a new API resource and initializes its Casbin policy.
func (uc *ApiUseCase) Create(ctx context.Context, api *Api) (*Api, error) {
	if api == nil {
		return nil, errorx.CodeInvalidParam.Error("API信息不能为空")
	}

	url := strings.TrimSpace(api.URL)
	method := strings.ToUpper(strings.TrimSpace(api.Method))
	if url == "" || method == "" {
		return nil, errorx.CodeMissingParam.Error("API URL和请求方法不能为空")
	}

	api.URL = url
	api.Method = method

	existing, err := uc.repo.FindByURLAndMethod(ctx, url, method)
	if err != nil && !errorx.IsRecordNotFound(err) {
		return nil, errorx.FromDBError(err)
	}
	if existing != nil {
		return nil, errorx.CodeDuplicatedKey.Error("该API路由已存在")
	}

	created, err := uc.repo.Create(ctx, api)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := uc.repo.Delete(rbCtx, created.ID); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back API model creation", slog.Uint64("api_id", created.ID), slog.Any("error", err))
		}
	}

	if err := uc.repo.AddPolicy(ctx, created); err != nil {
		uc.logger.ErrorContext(ctx, "failed to add casbin policy for api", slog.Uint64("api_id", created.ID), slog.Any("error", err))
		rollback()
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "添加API权限策略失败")
	}

	return created, nil
}

// Update updates an existing API resource and synchronizes its Casbin policy.
func (uc *ApiUseCase) Update(ctx context.Context, api *Api) (*Api, error) {
	if api == nil || api.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的API ID")
	}

	url := strings.TrimSpace(api.URL)
	method := strings.ToUpper(strings.TrimSpace(api.Method))
	if url == "" || method == "" {
		return nil, errorx.CodeMissingParam.Error("API URL和请求方法不能为空")
	}

	api.URL = url
	api.Method = method

	oldApi, err := uc.repo.FindByID(ctx, api.ID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldApi == nil {
		return nil, errorx.CodeRecordNotFound.Error("API不存在")
	}

	if oldApi.URL != api.URL || oldApi.Method != api.Method {
		existing, err := uc.repo.FindByURLAndMethod(ctx, api.URL, api.Method)
		if err != nil && !errorx.IsRecordNotFound(err) {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != api.ID {
			return nil, errorx.CodeDuplicatedKey.Error("该API路由已被其他记录使用")
		}
	}

	updated, err := uc.repo.Update(ctx, api)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if _, err := uc.repo.Update(rbCtx, oldApi); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back API model update", slog.Uint64("api_id", api.ID), slog.Any("error", err))
		}
		_ = uc.repo.RemovePolicy(rbCtx, updated, false)
		_ = uc.repo.AddPolicy(rbCtx, oldApi)
	}

	if err := uc.repo.UpdatePolicy(ctx, oldApi, updated); err != nil {
		uc.logger.ErrorContext(ctx, "failed to update casbin policy for api", slog.Uint64("api_id", api.ID), slog.Any("error", err))
		rollback()
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "更新API权限策略失败")
	}

	return updated, nil
}

// Delete deletes an API resource by ID and removes its Casbin policy.
func (uc *ApiUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的API ID")
	}

	api, err := uc.repo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if api == nil {
		return errorx.CodeRecordNotFound.Error("API不存在")
	}

	if err := uc.repo.Delete(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}

	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := uc.repo.RemovePolicy(cleanCtx, api, true); err != nil {
		uc.logger.ErrorContext(ctx, "failed to remove casbin policy for api", slog.Uint64("api_id", id), slog.Any("error", err))
		return errorx.Wrap(err, errorx.CodeSystemError, "删除API权限策略失败")
	}

	return nil
}

// Get finds an API resource by primary key ID.
func (uc *ApiUseCase) Get(ctx context.Context, id uint64) (*Api, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的API ID")
	}

	api, err := uc.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if api == nil {
		return nil, errorx.CodeRecordNotFound.Error("API不存在")
	}

	return api, nil
}

// GetByURLAndMethod finds an API resource by URL pattern and HTTP method.
func (uc *ApiUseCase) GetByURLAndMethod(ctx context.Context, url, method string) (*Api, error) {
	cleanURL := strings.TrimSpace(url)
	cleanMethod := strings.ToUpper(strings.TrimSpace(method))
	if cleanURL == "" || cleanMethod == "" {
		return nil, errorx.CodeMissingParam.Error("URL和请求方法不能为空")
	}

	api, err := uc.repo.FindByURLAndMethod(ctx, cleanURL, cleanMethod)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if api == nil {
		return nil, errorx.CodeRecordNotFound.Error("API不存在")
	}

	return api, nil
}

// List lists API resources with pagination and filtering conditions.
func (uc *ApiUseCase) List(ctx context.Context, opts ApiListOptions) ([]*Api, int64, error) {
	apis, total, err := uc.repo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return apis, total, nil
}

// SyncRoutes synchronizes registered routes into the API catalog and ensures policies exist in batch.
func (uc *ApiUseCase) SyncRoutes(ctx context.Context, routes []ApiRoute) (int, error) {
	if len(routes) == 0 {
		return 0, nil
	}

	count, err := uc.repo.SyncRoutes(ctx, routes)
	if err != nil {
		return 0, errorx.FromDBError(err)
	}
	if count == 0 {
		return 0, nil
	}

	// Query created/existing APIs for the synced routes in a single batch query
	apis, err := uc.repo.FindByRoutes(ctx, routes)
	if err != nil {
		uc.logger.WarnContext(ctx, "failed to query APIs for synced routes", slog.Any("error", err))
		return count, nil
	}

	// Ensure authorization policy rules exist in Casbin for newly synced routes in a single batch
	if len(apis) > 0 {
		if polErr := uc.repo.AddPolicies(ctx, apis); polErr != nil {
			uc.logger.WarnContext(ctx, "failed to add batch casbin policies for synced routes", slog.Int("api_count", len(apis)), slog.Any("error", polErr))
		}
	}

	return count, nil
}
