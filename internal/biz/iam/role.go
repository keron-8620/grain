package iam

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"grain/pkg/db"
	"grain/pkg/errorx"
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

// RoleUseCase handles role management, permission assignment, and authorization policy synchronization.
type RoleUseCase struct {
	repo     RoleRepo
	userRepo UserRepo
	logger   *slog.Logger
}

// NewRoleUseCase creates a new RoleUseCase instance.
func NewRoleUseCase(repo RoleRepo, userRepo UserRepo, logger *slog.Logger) *RoleUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	return &RoleUseCase{
		repo:     repo,
		userRepo: userRepo,
		logger:   logger,
	}
}

// Create creates a new role and associates it with permissions and Casbin grouping policies.
func (uc *RoleUseCase) Create(ctx context.Context, role *Role) (*Role, error) {
	if role == nil {
		return nil, errorx.CodeInvalidParam.Error("角色信息不能为空")
	}

	name := strings.TrimSpace(role.Name)
	if name == "" {
		return nil, errorx.CodeMissingParam.Error("角色名称不能为空")
	}
	role.Name = name

	existing, err := uc.repo.FindByName(ctx, role.Name)
	if err != nil && !errorx.IsRecordNotFound(err) {
		return nil, errorx.FromDBError(err)
	}
	if existing != nil {
		return nil, errorx.CodeDuplicatedKey.Error("角色名称已存在")
	}

	created, err := uc.repo.Create(ctx, role)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := uc.repo.Delete(rbCtx, created.ID); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back role model creation", slog.Uint64("role_id", created.ID), slog.Any("error", err))
		}
	}

	if err := uc.repo.AddGroupPolicy(ctx, created); err != nil {
		uc.logger.ErrorContext(ctx, "failed to add casbin group policy for role", slog.Uint64("role_id", created.ID), slog.Any("error", err))
		rollback()
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "添加角色权限策略失败")
	}

	return created, nil
}

// Update updates an existing role, synchronizes Casbin policies, and revokes sessions for users under this role.
func (uc *RoleUseCase) Update(ctx context.Context, role *Role) (*Role, error) {
	if role == nil || role.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的角色ID")
	}

	name := strings.TrimSpace(role.Name)
	if name == "" {
		return nil, errorx.CodeMissingParam.Error("角色名称不能为空")
	}
	role.Name = name

	oldRole, err := uc.repo.FindByID(ctx, role.ID, "Apis", "Menus", "Buttons")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldRole == nil {
		return nil, errorx.CodeRecordNotFound.Error("角色不存在")
	}

	// Ensure slice fields are non-nil so DB rollback can clear associations if they were originally empty
	if oldRole.Apis == nil {
		oldRole.Apis = []*Api{}
	}
	if oldRole.Menus == nil {
		oldRole.Menus = []*Menu{}
	}
	if oldRole.Buttons == nil {
		oldRole.Buttons = []*Button{}
	}

	if oldRole.Name != role.Name {
		existing, err := uc.repo.FindByName(ctx, role.Name)
		if err != nil && !errorx.IsRecordNotFound(err) {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != role.ID {
			return nil, errorx.CodeDuplicatedKey.Error("角色名称已被使用")
		}
	}

	updated, err := uc.repo.Update(ctx, role)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if _, err := uc.repo.Update(rbCtx, oldRole); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back role model update", slog.Uint64("role_id", role.ID), slog.Any("error", err))
		}
		_ = uc.repo.RemoveGroupPolicy(rbCtx, updated)
		_ = uc.repo.AddGroupPolicy(rbCtx, oldRole)
	}

	_ = uc.repo.RemoveGroupPolicy(ctx, oldRole)
	if err := uc.repo.AddGroupPolicy(ctx, updated); err != nil {
		uc.logger.ErrorContext(ctx, "failed to update casbin group policy for role", slog.Uint64("role_id", role.ID), slog.Any("error", err))
		rollback()
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "更新角色权限策略失败")
	}

	// Revoke sessions for all users belonging to this role so that their privileges are refreshed
	if uc.userRepo != nil {
		userIDs, err := uc.userRepo.ListIDsByRole(ctx, role.ID)
		if err != nil {
			uc.logger.WarnContext(ctx, "failed to query user IDs under role for session revocation", slog.Uint64("role_id", role.ID), slog.Any("error", err))
		} else if len(userIDs) > 0 {
			if revErr := uc.userRepo.IncrementTokenVersionBatch(ctx, userIDs); revErr != nil {
				uc.logger.WarnContext(ctx, "failed to batch revoke sessions for users under role", slog.Uint64("role_id", role.ID), slog.Int("user_count", len(userIDs)), slog.Any("error", revErr))
			}
		}
	}

	return updated, nil
}

// Delete deletes a role by ID if no users are assigned to it, and clears its Casbin grouping policies.
func (uc *RoleUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的角色ID")
	}

	role, err := uc.repo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if role == nil {
		return errorx.CodeRecordNotFound.Error("角色不存在")
	}

	userCount, err := uc.repo.CountUsersByRoleID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if userCount > 0 {
		return errorx.CodeOperationNotAllowed.Error("角色下仍有关联用户，无法删除")
	}

	if err := uc.repo.Delete(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}

	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := uc.repo.RemoveGroupPolicy(cleanCtx, role); err != nil {
		uc.logger.ErrorContext(ctx, "failed to remove casbin group policy for role", slog.Uint64("role_id", id), slog.Any("error", err))
		return errorx.Wrap(err, errorx.CodeSystemError, "删除角色权限策略失败")
	}

	return nil
}

// Get finds a role by primary key ID.
func (uc *RoleUseCase) Get(ctx context.Context, id uint64) (*Role, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的角色ID")
	}

	role, err := uc.repo.FindByID(ctx, id, "Apis", "Menus", "Buttons")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if role == nil {
		return nil, errorx.CodeRecordNotFound.Error("角色不存在")
	}

	return role, nil
}

// GetByName finds a role by name.
func (uc *RoleUseCase) GetByName(ctx context.Context, name string) (*Role, error) {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, errorx.CodeMissingParam.Error("角色名称不能为空")
	}

	role, err := uc.repo.FindByName(ctx, cleanName)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if role == nil {
		return nil, errorx.CodeRecordNotFound.Error("角色不存在")
	}

	return role, nil
}

// List lists roles with conditions.
func (uc *RoleUseCase) List(ctx context.Context, opts RoleListOptions) ([]*Role, int64, error) {
	roles, total, err := uc.repo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return roles, total, nil
}

// ListAllWithRelations lists all roles preloaded with relations.
func (uc *RoleUseCase) ListAllWithRelations(ctx context.Context) ([]*Role, error) {
	roles, err := uc.repo.ListAllWithRelations(ctx)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return roles, nil
}
