package iam

import (
	"context"
	"errors"
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
	Apis      []Api
	MenuIDs   []uint64
	Menus     []Menu
	ButtonIDs []uint64
	Buttons   []Button
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RoleRepo is the role repo interface contract
type RoleRepo interface {
	Create(ctx context.Context, role *Role) (*Role, error)
	Update(ctx context.Context, role *Role) (*Role, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*Role, error)
	FindByName(ctx context.Context, name string) (*Role, error)
	List(ctx context.Context, opts db.ListOptions) ([]Role, int64, error)
	ListAllWithRelations(ctx context.Context) ([]Role, error)
	// CountUsersByRoleID counts all users referencing the role, including soft-deleted users.
	CountUsersByRoleID(ctx context.Context, roleID uint64) (int64, error)

	// Casbin grouping policies
	AddGroupPolicy(ctx context.Context, role *Role) error
	RemoveGroupPolicy(ctx context.Context, role *Role) error
}

// RoleUseCase handles role management, permission assignment, and authorization policy synchronization.
type RoleUseCase struct {
	roleRepo RoleRepo
	userRepo UserRepo
	logger   *slog.Logger
}

// NewRoleUseCase creates a new RoleUseCase instance.
func NewRoleUseCase(roleRepo RoleRepo, userRepo UserRepo, logger *slog.Logger) *RoleUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	return &RoleUseCase{
		roleRepo: roleRepo,
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

	existing, err := uc.roleRepo.FindByName(ctx, role.Name)
	if err != nil && !errorx.IsRecordNotFound(err) {
		return nil, errorx.FromDBError(err)
	}
	if existing != nil {
		return nil, errorx.CodeDuplicatedKey.Error("角色名称已存在")
	}

	created, err := uc.roleRepo.Create(ctx, role)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := uc.roleRepo.Delete(rbCtx, created.ID); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back role model creation", slog.Uint64("role_id", created.ID), slog.Any("error", err))
		}
	}

	if err := uc.roleRepo.AddGroupPolicy(ctx, created); err != nil {
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

	oldRole, err := uc.roleRepo.FindByID(ctx, role.ID, "Apis", "Menus", "Buttons")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldRole == nil {
		return nil, errorx.CodeRecordNotFound.Error("角色不存在")
	}

	// Ensure slice fields are non-nil so DB rollback can clear associations if they were originally empty
	if oldRole.Apis == nil {
		oldRole.Apis = []Api{}
	}
	if oldRole.Menus == nil {
		oldRole.Menus = []Menu{}
	}
	if oldRole.Buttons == nil {
		oldRole.Buttons = []Button{}
	}

	if oldRole.Name != role.Name {
		existing, err := uc.roleRepo.FindByName(ctx, role.Name)
		if err != nil && !errorx.IsRecordNotFound(err) {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != role.ID {
			return nil, errorx.CodeDuplicatedKey.Error("角色名称已被使用")
		}
	}

	updated, err := uc.roleRepo.Update(ctx, role)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() error {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		var errs []error
		if _, err := uc.roleRepo.Update(rbCtx, oldRole); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back role model update", slog.Uint64("role_id", role.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		if err := uc.roleRepo.RemoveGroupPolicy(rbCtx, updated); err != nil {
			uc.logger.ErrorContext(ctx, "failed to clean up updated role policy", slog.Uint64("role_id", role.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		if err := uc.roleRepo.AddGroupPolicy(rbCtx, oldRole); err != nil {
			uc.logger.ErrorContext(ctx, "failed to restore role policy", slog.Uint64("role_id", role.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	if err := uc.roleRepo.RemoveGroupPolicy(ctx, oldRole); err != nil {
		return nil, errorx.Wrap(errors.Join(err, rollback()), errorx.CodeSystemError, "删除旧角色权限策略失败")
	}
	if err := uc.roleRepo.AddGroupPolicy(ctx, updated); err != nil {
		uc.logger.ErrorContext(ctx, "failed to update casbin group policy for role", slog.Uint64("role_id", role.ID), slog.Any("error", err))
		return nil, errorx.Wrap(errors.Join(err, rollback()), errorx.CodeSystemError, "更新角色权限策略失败")
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

	role, err := uc.roleRepo.FindByID(ctx, id, "Apis", "Menus", "Buttons")
	if err != nil {
		return errorx.FromDBError(err)
	}
	if role == nil {
		return errorx.CodeRecordNotFound.Error("角色不存在")
	}

	userCount, err := uc.roleRepo.CountUsersByRoleID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if userCount > 0 {
		return errorx.CodeOperationNotAllowed.Error("角色仍被用户引用（包括已删除用户），无法删除")
	}

	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := uc.roleRepo.RemoveGroupPolicy(cleanCtx, role); err != nil {
		return errorx.Wrap(err, errorx.CodeSystemError, "删除角色权限策略失败")
	}
	if err := uc.roleRepo.Delete(ctx, id); err != nil {
		restoreErr := uc.roleRepo.AddGroupPolicy(cleanCtx, role)
		return errorx.Wrap(errors.Join(errorx.FromDBError(err), restoreErr), errorx.CodeSystemError, "删除角色失败")
	}

	return nil
}

// Get finds a role by primary key ID.
func (uc *RoleUseCase) Get(ctx context.Context, id uint64) (*Role, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的角色ID")
	}

	role, err := uc.roleRepo.FindByID(ctx, id, "Apis", "Menus", "Buttons")
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

	role, err := uc.roleRepo.FindByName(ctx, cleanName)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if role == nil {
		return nil, errorx.CodeRecordNotFound.Error("角色不存在")
	}

	return role, nil
}

// List lists roles with conditions.
func (uc *RoleUseCase) List(ctx context.Context, opts db.ListOptions) ([]Role, int64, error) {
	roles, total, err := uc.roleRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return roles, total, nil
}

// ListAllWithRelations lists all roles preloaded with relations.
func (uc *RoleUseCase) ListAllWithRelations(ctx context.Context) ([]Role, error) {
	roles, err := uc.roleRepo.ListAllWithRelations(ctx)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return roles, nil
}
