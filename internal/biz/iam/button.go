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
	Apis      []Api
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ButtonRepo is the button repository interface contract.
type ButtonRepo interface {
	Create(ctx context.Context, button *Button) (*Button, error)
	Update(ctx context.Context, button *Button) (*Button, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*Button, error)
	FindByIDs(ctx context.Context, ids []uint64, preloads ...string) ([]Button, error)
	FindByName(ctx context.Context, name string) (*Button, error)
	List(ctx context.Context, opts db.ListOptions) ([]Button, int64, error)
	ListAllWithApis(ctx context.Context) ([]Button, error)

	// Casbin grouping policies
	AddGroupPolicy(ctx context.Context, button *Button) error
	RemoveGroupPolicy(ctx context.Context, button *Button, removeInherited bool) error
}

// ButtonUseCase handles button resource management and grouping policy synchronization.
type ButtonUseCase struct {
	buttonRepo ButtonRepo
	menuRepo   MenuRepo
	logger     *slog.Logger
}

// NewButtonUseCase creates a new ButtonUseCase instance.
func NewButtonUseCase(buttonRepo ButtonRepo, menuRepo MenuRepo, logger *slog.Logger) *ButtonUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	return &ButtonUseCase{
		buttonRepo: buttonRepo,
		menuRepo:   menuRepo,
		logger:     logger,
	}
}

// Create creates a new button and associates it with its parent menu and Casbin grouping policy.
func (uc *ButtonUseCase) Create(ctx context.Context, button *Button) (*Button, error) {
	if button == nil {
		return nil, errorx.CodeInvalidParam.Error("按钮信息不能为空")
	}

	name := strings.TrimSpace(button.Name)
	if name == "" {
		return nil, errorx.CodeMissingParam.Error("按钮名称不能为空")
	}
	if button.MenuID == 0 {
		return nil, errorx.CodeMissingParam.Error("按钮必须关联菜单")
	}
	button.Name = name

	// Verify the associated menu exists
	if uc.menuRepo != nil {
		menu, err := uc.menuRepo.FindByID(ctx, button.MenuID)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if menu == nil {
			return nil, errorx.CodeRecordNotFound.Error("关联菜单不存在")
		}
	}

	// Verify button name uniqueness
	existing, err := uc.buttonRepo.FindByName(ctx, button.Name)
	if err != nil && !errorx.IsRecordNotFound(err) {
		return nil, errorx.FromDBError(err)
	}
	if existing != nil {
		return nil, errorx.CodeDuplicatedKey.Error("按钮名称已存在")
	}

	created, err := uc.buttonRepo.Create(ctx, button)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := uc.buttonRepo.Delete(rbCtx, created.ID); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back button model creation", slog.Uint64("button_id", created.ID), slog.Any("error", err))
		}
	}

	if err := uc.buttonRepo.AddGroupPolicy(ctx, created); err != nil {
		uc.logger.ErrorContext(ctx, "failed to add casbin group policy for button", slog.Uint64("button_id", created.ID), slog.Any("error", err))
		rollback()
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "添加按钮权限策略失败")
	}

	return created, nil
}

// Update updates an existing button and synchronizes its Casbin grouping policy.
func (uc *ButtonUseCase) Update(ctx context.Context, button *Button) (*Button, error) {
	if button == nil || button.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的按钮ID")
	}

	name := strings.TrimSpace(button.Name)
	if name == "" {
		return nil, errorx.CodeMissingParam.Error("按钮名称不能为空")
	}
	if button.MenuID == 0 {
		return nil, errorx.CodeMissingParam.Error("按钮必须关联菜单")
	}
	button.Name = name

	oldBtn, err := uc.buttonRepo.FindByID(ctx, button.ID, "Menu", "Apis")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldBtn == nil {
		return nil, errorx.CodeRecordNotFound.Error("按钮不存在")
	}

	// Ensure slice fields are non-nil so DB rollback can clear associations if they were originally empty
	if oldBtn.Apis == nil {
		oldBtn.Apis = []Api{}
	}

	// Check name uniqueness if changed
	if oldBtn.Name != button.Name {
		existing, err := uc.buttonRepo.FindByName(ctx, button.Name)
		if err != nil && !errorx.IsRecordNotFound(err) {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != button.ID {
			return nil, errorx.CodeDuplicatedKey.Error("按钮名称已被使用")
		}
	}

	// Verify the associated menu exists if changed
	if button.MenuID != oldBtn.MenuID && uc.menuRepo != nil {
		menu, err := uc.menuRepo.FindByID(ctx, button.MenuID)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if menu == nil {
			return nil, errorx.CodeRecordNotFound.Error("关联菜单不存在")
		}
	}

	updated, err := uc.buttonRepo.Update(ctx, button)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() error {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		var errs []error
		if _, err := uc.buttonRepo.Update(rbCtx, oldBtn); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back button model update", slog.Uint64("button_id", button.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		if err := uc.buttonRepo.RemoveGroupPolicy(rbCtx, updated, false); err != nil {
			uc.logger.ErrorContext(ctx, "failed to clean up updated button policy", slog.Uint64("button_id", button.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		if err := uc.buttonRepo.AddGroupPolicy(rbCtx, oldBtn); err != nil {
			uc.logger.ErrorContext(ctx, "failed to restore button policy", slog.Uint64("button_id", button.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	if err := uc.buttonRepo.RemoveGroupPolicy(ctx, oldBtn, false); err != nil {
		return nil, errorx.Wrap(errors.Join(err, rollback()), errorx.CodeSystemError, "删除旧按钮权限策略失败")
	}
	if err := uc.buttonRepo.AddGroupPolicy(ctx, updated); err != nil {
		uc.logger.ErrorContext(ctx, "failed to update casbin group policy for button", slog.Uint64("button_id", button.ID), slog.Any("error", err))
		return nil, errorx.Wrap(errors.Join(err, rollback()), errorx.CodeSystemError, "更新按钮权限策略失败")
	}

	return updated, nil
}

// Delete deletes a button by ID and removes its Casbin grouping policies.
func (uc *ButtonUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的按钮ID")
	}

	btn, err := uc.buttonRepo.FindByID(ctx, id, "Apis")
	if err != nil {
		return errorx.FromDBError(err)
	}
	if btn == nil {
		return errorx.CodeRecordNotFound.Error("按钮不存在")
	}

	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := uc.buttonRepo.RemoveGroupPolicy(cleanCtx, btn, false); err != nil {
		return errorx.Wrap(err, errorx.CodeSystemError, "删除按钮权限策略失败")
	}
	if err := uc.buttonRepo.Delete(ctx, id); err != nil {
		restoreErr := uc.buttonRepo.AddGroupPolicy(cleanCtx, btn)
		return errorx.Wrap(errors.Join(errorx.FromDBError(err), restoreErr), errorx.CodeSystemError, "删除按钮失败")
	}
	if err := uc.buttonRepo.RemoveGroupPolicy(cleanCtx, btn, true); err != nil {
		return errorx.Wrap(err, errorx.CodeSystemError, "清理按钮关联权限策略失败")
	}

	return nil
}

// Get finds a button by primary key ID.
func (uc *ButtonUseCase) Get(ctx context.Context, id uint64) (*Button, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的按钮ID")
	}

	btn, err := uc.buttonRepo.FindByID(ctx, id, "Menu", "Apis")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if btn == nil {
		return nil, errorx.CodeRecordNotFound.Error("按钮不存在")
	}

	return btn, nil
}

// GetByName finds a button by name.
func (uc *ButtonUseCase) GetByName(ctx context.Context, name string) (*Button, error) {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, errorx.CodeMissingParam.Error("按钮名称不能为空")
	}

	btn, err := uc.buttonRepo.FindByName(ctx, cleanName)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if btn == nil {
		return nil, errorx.CodeRecordNotFound.Error("按钮不存在")
	}

	return btn, nil
}

// List lists buttons matching conditions.
func (uc *ButtonUseCase) List(ctx context.Context, opts db.ListOptions) ([]Button, int64, error) {
	btns, total, err := uc.buttonRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return btns, total, nil
}

// ListAllWithApis lists all buttons preloaded with associated APIs.
func (uc *ButtonUseCase) ListAllWithApis(ctx context.Context) ([]Button, error) {
	btns, err := uc.buttonRepo.ListAllWithApis(ctx)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return btns, nil
}
