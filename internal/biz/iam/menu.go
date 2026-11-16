package iam

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"grain/pkg/db"
	"grain/pkg/errorx"
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

// MenuTreeNode represents a node in the hierarchical menu tree.
type MenuTreeNode struct {
	*Menu
	Children []*MenuTreeNode `json:"children,omitempty"`
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
	CountChildren(ctx context.Context, parentID uint64) (int64, error)

	// Casbin grouping policies
	AddGroupPolicy(ctx context.Context, menu *Menu) error
	RemoveGroupPolicy(ctx context.Context, menu *Menu, removeInherited bool) error
}

// MenuUseCase handles menu hierarchy, resource management, and Casbin policy inheritance.
type MenuUseCase struct {
	repo       MenuRepo
	buttonRepo ButtonRepo
	logger     *slog.Logger
}

// NewMenuUseCase creates a new MenuUseCase instance.
func NewMenuUseCase(repo MenuRepo, logger *slog.Logger, buttonRepo ...ButtonRepo) *MenuUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	var br ButtonRepo
	if len(buttonRepo) > 0 {
		br = buttonRepo[0]
	}
	return &MenuUseCase{
		repo:       repo,
		buttonRepo: br,
		logger:     logger,
	}
}

// Create creates a new menu and registers Casbin grouping inheritance policies.
func (uc *MenuUseCase) Create(ctx context.Context, menu *Menu) (*Menu, error) {
	if menu == nil {
		return nil, errorx.CodeInvalidParam.Error("菜单信息不能为空")
	}

	name := strings.TrimSpace(menu.Name)
	path := strings.TrimSpace(menu.Path)
	if name == "" || path == "" {
		return nil, errorx.CodeMissingParam.Error("菜单名称和路由路径不能为空")
	}
	menu.Name = name
	menu.Path = path

	if menu.ParentID != nil && *menu.ParentID > 0 {
		parent, err := uc.repo.FindByID(ctx, *menu.ParentID)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if parent == nil {
			return nil, errorx.CodeRecordNotFound.Error("父级菜单不存在")
		}
	}

	existingName, err := uc.repo.FindByName(ctx, menu.Name)
	if err != nil && !errorx.IsRecordNotFound(err) {
		return nil, errorx.FromDBError(err)
	}
	if existingName != nil {
		return nil, errorx.CodeDuplicatedKey.Error("菜单名称已存在")
	}

	existingPath, err := uc.repo.FindByPath(ctx, menu.Path)
	if err != nil && !errorx.IsRecordNotFound(err) {
		return nil, errorx.FromDBError(err)
	}
	if existingPath != nil {
		return nil, errorx.CodeDuplicatedKey.Error("菜单路由路径已存在")
	}

	created, err := uc.repo.Create(ctx, menu)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := uc.repo.Delete(rbCtx, created.ID); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back menu model creation", slog.Uint64("menu_id", created.ID), slog.Any("error", err))
		}
	}

	if err := uc.repo.AddGroupPolicy(ctx, created); err != nil {
		uc.logger.ErrorContext(ctx, "failed to add casbin group policy for menu", slog.Uint64("menu_id", created.ID), slog.Any("error", err))
		rollback()
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "添加菜单权限策略失败")
	}

	return created, nil
}

// Update updates an existing menu and updates Casbin grouping policies.
func (uc *MenuUseCase) Update(ctx context.Context, menu *Menu) (*Menu, error) {
	if menu == nil || menu.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的菜单ID")
	}

	name := strings.TrimSpace(menu.Name)
	path := strings.TrimSpace(menu.Path)
	if name == "" || path == "" {
		return nil, errorx.CodeMissingParam.Error("菜单名称和路由路径不能为空")
	}
	menu.Name = name
	menu.Path = path

	oldMenu, err := uc.repo.FindByID(ctx, menu.ID, "Parent", "Apis")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldMenu == nil {
		return nil, errorx.CodeRecordNotFound.Error("菜单不存在")
	}

	// Ensure slice fields are non-nil so DB rollback can clear associations if they were originally empty
	if oldMenu.Apis == nil {
		oldMenu.Apis = []*Api{}
	}

	// Validate parent relation and cycle prevention
	if menu.ParentID != nil && *menu.ParentID > 0 {
		if *menu.ParentID == menu.ID {
			return nil, errorx.CodeOperationNotAllowed.Error("父级菜单不能是自身")
		}
		parent, err := uc.repo.FindByID(ctx, *menu.ParentID)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if parent == nil {
			return nil, errorx.CodeRecordNotFound.Error("父级菜单不存在")
		}

		// Detect circular hierarchy with visited set and depth limit
		visited := map[uint64]struct{}{menu.ID: {}, parent.ID: {}}
		curr := parent
		const maxMenuDepth = 50
		depth := 0
		for curr != nil && curr.ParentID != nil && *curr.ParentID > 0 {
			depth++
			if depth > maxMenuDepth {
				return nil, errorx.CodeOperationNotAllowed.Error("菜单层级深度超出限制")
			}
			parentID := *curr.ParentID
			if parentID == menu.ID {
				return nil, errorx.CodeOperationNotAllowed.Error("不能将父级菜单设置为自己的子孙菜单")
			}
			if _, ok := visited[parentID]; ok {
				return nil, errorx.CodeOperationNotAllowed.Error("检测到循环菜单层级关系")
			}
			visited[parentID] = struct{}{}
			nextParent, findErr := uc.repo.FindByID(ctx, parentID)
			if findErr != nil {
				return nil, errorx.FromDBError(findErr)
			}
			curr = nextParent
		}
	}

	if oldMenu.Name != menu.Name {
		existing, err := uc.repo.FindByName(ctx, menu.Name)
		if err != nil && !errorx.IsRecordNotFound(err) {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != menu.ID {
			return nil, errorx.CodeDuplicatedKey.Error("菜单名称已被使用")
		}
	}

	if oldMenu.Path != menu.Path {
		existing, err := uc.repo.FindByPath(ctx, menu.Path)
		if err != nil && !errorx.IsRecordNotFound(err) {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != menu.ID {
			return nil, errorx.CodeDuplicatedKey.Error("菜单路由路径已被使用")
		}
	}

	updated, err := uc.repo.Update(ctx, menu)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	rollback := func() error {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		var errs []error
		if _, err := uc.repo.Update(rbCtx, oldMenu); err != nil {
			uc.logger.ErrorContext(ctx, "failed to roll back menu model update", slog.Uint64("menu_id", menu.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		if err := uc.repo.RemoveGroupPolicy(rbCtx, updated, false); err != nil {
			uc.logger.ErrorContext(ctx, "failed to clean up updated menu policy", slog.Uint64("menu_id", menu.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		if err := uc.repo.AddGroupPolicy(rbCtx, oldMenu); err != nil {
			uc.logger.ErrorContext(ctx, "failed to restore menu policy", slog.Uint64("menu_id", menu.ID), slog.Any("error", err))
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	if err := uc.repo.RemoveGroupPolicy(ctx, oldMenu, false); err != nil {
		return nil, errorx.Wrap(errors.Join(err, rollback()), errorx.CodeSystemError, "删除旧菜单权限策略失败")
	}
	if err := uc.repo.AddGroupPolicy(ctx, updated); err != nil {
		uc.logger.ErrorContext(ctx, "failed to update casbin group policy for menu", slog.Uint64("menu_id", menu.ID), slog.Any("error", err))
		return nil, errorx.Wrap(errors.Join(err, rollback()), errorx.CodeSystemError, "更新菜单权限策略失败")
	}

	return updated, nil
}

// Delete deletes a menu by ID, ensuring no child menus or associated buttons exist.
func (uc *MenuUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的菜单ID")
	}

	menu, err := uc.repo.FindByID(ctx, id, "Apis")
	if err != nil {
		return errorx.FromDBError(err)
	}
	if menu == nil {
		return errorx.CodeRecordNotFound.Error("菜单不存在")
	}

	// Check for child menus
	childCount, err := uc.repo.CountChildren(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if childCount > 0 {
		return errorx.CodeOperationNotAllowed.Error("存在子菜单，请先删除子菜单")
	}

	// Check for associated buttons
	if uc.buttonRepo != nil {
		btns, _, err := uc.buttonRepo.List(ctx, ButtonListOptions{
			Filters: []db.ListFilter{
				{Field: "menu_id", Op: db.ListFilterEquals, Value: id},
			},
		})
		if err != nil {
			return errorx.FromDBError(err)
		}
		if len(btns) > 0 {
			return errorx.CodeOperationNotAllowed.Error("菜单下存在关联按钮，请先删除按钮")
		}
	}

	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	// Remove the menu's outgoing grants first. If the DB delete fails we can
	// restore them; if the later cleanup of inherited edges fails, the menu no
	// longer leads to any permission and therefore cannot widen access.
	if err := uc.repo.RemoveGroupPolicy(cleanCtx, menu, false); err != nil {
		return errorx.Wrap(err, errorx.CodeSystemError, "删除菜单权限策略失败")
	}
	if err := uc.repo.Delete(ctx, id); err != nil {
		restoreErr := uc.repo.AddGroupPolicy(cleanCtx, menu)
		return errorx.Wrap(errors.Join(errorx.FromDBError(err), restoreErr), errorx.CodeSystemError, "删除菜单失败")
	}
	if err := uc.repo.RemoveGroupPolicy(cleanCtx, menu, true); err != nil {
		return errorx.Wrap(err, errorx.CodeSystemError, "清理菜单关联权限策略失败")
	}

	return nil
}

// Get finds a menu by primary key ID.
func (uc *MenuUseCase) Get(ctx context.Context, id uint64) (*Menu, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的菜单ID")
	}

	menu, err := uc.repo.FindByID(ctx, id, "Parent", "Apis")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if menu == nil {
		return nil, errorx.CodeRecordNotFound.Error("菜单不存在")
	}

	return menu, nil
}

// GetByName finds a menu by unique name.
func (uc *MenuUseCase) GetByName(ctx context.Context, name string) (*Menu, error) {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, errorx.CodeMissingParam.Error("菜单名称不能为空")
	}

	menu, err := uc.repo.FindByName(ctx, cleanName)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if menu == nil {
		return nil, errorx.CodeRecordNotFound.Error("菜单不存在")
	}

	return menu, nil
}

// GetByPath finds a menu by route path.
func (uc *MenuUseCase) GetByPath(ctx context.Context, path string) (*Menu, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errorx.CodeMissingParam.Error("菜单路径不能为空")
	}

	menu, err := uc.repo.FindByPath(ctx, cleanPath)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if menu == nil {
		return nil, errorx.CodeRecordNotFound.Error("菜单不存在")
	}

	return menu, nil
}

// List lists menus with conditions.
func (uc *MenuUseCase) List(ctx context.Context, opts MenuListOptions) ([]*Menu, int64, error) {
	menus, total, err := uc.repo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return menus, total, nil
}

// ListTree retrieves all menus and constructs a hierarchical menu tree.
func (uc *MenuUseCase) ListTree(ctx context.Context) ([]*MenuTreeNode, error) {
	menus, err := uc.repo.ListAllWithApis(ctx)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return BuildMenuTree(menus), nil
}

// ListAllWithApis lists all menus preloaded with APIs.
func (uc *MenuUseCase) ListAllWithApis(ctx context.Context) ([]*Menu, error) {
	menus, err := uc.repo.ListAllWithApis(ctx)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return menus, nil
}

// BuildMenuTree constructs a hierarchical tree from a flat list of menus.
func BuildMenuTree(menus []*Menu) []*MenuTreeNode {
	if len(menus) == 0 {
		return []*MenuTreeNode{}
	}

	nodeMap := make(map[uint64]*MenuTreeNode, len(menus))
	for _, m := range menus {
		if m != nil {
			nodeMap[m.ID] = &MenuTreeNode{
				Menu:     m,
				Children: []*MenuTreeNode{},
			}
		}
	}

	var roots []*MenuTreeNode
	for _, m := range menus {
		if m == nil {
			continue
		}
		node := nodeMap[m.ID]
		if m.ParentID == nil || *m.ParentID == 0 {
			roots = append(roots, node)
		} else if parent, ok := nodeMap[*m.ParentID]; ok {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}

	sortNodes := func(nodes []*MenuTreeNode) {
		sort.SliceStable(nodes, func(i, j int) bool {
			if nodes[i].Sort != nodes[j].Sort {
				return nodes[i].Sort < nodes[j].Sort
			}
			return nodes[i].ID < nodes[j].ID
		})
	}

	sortNodes(roots)
	var walk func([]*MenuTreeNode)
	walk = func(nodes []*MenuTreeNode) {
		for _, n := range nodes {
			if len(n.Children) > 0 {
				sortNodes(n.Children)
				walk(n.Children)
			}
		}
	}
	walk(roots)

	return roots
}
