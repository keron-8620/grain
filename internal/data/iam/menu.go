package iam

import (
	"context"
	"log/slog"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"

	biz "grain/internal/biz/iam"
	"grain/pkg/auth"
	"grain/pkg/db"
)

type menuRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewMenuRepo creates a menu repository instance and returns the biz.MenuRepo interface
func NewMenuRepo(
	data *Data,
	logger *slog.Logger,
) biz.MenuRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &menuRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizMenu(po menuPO) biz.Menu {
	m := biz.Menu{
		ID:        po.ID,
		Path:      po.Path,
		Component: po.Component,
		Name:      po.Name,
		Meta: biz.MenuMeta{
			Title: po.Meta.Title,
			Icon:  po.Meta.Icon,
		},
		Sort:      po.Sort,
		IsActive:  po.IsActive,
		Descr:     po.Descr,
		ParentID:  po.ParentID,
		CreatedAt: po.CreatedAt,
		UpdatedAt: po.UpdatedAt,
	}

	if po.Parent != nil {
		m.Parent = new(toBizMenu(*po.Parent))
	}

	if len(po.Apis) > 0 {
		m.Apis = make([]biz.Api, len(po.Apis))
		m.ApiIDs = make([]uint64, len(po.Apis))
		for i := range po.Apis {
			m.Apis[i] = toBizApi(po.Apis[i])
			m.ApiIDs[i] = po.Apis[i].ID
		}
	}

	return m
}

func newMenuPO(do biz.Menu) menuPO {
	po := menuPO{
		StandardModel: db.StandardModel{
			BaseModel: db.BaseModel{ID: do.ID},
			CreatedAt: do.CreatedAt,
			UpdatedAt: do.UpdatedAt,
		},
		Path:      do.Path,
		Component: do.Component,
		Name:      do.Name,
		Meta: MetaSchemas{
			Title: do.Meta.Title,
			Icon:  do.Meta.Icon,
		},
		Sort:     do.Sort,
		IsActive: do.IsActive,
		Descr:    do.Descr,
		ParentID: do.ParentID,
	}

	if len(do.Apis) > 0 {
		po.Apis = make([]apiPO, 0, len(do.Apis))
		for _, a := range do.Apis {
			if a.ID > 0 {
				po.Apis = append(po.Apis, newApiPO(a))
			}
		}
	} else if len(do.ApiIDs) > 0 {
		po.Apis = make([]apiPO, 0, len(do.ApiIDs))
		for _, id := range do.ApiIDs {
			if id > 0 {
				po.Apis = append(po.Apis, apiPO{BaseModel: db.BaseModel{ID: id}})
			}
		}
	}

	return po
}

// ==================== Repository method implementations ====================

func (r *menuRepo) Create(ctx context.Context, do *biz.Menu) (*biz.Menu, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create menu: invalid argument, model must not be nil")
		return nil, errors.New("create menu: model must not be nil")
	}

	po := newMenuPO(*do)
	now := time.Now()
	if po.CreatedAt.IsZero() {
		po.CreatedAt = now
	}
	if po.UpdatedAt.IsZero() {
		po.UpdatedAt = now
	}

	upmap := make(map[string]any, 1)
	if len(po.Apis) > 0 {
		upmap["Apis"] = po.Apis
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"create menu: model details",
			slog.Any("menu_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create menu", func(dbCtx context.Context) error {
		return db.DBCreateRelationTx(dbCtx, r.data.gormdb, &menuPO{}, &po, upmap)
	}, slog.String("name", po.Name), slog.String("path", po.Path)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID, "Parent", "Apis")
}

func (r *menuRepo) Update(ctx context.Context, do *biz.Menu) (*biz.Menu, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update menu: invalid argument")
		return nil, errors.New("update menu: invalid argument")
	}

	po := newMenuPO(*do)
	updates := po.ToUpdateMap()

	upmap := make(map[string]any, 1)
	if do.Apis != nil || do.ApiIDs != nil {
		if len(po.Apis) > 0 {
			upmap["Apis"] = po.Apis
		} else {
			upmap["Apis"] = []apiPO{}
		}
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update menu: update data",
			slog.Any("updates", updates),
			slog.Uint64("id", uint64(do.ID)),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update menu", func(dbCtx context.Context) error {
		return db.DBUpdateRelationTx(dbCtx, r.data.gormdb, &menuPO{}, updates, upmap, "id = ?", do.ID)
	}, slog.Uint64("id", uint64(do.ID)), slog.String("name", po.Name), slog.String("path", po.Path)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, do.ID, "Parent", "Apis")
}

func (r *menuRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete menu: ID must not be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete menu: primary key ID",
			slog.Uint64("id", id),
		)
	}

	return db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete menu", func(dbCtx context.Context) error {
		_, delErr := db.DBDeleteTx(dbCtx, r.data.gormdb, &menuPO{}, "id = ?", id)
		return delErr
	}, slog.Uint64("id", id))
}

func (r *menuRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*biz.Menu, error) {
	if id == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find menu by ID",
			slog.Uint64("id", id),
			slog.Any("preloads", preloads),
		)
	}

	var po menuPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find menu by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, preloads, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizMenu(po)), nil
}

func (r *menuRepo) FindByIDs(ctx context.Context, ids []uint64, preloads ...string) ([]biz.Menu, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find menus by IDs",
			slog.Any("ids", ids),
			slog.Any("preloads", preloads),
		)
	}

	var pos []menuPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find menus by IDs", func(dbCtx context.Context) error {
		tx := r.data.gormdb.WithContext(dbCtx)
		for _, p := range preloads {
			tx = tx.Preload(p)
		}
		return tx.Where("id IN ?", ids).Find(&pos).Error
	}, slog.Int("count", len(ids))); err != nil {
		return nil, err
	}

	res := make([]biz.Menu, 0, len(pos))
	for i := range pos {
		res = append(res, toBizMenu(pos[i]))
	}
	return res, nil
}

func (r *menuRepo) FindByName(ctx context.Context, name string) (*biz.Menu, error) {
	if name == "" {
		return nil, nil
	}

	var po menuPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find menu by name", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, nil, "name = ?", name)
	}, slog.String("name", name)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizMenu(po)), nil
}

func (r *menuRepo) FindByPath(ctx context.Context, path string) (*biz.Menu, error) {
	if path == "" {
		return nil, nil
	}

	var po menuPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find menu by path", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, nil, "path = ?", path)
	}, slog.String("path", path)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizMenu(po)), nil
}

func (r *menuRepo) List(ctx context.Context, opts db.ListOptions) ([]biz.Menu, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list menus: request details",
			slog.Any("opts", opts),
		)
	}

	if err := opts.Normalize(); err != nil {
		return nil, 0, err
	}

	orderBy := []string{"sort ASC", "id ASC"}
	if opts.OrderBy != "" {
		orderBy = []string{opts.OrderBy}
	}

	qp := db.QueryParams{
		Offset:              opts.Offset,
		Limit:               opts.PageSize,
		Filters:             opts.Filters,
		FilterColumnMap:     menuFilterColumns,
		Preloads:            []string{"Parent", "Apis"},
		OrderBy:             orderBy,
		AllowedOrderColumns: menuOrderColumns,
	}

	var pos []menuPO
	var total int64

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list menus", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &menuPO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		if errors.Is(err, db.ErrInvalidListOption) {
			return nil, 0, err
		}
		return nil, 0, err
	}

	res := make([]biz.Menu, 0, len(pos))
	for i := range pos {
		res = append(res, toBizMenu(pos[i]))
	}
	return res, total, nil
}

func (r *menuRepo) ListAllWithApis(ctx context.Context) ([]biz.Menu, error) {
	qp := db.QueryParams{
		Preloads: []string{"Apis"},
		OrderBy:  []string{"id ASC"},
	}

	var pos []menuPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list all menus with apis", func(dbCtx context.Context) error {
		return db.DBList(dbCtx, r.data.gormdb, &menuPO{}, &pos, qp)
	}); err != nil {
		return nil, err
	}

	res := make([]biz.Menu, 0, len(pos))
	for i := range pos {
		res = append(res, toBizMenu(pos[i]))
	}
	return res, nil
}

func (r *menuRepo) CountChildren(ctx context.Context, parentID uint64) (int64, error) {
	if parentID == 0 {
		return 0, nil
	}
	var count int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "count children menus", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Model(&menuPO{}).Where("parent_id = ?", parentID).Count(&count).Error
	}, slog.Uint64("parent_id", parentID)); err != nil {
		return 0, err
	}
	return count, nil
}

// ==================== Casbin grouping policy management ====================

func (r *menuRepo) AddGroupPolicy(ctx context.Context, menu *biz.Menu) error {
	if menu == nil || menu.ID == 0 {
		return errors.New("add menu grouping policy: invalid menu ID")
	}

	sub := auth.MenuToSubject(menu.ID)
	rules := [][]string{}

	// 1. Parent menu inheritance policy: (menu_sub, parent_sub)
	if menu.ParentID != nil && *menu.ParentID > 0 && *menu.ParentID != menu.ID {
		parentSub := auth.MenuToSubject(*menu.ParentID)
		rules = append(rules, []string{sub, parentSub})
	}

	// 2. Related API inheritance policy: (menu_sub, api_sub)
	for _, api := range menu.Apis {
		if api.ID > 0 {
			apiSub := auth.ApiToSubject(api.ID)
			rules = append(rules, []string{sub, apiSub})
		}
	}
	if len(menu.Apis) == 0 && len(menu.ApiIDs) > 0 {
		for _, id := range menu.ApiIDs {
			if id > 0 {
				apiSub := auth.ApiToSubject(id)
				rules = append(rules, []string{sub, apiSub})
			}
		}
	}

	if len(rules) == 0 {
		return nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"add menu grouping policy: rule list",
			slog.Any("rules", rules),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "add menu grouping policy", func(opCtx context.Context) error {
		return AddGroupPolicies(opCtx, r.data.enforcer, rules)
	}, slog.Uint64("menu_id", uint64(menu.ID)), slog.Int("rules_count", len(rules)))
}

func (r *menuRepo) RemoveGroupPolicy(ctx context.Context, menu *biz.Menu, removeInherited bool) error {
	if menu == nil || menu.ID == 0 {
		return errors.New("remove menu grouping policy: invalid menu ID")
	}

	sub := auth.MenuToSubject(menu.ID)

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"remove menu grouping policy",
			slog.String("sub", sub),
			slog.Bool("removeInherited", removeInherited),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "remove menu grouping policy", func(opCtx context.Context) error {
		if removeInherited {
			// Remove policies where other subjects inherit this menu: g, _, menu_xxx (fieldIndex 1)
			if _, err := RemoveFilteredGroupingPolicy(opCtx, r.data.enforcer, 1, sub); err != nil {
				return errors.WrapIf(err, "failed to remove grouping policies inheriting this menu")
			}
		}

		// Remove policies where this menu inherits other menus or APIs: g, menu_xxx, _ (fieldIndex 0)
		if _, err := RemoveFilteredGroupingPolicy(opCtx, r.data.enforcer, 0, sub); err != nil {
			return errors.WrapIf(err, "failed to remove grouping policies where the menu is the subject")
		}
		return nil
	}, slog.Uint64("menu_id", uint64(menu.ID)))
}
