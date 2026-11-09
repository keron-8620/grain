package iam

import (
	"context"
	"log/slog"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	biz "grain/internal/biz/iam"
	"grain/pkg/auth"
	"grain/pkg/db"
)

type roleRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewRoleRepo creates a role repository instance and returns the biz.RoleRepo interface
func NewRoleRepo(
	data *Data,
	logger *slog.Logger,
) biz.RoleRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &roleRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizRole(po *rolePO) *biz.Role {
	if po == nil {
		return nil
	}
	r := &biz.Role{
		ID:        po.ID,
		Name:      po.Name,
		Descr:     po.Descr,
		CreatedAt: po.CreatedAt,
		UpdatedAt: po.UpdatedAt,
	}

	if len(po.Apis) > 0 {
		r.Apis = make([]*biz.Api, len(po.Apis))
		r.ApiIDs = make([]uint64, len(po.Apis))
		for i := range po.Apis {
			r.Apis[i] = toBizApi(&po.Apis[i])
			r.ApiIDs[i] = po.Apis[i].ID
		}
	}
	if len(po.Menus) > 0 {
		r.Menus = make([]*biz.Menu, len(po.Menus))
		r.MenuIDs = make([]uint64, len(po.Menus))
		for i := range po.Menus {
			r.Menus[i] = toBizMenu(&po.Menus[i])
			r.MenuIDs[i] = po.Menus[i].ID
		}
	}
	if len(po.Buttons) > 0 {
		r.Buttons = make([]*biz.Button, len(po.Buttons))
		r.ButtonIDs = make([]uint64, len(po.Buttons))
		for i := range po.Buttons {
			r.Buttons[i] = toBizButton(&po.Buttons[i])
			r.ButtonIDs[i] = po.Buttons[i].ID
		}
	}

	return r
}

func newRolePO(do *biz.Role) *rolePO {
	if do == nil {
		return nil
	}
	po := &rolePO{
		StandardModel: db.StandardModel{
			BaseModel: db.BaseModel{ID: do.ID},
			CreatedAt: do.CreatedAt,
			UpdatedAt: do.UpdatedAt,
		},
		Name:  do.Name,
		Descr: do.Descr,
	}

	if len(do.Apis) > 0 {
		po.Apis = make([]apiPO, len(do.Apis))
		for i, a := range do.Apis {
			if a != nil {
				po.Apis[i] = *newApiPO(a)
			}
		}
	} else if len(do.ApiIDs) > 0 {
		po.Apis = make([]apiPO, len(do.ApiIDs))
		for i, id := range do.ApiIDs {
			po.Apis[i] = apiPO{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: id}}}
		}
	}

	if len(do.Menus) > 0 {
		po.Menus = make([]menuPO, len(do.Menus))
		for i, m := range do.Menus {
			if m != nil {
				po.Menus[i] = *newMenuPO(m)
			}
		}
	} else if len(do.MenuIDs) > 0 {
		po.Menus = make([]menuPO, len(do.MenuIDs))
		for i, id := range do.MenuIDs {
			po.Menus[i] = menuPO{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: id}}}
		}
	}

	if len(do.Buttons) > 0 {
		po.Buttons = make([]buttonPO, len(do.Buttons))
		for i, b := range do.Buttons {
			if b != nil {
				po.Buttons[i] = *newButtonPO(b)
			}
		}
	} else if len(do.ButtonIDs) > 0 {
		po.Buttons = make([]buttonPO, len(do.ButtonIDs))
		for i, id := range do.ButtonIDs {
			po.Buttons[i] = buttonPO{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: id}}}
		}
	}

	return po
}

// ==================== Repository method implementations ====================

func (r *roleRepo) Create(ctx context.Context, do *biz.Role) (*biz.Role, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create role: invalid argument, model must not be nil")
		return nil, errors.New("create role: model must not be nil")
	}

	po := newRolePO(do)
	now := time.Now()
	if po.CreatedAt.IsZero() {
		po.CreatedAt = now
	}
	if po.UpdatedAt.IsZero() {
		po.UpdatedAt = now
	}

	upmap := map[string]any{
		"Apis":    po.Apis,
		"Menus":   po.Menus,
		"Buttons": po.Buttons,
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"create role: model details",
			slog.Any("role_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create role", func(dbCtx context.Context) error {
		return db.DBCreateRelationTx(dbCtx, r.data.gormdb, &rolePO{}, po, upmap)
	}, slog.String("name", po.Name)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID, "Apis", "Menus", "Buttons")
}

func (r *roleRepo) Update(ctx context.Context, do *biz.Role) (*biz.Role, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update role: invalid argument")
		return nil, errors.New("update role: invalid argument")
	}

	if do.Name == "" {
		return nil, errors.New("update role: name cannot be empty")
	}

	po := newRolePO(do)
	updates := po.ToUpdateMap()

	upmap := make(map[string]any)
	if do.Apis != nil || do.ApiIDs != nil {
		if len(po.Apis) > 0 {
			upmap["Apis"] = po.Apis
		} else {
			upmap["Apis"] = []apiPO{}
		}
	}

	if do.Menus != nil || do.MenuIDs != nil {
		if len(po.Menus) > 0 {
			upmap["Menus"] = po.Menus
		} else {
			upmap["Menus"] = []menuPO{}
		}
	}

	if do.Buttons != nil || do.ButtonIDs != nil {
		if len(po.Buttons) > 0 {
			upmap["Buttons"] = po.Buttons
		} else {
			upmap["Buttons"] = []buttonPO{}
		}
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update role: update data",
			slog.Any("updates", updates),
			slog.Uint64("id", uint64(do.ID)),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update role", func(dbCtx context.Context) error {
		return db.DBUpdateRelationTx(dbCtx, r.data.gormdb, &rolePO{}, updates, upmap, "id = ?", do.ID)
	}, slog.Uint64("id", uint64(do.ID)), slog.String("name", po.Name)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, do.ID, "Apis", "Menus", "Buttons")
}

func (r *roleRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete role: ID must not be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete role: primary key ID",
			slog.Uint64("id", id),
		)
	}

	return db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete role", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Transaction(func(tx *gorm.DB) error {
			var role rolePO
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&role, "id = ?", id).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil
				}
				return err
			}

			var userCount int64
			if err := tx.Model(&userPO{}).Where("role_id = ?", id).Count(&userCount).Error; err != nil {
				return err
			}
			if userCount > 0 {
				return errors.New("role still has associated users and cannot be deleted")
			}

			if err := tx.Model(&role).Association("Apis").Clear(); err != nil {
				return err
			}
			if err := tx.Model(&role).Association("Menus").Clear(); err != nil {
				return err
			}
			if err := tx.Model(&role).Association("Buttons").Clear(); err != nil {
				return err
			}

			if err := tx.Delete(&role).Error; err != nil {
				return err
			}
			return nil
		})
	}, slog.Uint64("id", id))
}

func (r *roleRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*biz.Role, error) {
	if id == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find role by ID",
			slog.Uint64("id", id),
			slog.Any("preloads", preloads),
		)
	}

	var po rolePO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find role by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, preloads, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return toBizRole(&po), nil
}

func (r *roleRepo) FindByName(ctx context.Context, name string) (*biz.Role, error) {
	var po rolePO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find role by name", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, nil, "name = ?", name)
	}, slog.String("name", name)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return toBizRole(&po), nil
}

func (r *roleRepo) List(ctx context.Context, opts biz.RoleListOptions) ([]*biz.Role, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list roles: request details",
			slog.Any("opts", opts),
		)
	}

	if opts.PageSize <= 0 {
		opts.PageSize = db.DefaultPageSize
	}
	if err := db.ValidateListOptions(opts.Offset, opts.PageSize); err != nil {
		return nil, 0, err
	}

	orderBy := []string{"id ASC"}
	if opts.OrderBy != "" {
		orderBy = []string{opts.OrderBy}
	}

	qp := db.QueryParams{
		Offset:              opts.Offset,
		Limit:               opts.PageSize,
		Filters:             opts.Filters,
		FilterColumnMap:     roleFilterColumns,
		Preloads:            []string{"Apis", "Menus", "Buttons"},
		OrderBy:             orderBy,
		AllowedOrderColumns: roleOrderColumns,
	}

	var pos []rolePO
	var total int64

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list roles", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &rolePO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		if errors.Is(err, db.ErrInvalidListOption) {
			return nil, 0, err
		}
		return nil, 0, err
	}

	res := make([]*biz.Role, 0, len(pos))
	for i := range pos {
		res = append(res, toBizRole(&pos[i]))
	}
	return res, total, nil
}

func (r *roleRepo) ListAllWithRelations(ctx context.Context) ([]*biz.Role, error) {
	qp := db.QueryParams{
		Preloads:            []string{"Apis", "Menus", "Buttons"},
		OrderBy:             []string{"id ASC"},
		FilterColumnMap:     roleFilterColumns,
		AllowedOrderColumns: roleOrderColumns,
	}

	var pos []rolePO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list all roles with relations", func(dbCtx context.Context) error {
		return db.DBList(dbCtx, r.data.gormdb, &rolePO{}, &pos, qp)
	}); err != nil {
		return nil, err
	}

	res := make([]*biz.Role, 0, len(pos))
	for i := range pos {
		res = append(res, toBizRole(&pos[i]))
	}
	return res, nil
}

func (r *roleRepo) CountUsersByRoleID(ctx context.Context, roleID uint64) (int64, error) {
	var count int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "count users by role", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Model(&userPO{}).Where("role_id = ?", roleID).Count(&count).Error
	}, slog.Uint64("role_id", roleID)); err != nil {
		return 0, err
	}
	return count, nil
}

// ==================== Casbin grouping policy management ====================

func (r *roleRepo) AddGroupPolicy(ctx context.Context, role *biz.Role) error {
	if role == nil || role.ID == 0 {
		return errors.New("add role grouping policy: invalid role ID")
	}

	sub := auth.RoleToSubject(role.ID)
	rules := [][]string{}

	// API link policy: (role_sub, api_sub)
	for _, a := range role.Apis {
		if a != nil && a.ID > 0 {
			rules = append(rules, []string{sub, auth.ApiToSubject(a.ID)})
		}
	}
	if len(role.Apis) == 0 && len(role.ApiIDs) > 0 {
		for _, id := range role.ApiIDs {
			if id > 0 {
				rules = append(rules, []string{sub, auth.ApiToSubject(id)})
			}
		}
	}

	// Menu link policy: (role_sub, menu_sub)
	for _, m := range role.Menus {
		if m != nil && m.ID > 0 {
			rules = append(rules, []string{sub, auth.MenuToSubject(m.ID)})
		}
	}
	if len(role.Menus) == 0 && len(role.MenuIDs) > 0 {
		for _, id := range role.MenuIDs {
			if id > 0 {
				rules = append(rules, []string{sub, auth.MenuToSubject(id)})
			}
		}
	}

	// Button link policy: (role_sub, button_sub)
	for _, b := range role.Buttons {
		if b != nil && b.ID > 0 {
			rules = append(rules, []string{sub, auth.ButtonToSubject(b.ID)})
		}
	}
	if len(role.Buttons) == 0 && len(role.ButtonIDs) > 0 {
		for _, id := range role.ButtonIDs {
			if id > 0 {
				rules = append(rules, []string{sub, auth.ButtonToSubject(id)})
			}
		}
	}

	if len(rules) == 0 {
		return nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"add role grouping policy: rule list",
			slog.Any("rules", rules),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "add role grouping policy", func(opCtx context.Context) error {
		return AddGroupPolicies(opCtx, r.data.enforcer, rules)
	}, slog.Uint64("role_id", uint64(role.ID)), slog.Int("rules_count", len(rules)))
}

func (r *roleRepo) RemoveGroupPolicy(ctx context.Context, role *biz.Role) error {
	if role == nil || role.ID == 0 {
		return errors.New("remove role grouping policy: invalid role ID")
	}

	sub := auth.RoleToSubject(role.ID)

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"remove role grouping policy",
			slog.String("sub", sub),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "remove role grouping policy", func(opCtx context.Context) error {
		// Remove all API, menu, and button policies inherited by this role: g, role_xxx, _ (fieldIndex 0)
		if _, err := RemoveFilteredGroupingPolicy(opCtx, r.data.enforcer, 0, sub); err != nil {
			return errors.WrapIf(err, "failed to remove grouping policies where the role is the subject")
		}
		return nil
	}, slog.Uint64("role_id", uint64(role.ID)))
}
