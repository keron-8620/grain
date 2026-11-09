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

type buttonRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewButtonRepo creates a button repository instance and returns the biz.ButtonRepo interface
func NewButtonRepo(
	data *Data,
	logger *slog.Logger,
) biz.ButtonRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &buttonRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizButton(po *buttonPO) *biz.Button {
	if po == nil {
		return nil
	}
	b := &biz.Button{
		ID:        po.ID,
		Name:      po.Name,
		Sort:      po.Sort,
		IsActive:  po.IsActive,
		Descr:     po.Descr,
		MenuID:    po.MenuID,
		CreatedAt: po.CreatedAt,
		UpdatedAt: po.UpdatedAt,
	}

	if po.Menu.ID > 0 {
		b.Menu = toBizMenu(&po.Menu)
	}

	if len(po.Apis) > 0 {
		b.Apis = make([]*biz.Api, len(po.Apis))
		b.ApiIDs = make([]uint64, len(po.Apis))
		for i := range po.Apis {
			b.Apis[i] = toBizApi(&po.Apis[i])
			b.ApiIDs[i] = po.Apis[i].ID
		}
	}

	return b
}

func newButtonPO(do *biz.Button) *buttonPO {
	if do == nil {
		return nil
	}
	po := &buttonPO{
		ID:        do.ID,
		CreatedAt: do.CreatedAt,
		UpdatedAt: do.UpdatedAt,
		Name:      do.Name,
		Sort:      do.Sort,
		IsActive:  do.IsActive,
		Descr:     do.Descr,
		MenuID:    do.MenuID,
	}

	if len(do.Apis) > 0 {
		po.Apis = make([]apiPO, 0, len(do.Apis))
		for _, a := range do.Apis {
			if a != nil && a.ID > 0 {
				po.Apis = append(po.Apis, *newApiPO(a))
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

func (r *buttonRepo) Create(ctx context.Context, do *biz.Button) (*biz.Button, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create button: invalid argument, model cannot be nil")
		return nil, errors.New("create button: model cannot be nil")
	}

	po := newButtonPO(do)
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
			"create button: model details",
			slog.Any("button_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create button", func(dbCtx context.Context) error {
		return db.DBCreateRelationTx(dbCtx, r.data.gormdb, &buttonPO{}, po, upmap)
	}, slog.String("name", po.Name), slog.Uint64("menu_id", uint64(po.MenuID))); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID, "Menu", "Apis")
}

func (r *buttonRepo) Update(ctx context.Context, do *biz.Button) (*biz.Button, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update button: invalid argument")
		return nil, errors.New("update button: invalid argument")
	}

	po := newButtonPO(do)
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
			"update button: update data",
			slog.Any("updates", updates),
			slog.Uint64("id", uint64(do.ID)),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update button", func(dbCtx context.Context) error {
		return db.DBUpdateRelationTx(dbCtx, r.data.gormdb, &buttonPO{}, updates, upmap, "id = ?", do.ID)
	}, slog.Uint64("id", uint64(do.ID)), slog.String("name", po.Name), slog.Uint64("menu_id", uint64(po.MenuID))); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, do.ID, "Menu", "Apis")
}

func (r *buttonRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete button: ID cannot be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete button: primary key ID",
			slog.Uint64("id", id),
		)
	}

	return db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete button", func(dbCtx context.Context) error {
		_, delErr := db.DBDeleteTx(dbCtx, r.data.gormdb, &buttonPO{}, "id = ?", id)
		return delErr
	}, slog.Uint64("id", id))
}

func (r *buttonRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*biz.Button, error) {
	if id == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find button by ID",
			slog.Uint64("id", id),
			slog.Any("preloads", preloads),
		)
	}

	var po buttonPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find button by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, preloads, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return toBizButton(&po), nil
}

func (r *buttonRepo) FindByIDs(ctx context.Context, ids []uint64, preloads ...string) ([]*biz.Button, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find buttons by IDs",
			slog.Any("ids", ids),
			slog.Any("preloads", preloads),
		)
	}

	var pos []buttonPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find buttons by IDs", func(dbCtx context.Context) error {
		tx := r.data.gormdb.WithContext(dbCtx)
		for _, p := range preloads {
			tx = tx.Preload(p)
		}
		return tx.Where("id IN ?", ids).Find(&pos).Error
	}, slog.Int("count", len(ids))); err != nil {
		return nil, err
	}

	res := make([]*biz.Button, 0, len(pos))
	for i := range pos {
		res = append(res, toBizButton(&pos[i]))
	}
	return res, nil
}

func (r *buttonRepo) FindByName(ctx context.Context, name string) (*biz.Button, error) {
	var po buttonPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find button by name", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, nil, "name = ?", name)
	}, slog.String("name", name)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return toBizButton(&po), nil
}

func (r *buttonRepo) List(ctx context.Context, opts biz.ButtonListOptions) ([]*biz.Button, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list buttons: request details",
			slog.Any("opts", opts),
		)
	}

	if opts.PageSize <= 0 {
		opts.PageSize = db.DefaultPageSize
	}
	if err := db.ValidateListOptions(opts.Offset, opts.PageSize); err != nil {
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
		FilterColumnMap:     buttonFilterColumns,
		Preloads:            []string{"Menu", "Apis"},
		OrderBy:             orderBy,
		AllowedOrderColumns: buttonOrderColumns,
	}

	var pos []buttonPO
	var total int64

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list buttons", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &buttonPO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		if errors.Is(err, db.ErrInvalidListOption) {
			return nil, 0, err
		}
		return nil, 0, err
	}

	res := make([]*biz.Button, 0, len(pos))
	for i := range pos {
		res = append(res, toBizButton(&pos[i]))
	}
	return res, total, nil
}

func (r *buttonRepo) ListAllWithApis(ctx context.Context) ([]*biz.Button, error) {
	qp := db.QueryParams{
		Preloads: []string{"Apis"},
		OrderBy:  []string{"id ASC"},
	}

	var pos []buttonPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list all buttons with apis", func(dbCtx context.Context) error {
		return db.DBList(dbCtx, r.data.gormdb, &buttonPO{}, &pos, qp)
	}); err != nil {
		return nil, err
	}

	res := make([]*biz.Button, 0, len(pos))
	for i := range pos {
		res = append(res, toBizButton(&pos[i]))
	}
	return res, nil
}

// ==================== Casbin grouping policy management ====================

func (r *buttonRepo) AddGroupPolicy(ctx context.Context, button *biz.Button) error {
	if button == nil || button.ID == 0 {
		return errors.New("add button grouping policy: invalid button ID")
	}
	if button.MenuID == 0 {
		return errors.New("add button grouping policy: invalid menu ID")
	}

	sub := auth.ButtonToSubject(button.ID)
	menuObj := auth.MenuToSubject(button.MenuID)
	rules := [][]string{{sub, menuObj}}

	seen := make(map[uint64]struct{})
	addApiRule := func(id uint64) {
		if id > 0 {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				rules = append(rules, []string{sub, auth.ApiToSubject(id)})
			}
		}
	}

	// Associated API inheritance policies: (button_sub, api_sub)
	if len(button.Apis) > 0 {
		for _, api := range button.Apis {
			if api != nil {
				addApiRule(api.ID)
			}
		}
	} else if len(button.ApiIDs) > 0 {
		for _, id := range button.ApiIDs {
			addApiRule(id)
		}
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"add button grouping policy: rule list",
			slog.Any("rules", rules),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "add button grouping policy", func(opCtx context.Context) error {
		return AddGroupPolicies(opCtx, r.data.enforcer, rules)
	}, slog.Uint64("button_id", uint64(button.ID)), slog.Uint64("menu_id", uint64(button.MenuID)), slog.Int("rules_count", len(rules)))
}

func (r *buttonRepo) RemoveGroupPolicy(ctx context.Context, button *biz.Button, removeInherited bool) error {
	if button == nil || button.ID == 0 {
		return errors.New("remove button grouping policy: invalid button ID")
	}

	sub := auth.ButtonToSubject(button.ID)

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"remove button grouping policy",
			slog.String("sub", sub),
			slog.Bool("removeInherited", removeInherited),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "remove button grouping policy", func(opCtx context.Context) error {
		if removeInherited {
			// Remove policies where other subjects inherit this button: g, _, button_xxx (fieldIndex 1)
			if _, err := RemoveFilteredGroupingPolicy(opCtx, r.data.enforcer, 1, sub); err != nil {
				return errors.WrapIf(err, "failed to remove grouping policies inheriting from this button")
			}
		}

		// Remove policies this button inherits from menus or APIs: g, button_xxx, _ (fieldIndex 0)
		if _, err := RemoveFilteredGroupingPolicy(opCtx, r.data.enforcer, 0, sub); err != nil {
			return errors.WrapIf(err, "failed to remove grouping policies where the button is the subject")
		}
		return nil
	}, slog.Uint64("button_id", uint64(button.ID)))
}
