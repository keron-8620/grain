package job

import (
	"context"
	"log/slog"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"

	biz "grain/internal/biz/job"
	"grain/pkg/db"
)

type scriptRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewScriptRepo creates a script repository instance and returns the biz.ScriptRepo interface.
func NewScriptRepo(data *Data, logger *slog.Logger) biz.ScriptRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &scriptRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizScript(po scriptPO) biz.Script {
	return biz.Script{
		ID:        po.ID,
		Name:      po.Name,
		Descr:     po.Descr,
		ParamDesc: po.ParamDesc,
		Project:   po.Project,
		Label:     po.Label,
		Language:  po.Language,
		Status:    po.Status,
		Username:  po.Username,
		CreatedAt: po.CreatedAt,
		UpdatedAt: po.UpdatedAt,
	}
}

func newScriptPO(do biz.Script) scriptPO {
	return scriptPO{
		SoftDeleteModel: db.SoftDeleteModel{
			StandardModel: db.StandardModel{
				BaseModel: db.BaseModel{ID: do.ID},
				CreatedAt: do.CreatedAt,
				UpdatedAt: do.UpdatedAt,
			},
		},
		Name:      do.Name,
		Descr:     do.Descr,
		ParamDesc: do.ParamDesc,
		Project:   do.Project,
		Label:     do.Label,
		Language:  do.Language,
		Status:    do.Status,
		Username:  do.Username,
	}
}

// ==================== Repository method implementations ====================

func (r *scriptRepo) Create(ctx context.Context, do *biz.Script) (*biz.Script, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create script: invalid argument, model must not be nil")
		return nil, errors.New("create script: model must not be nil")
	}
	if do.Name == "" {
		return nil, errors.New("create script: name cannot be empty")
	}

	po := newScriptPO(*do)
	now := time.Now()
	if po.CreatedAt.IsZero() {
		po.CreatedAt = now
	}
	if po.UpdatedAt.IsZero() {
		po.UpdatedAt = now
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"create script: model details",
			slog.Any("script_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create script", func(dbCtx context.Context) error {
		return db.DBCreateTX(dbCtx, r.data.gormdb, &scriptPO{}, &po)
	}, slog.String("name", po.Name), slog.String("project", po.Project)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID)
}

func (r *scriptRepo) Update(ctx context.Context, do *biz.Script) (*biz.Script, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update script: invalid argument")
		return nil, errors.New("update script: invalid argument")
	}
	if do.Name == "" {
		return nil, errors.New("update script: name cannot be empty")
	}

	po := newScriptPO(*do)
	updates := po.ToUpdateMap()

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update script: updated fields",
			slog.Uint64("id", do.ID),
			slog.String("name", do.Name),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update script", func(dbCtx context.Context) error {
		var upErr error
		rowsAffected, upErr = db.DBUpdateTx(dbCtx, r.data.gormdb, &scriptPO{}, updates, "id = ?", do.ID)
		return upErr
	}, slog.Uint64("id", do.ID), slog.String("name", do.Name)); err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, errors.New("update script: record not found")
	}

	return r.FindByID(ctx, do.ID)
}

func (r *scriptRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete script: ID must not be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete script: primary key ID",
			slog.Uint64("id", id),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete script", func(dbCtx context.Context) error {
		var delErr error
		rowsAffected, delErr = db.DBDeleteTx(dbCtx, r.data.gormdb, &scriptPO{}, "id = ?", id)
		return delErr
	}, slog.Uint64("id", id)); err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("delete script: record not found")
	}
	return nil
}

func (r *scriptRepo) FindByID(ctx context.Context, id uint64) (*biz.Script, error) {
	if id == 0 {
		return nil, nil
	}

	var po scriptPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find script by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, nil, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizScript(po)), nil
}

func (r *scriptRepo) FindByIDs(ctx context.Context, ids []uint64) ([]biz.Script, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	var pos []scriptPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find scripts by IDs", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Where("id IN ?", ids).Find(&pos).Error
	}, slog.Int("count", len(ids))); err != nil {
		return nil, err
	}

	res := make([]biz.Script, 0, len(pos))
	for i := range pos {
		res = append(res, toBizScript(pos[i]))
	}
	return res, nil
}

// FindByProjectLableName finds a script by its (project, label, name) business key.
// The key is indexed but not unique; the first matching script is returned.
func (r *scriptRepo) FindByProjectLableName(ctx context.Context, project, lable, name string) (*biz.Script, error) {
	if name == "" {
		return nil, nil
	}

	var po scriptPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find script by project/label/name", func(dbCtx context.Context) error {
		return db.DBFindOne(
			dbCtx,
			r.data.gormdb,
			&po,
			nil,
			"project = ? AND label = ? AND name = ?",
			project, lable, name,
		)
	}, slog.String("project", project), slog.String("label", lable), slog.String("name", name)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizScript(po)), nil
}

func (r *scriptRepo) List(ctx context.Context, opts db.ListOptions) ([]biz.Script, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list scripts: request details",
			slog.Any("opts", opts),
		)
	}

	if err := opts.Normalize(); err != nil {
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
		FilterColumnMap:     scriptFilterColumns,
		OrderBy:             orderBy,
		AllowedOrderColumns: scriptOrderColumns,
	}

	var pos []scriptPO
	var total int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list scripts", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &scriptPO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		return nil, 0, err
	}

	res := make([]biz.Script, 0, len(pos))
	for i := range pos {
		res = append(res, toBizScript(pos[i]))
	}
	return res, total, nil
}
