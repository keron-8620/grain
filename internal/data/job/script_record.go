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

type scriptRecordRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewScriptRecordRepo creates a script record repository instance and returns the
// biz.ScriptRecordRepo interface.
func NewScriptRecordRepo(data *Data, logger *slog.Logger) biz.ScriptRecordRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &scriptRecordRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizScriptRecord(po scriptRecordPO) biz.ScriptRecord {
	sr := biz.ScriptRecord{
		ID:           po.ID,
		TriggerType:  biz.TriggerType(po.TriggerType),
		Status:       biz.ScriptRecordStatus(po.Status),
		ExitCode:     po.ExitCode,
		EnvVars:      po.EnvVars,
		ScriptArgs:   po.ScriptArgs,
		WorkDir:      po.WorkDir,
		Timeout:      po.Timeout,
		LogName:      po.LogName,
		ErrorMessage: po.ErrorMessage,
		Username:     po.Username,
		ScriptID:     po.ScriptID,
		CreatedAt:    po.CreatedAt,
		UpdatedAt:    po.UpdatedAt,
	}
	if po.Script != nil {
		sr.Script = new(toBizScript(*po.Script))
	}
	return sr
}

func newScriptRecordPO(do biz.ScriptRecord) scriptRecordPO {
	scriptID := do.ScriptID
	if scriptID == 0 && do.Script != nil {
		scriptID = do.Script.ID
	}
	return scriptRecordPO{
		StandardModel: db.StandardModel{
			BaseModel: db.BaseModel{ID: do.ID},
			CreatedAt: do.CreatedAt,
			UpdatedAt: do.UpdatedAt,
		},
		TriggerType:  string(do.TriggerType),
		Status:       int(do.Status),
		ExitCode:     do.ExitCode,
		EnvVars:      do.EnvVars,
		ScriptArgs:   do.ScriptArgs,
		WorkDir:      do.WorkDir,
		Timeout:      do.Timeout,
		LogName:      do.LogName,
		ErrorMessage: do.ErrorMessage,
		Username:     do.Username,
		ScriptID:     scriptID,
	}
}

// ==================== Repository method implementations ====================

func (r *scriptRecordRepo) Create(ctx context.Context, do *biz.ScriptRecord) (*biz.ScriptRecord, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create script record: invalid argument, model must not be nil")
		return nil, errors.New("create script record: model must not be nil")
	}

	po := newScriptRecordPO(*do)
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
			"create script record: model details",
			slog.Any("script_record_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create script record", func(dbCtx context.Context) error {
		return db.DBCreateTX(dbCtx, r.data.gormdb, &scriptRecordPO{}, &po)
	}, slog.Uint64("script_id", po.ScriptID)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID)
}

func (r *scriptRecordRepo) Update(ctx context.Context, id uint64, status, code int, msg string) error {
	if id == 0 {
		r.logger.WarnContext(ctx, "update script record: invalid argument")
		return errors.New("update script record: invalid argument")
	}

	updates := map[string]any{
		"status":        status,
		"exit_code":     code,
		"error_message": msg,
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update script record: updated fields",
			slog.Uint64("id", id),
			slog.Int("status", status),
			slog.Int("exit_code", code),
			slog.String("error_message", msg),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update script record", func(dbCtx context.Context) error {
		var upErr error
		rowsAffected, upErr = db.DBUpdateTx(dbCtx, r.data.gormdb, &scriptRecordPO{}, updates, "id = ?", id)
		return upErr
	}, slog.Uint64("id", id), slog.Int("status", status), slog.Int("exit_code", code), slog.String("error_message", msg)); err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("update script record: record not found")
	}

	return nil
}

func (r *scriptRecordRepo) FindByID(ctx context.Context, id uint64) (*biz.ScriptRecord, error) {
	if id == 0 {
		return nil, nil
	}

	var po scriptRecordPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find script record by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, []string{"Script"}, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizScriptRecord(po)), nil
}

func (r *scriptRecordRepo) FindByIDs(ctx context.Context, ids []uint64) ([]biz.ScriptRecord, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	var pos []scriptRecordPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find script records by IDs", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).
			Preload("Script").
			Where("id IN ?", ids).
			Find(&pos).Error
	}, slog.Int("count", len(ids))); err != nil {
		return nil, err
	}

	res := make([]biz.ScriptRecord, 0, len(pos))
	for i := range pos {
		res = append(res, toBizScriptRecord(pos[i]))
	}
	return res, nil
}

func (r *scriptRecordRepo) List(ctx context.Context, opts db.ListOptions) ([]biz.ScriptRecord, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list script records: request details",
			slog.Any("opts", opts),
		)
	}

	if err := opts.Normalize(); err != nil {
		return nil, 0, err
	}

	orderBy := []string{"id DESC"}
	if opts.OrderBy != "" {
		orderBy = []string{opts.OrderBy}
	}

	qp := db.QueryParams{
		Offset:              opts.Offset,
		Limit:               opts.PageSize,
		Filters:             opts.Filters,
		FilterColumnMap:     scriptRecordFilterColumns,
		Preloads:            []string{"Script"},
		OrderBy:             orderBy,
		AllowedOrderColumns: scriptRecordOrderColumns,
	}

	var pos []scriptRecordPO
	var total int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list script records", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &scriptRecordPO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		return nil, 0, err
	}

	res := make([]biz.ScriptRecord, 0, len(pos))
	for i := range pos {
		res = append(res, toBizScriptRecord(pos[i]))
	}
	return res, total, nil
}
