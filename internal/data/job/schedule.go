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

type scheduleRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewScheduleRepo creates a schedule repository instance and returns the biz.ScheduleRepo interface.
func NewScheduleRepo(data *Data, logger *slog.Logger) biz.ScheduleRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &scheduleRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizSchedule(po schedulePO) biz.Schedule {
	sr := biz.Schedule{
		ID:            po.ID,
		Name:          po.Name,
		Specification: po.Specification,
		IsEnabled:     po.IsEnabled,
		EnvVars:       po.EnvVars,
		ScriptArgs:    po.ScriptArgs,
		WorkDir:       po.WorkDir,
		Timeout:       po.Timeout,
		IsRetry:       po.IsRetry,
		RetryInterval: po.RetryInterval,
		MaxRetries:    po.MaxRetries,
		Username:      po.Username,
		HostID:        po.HostID,
		ScriptID:      po.ScriptID,
		CreatedAt:     po.CreatedAt,
		UpdatedAt:     po.UpdatedAt,
	}
	if po.Script != nil {
		sr.Script = new(toBizScript(*po.Script))
	}
	return sr
}

func newSchedulePO(do biz.Schedule) schedulePO {
	scriptID := do.ScriptID
	if scriptID == 0 && do.Script != nil {
		scriptID = do.Script.ID
	}
	return schedulePO{
		StandardModel: db.StandardModel{
			BaseModel: db.BaseModel{ID: do.ID},
			CreatedAt: do.CreatedAt,
			UpdatedAt: do.UpdatedAt,
		},
		Name:          do.Name,
		Specification: do.Specification,
		IsEnabled:     do.IsEnabled,
		EnvVars:       do.EnvVars,
		ScriptArgs:    do.ScriptArgs,
		WorkDir:       do.WorkDir,
		Timeout:       do.Timeout,
		IsRetry:       do.IsRetry,
		RetryInterval: do.RetryInterval,
		MaxRetries:    do.MaxRetries,
		Username:      do.Username,
		HostID:        do.HostID,
		ScriptID:      scriptID,
	}
}

// ==================== Repository method implementations ====================

func (r *scheduleRepo) Create(ctx context.Context, do *biz.Schedule) (*biz.Schedule, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create schedule: invalid argument, model must not be nil")
		return nil, errors.New("create schedule: model must not be nil")
	}
	if do.Name == "" {
		return nil, errors.New("create schedule: name cannot be empty")
	}

	po := newSchedulePO(*do)
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
			"create schedule: model details",
			slog.Any("schedule_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create schedule", func(dbCtx context.Context) error {
		return db.DBCreateTX(dbCtx, r.data.gormdb, &schedulePO{}, &po)
	}, slog.String("name", po.Name)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID)
}

// Creates bulk-inserts schedules in a single transaction. It is used by the
// scheduler when one job definition expands into multiple schedule entries.
func (r *scheduleRepo) Creates(ctx context.Context, dos []biz.Schedule) ([]biz.Schedule, error) {
	if len(dos) == 0 {
		return nil, nil
	}

	pos := make([]schedulePO, len(dos))
	now := time.Now()
	for i := range dos {
		if dos[i].Name == "" {
			return nil, errors.New("create schedules: name cannot be empty")
		}
		pos[i] = newSchedulePO(dos[i])
		if pos[i].CreatedAt.IsZero() {
			pos[i].CreatedAt = now
		}
		if pos[i].UpdatedAt.IsZero() {
			pos[i].UpdatedAt = now
		}
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"create schedules: model details",
			slog.Int("count", len(pos)),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create schedules", func(dbCtx context.Context) error {
		return db.DBCreateTX(dbCtx, r.data.gormdb, &schedulePO{}, &pos)
	}, slog.Int("count", len(pos))); err != nil {
		return nil, err
	}

	res := make([]biz.Schedule, len(pos))
	for i := range pos {
		res[i] = toBizSchedule(pos[i])
	}
	return res, nil
}

func (r *scheduleRepo) Update(ctx context.Context, do *biz.Schedule) (*biz.Schedule, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update schedule: invalid argument")
		return nil, errors.New("update schedule: invalid argument")
	}
	if do.Name == "" {
		return nil, errors.New("update schedule: name cannot be empty")
	}

	po := newSchedulePO(*do)
	updates := po.ToUpdateMap()

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update schedule: updated fields",
			slog.Uint64("id", do.ID),
			slog.String("name", do.Name),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update schedule", func(dbCtx context.Context) error {
		var upErr error
		rowsAffected, upErr = db.DBUpdateTx(dbCtx, r.data.gormdb, &schedulePO{}, updates, "id = ?", do.ID)
		return upErr
	}, slog.Uint64("id", do.ID), slog.String("name", do.Name)); err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, errors.New("update schedule: record not found")
	}

	return r.FindByID(ctx, do.ID)
}

// Updates applies multiple schedule updates in a single transaction. Either all
// records are updated or none are.
func (r *scheduleRepo) Updates(ctx context.Context, dos []biz.Schedule) ([]biz.Schedule, error) {
	if len(dos) == 0 {
		return nil, nil
	}
	for i := range dos {
		if dos[i].ID == 0 {
			return nil, errors.New("update schedules: ID must not be 0")
		}
		if dos[i].Name == "" {
			return nil, errors.New("update schedules: name cannot be empty")
		}
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update schedules: request details",
			slog.Int("count", len(dos)),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update schedules", func(dbCtx context.Context) error {
		return db.WithTransaction(dbCtx, r.data.gormdb, func(tx *gorm.DB) error {
			for i := range dos {
				po := newSchedulePO(dos[i])
				res := tx.Model(&schedulePO{}).Where("id = ?", dos[i].ID).Updates(po.ToUpdateMap())
				if res.Error != nil {
					return res.Error
				}
				if res.RowsAffected == 0 {
					// Some databases report zero affected rows for a no-op
					// update, so distinguish that from a missing record.
					var count int64
					if err := tx.Model(&schedulePO{}).Where("id = ?", dos[i].ID).Count(&count).Error; err != nil {
						return err
					}
					if count == 0 {
						return gorm.ErrRecordNotFound
					}
				}
			}
			return nil
		})
	}, slog.Int("count", len(dos))); err != nil {
		return nil, err
	}

	ids := make([]uint64, 0, len(dos))
	for i := range dos {
		ids = append(ids, dos[i].ID)
	}
	found, err := r.FindByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := make(map[uint64]biz.Schedule, len(found))
	for i := range found {
		byID[found[i].ID] = found[i]
	}
	res := make([]biz.Schedule, 0, len(dos))
	for i := range dos {
		if schedule, ok := byID[dos[i].ID]; ok {
			res = append(res, schedule)
		}
	}
	return res, nil
}

// Delete method for single-record callers.
func (r *scheduleRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete schedule: ID must not be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete schedules: primary key IDs",
			slog.Uint64("id", id),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete schedule", func(dbCtx context.Context) error {
		var delErr error
		rowsAffected, delErr = db.DBDeleteTx(dbCtx, r.data.gormdb, &schedulePO{}, "id = ?", id)
		return delErr
	}, slog.Uint64("id", id)); err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("delete schedule: record not found")
	}
	return nil
}

// Delete deletes the schedules with the given IDs in one transaction. Either all
// records exist and are deleted, or none are.
func (r *scheduleRepo) DeleteByIDS(ctx context.Context, ids []uint64) error {
	if len(ids) == 0 {
		return nil
	}

	uniqueIDs := make([]uint64, 0, len(ids))
	seen := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		if id == 0 {
			return errors.New("delete schedules: ID must not be 0")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete schedules: primary key IDs",
			slog.Int("count", len(uniqueIDs)),
		)
	}

	return db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete schedules", func(dbCtx context.Context) error {
		return db.WithTransaction(dbCtx, r.data.gormdb, func(tx *gorm.DB) error {
			res := tx.Where("id IN ?", uniqueIDs).Delete(&schedulePO{})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != int64(len(uniqueIDs)) {
				return gorm.ErrRecordNotFound
			}
			return nil
		})
	}, slog.Int("count", len(uniqueIDs)))
}

func (r *scheduleRepo) FindByID(ctx context.Context, id uint64) (*biz.Schedule, error) {
	if id == 0 {
		return nil, nil
	}

	var po schedulePO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find schedule by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, []string{"Script"}, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizSchedule(po)), nil
}

func (r *scheduleRepo) FindByIDs(ctx context.Context, ids []uint64) ([]biz.Schedule, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	var pos []schedulePO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find schedules by IDs", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).
			Preload("Script").
			Where("id IN ?", ids).
			Find(&pos).Error
	}, slog.Int("count", len(ids))); err != nil {
		return nil, err
	}

	res := make([]biz.Schedule, 0, len(pos))
	for i := range pos {
		res = append(res, toBizSchedule(pos[i]))
	}
	return res, nil
}

func (r *scheduleRepo) List(ctx context.Context, opts db.ListOptions) ([]biz.Schedule, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list schedules: request details",
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
		FilterColumnMap:     scheduleFilterColumns,
		Preloads:            []string{"Script"},
		OrderBy:             orderBy,
		AllowedOrderColumns: scheduleOrderColumns,
	}

	var pos []schedulePO
	var total int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list schedules", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &schedulePO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		return nil, 0, err
	}

	res := make([]biz.Schedule, 0, len(pos))
	for i := range pos {
		res = append(res, toBizSchedule(pos[i]))
	}
	return res, total, nil
}
