package cmdb

import (
	"context"
	"log/slog"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"

	biz "grain/internal/biz/cmdb"
	"grain/pkg/db"
)

type hostRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewHostRepo creates a host repository instance and returns the biz.HostRepo interface.
func NewHostRepo(data *Data, logger *slog.Logger) biz.HostRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &hostRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizHost(po hostPO) biz.Host {
	return biz.Host{
		ID:        po.ID,
		Name:      po.Name,
		Label:     po.Label,
		HostIP:    po.HostIP,
		HostPort:  po.HostPort,
		HostUser:  po.HostUser,
		Protocol:  po.Protocol,
		PyPath:    po.PyPath,
		Remark:    po.Remark,
		OSType:    po.OSType,
		HostKey:   po.SSHHostKey,
		CreatedAt: po.CreatedAt,
		UpdatedAt: po.UpdatedAt,
	}
}

func newHostPO(do biz.Host) hostPO {
	return hostPO{
		SoftDeleteModel: db.SoftDeleteModel{
			StandardModel: db.StandardModel{
				BaseModel: db.BaseModel{ID: do.ID},
				CreatedAt: do.CreatedAt,
				UpdatedAt: do.UpdatedAt,
			},
		},
		Name:       do.Name,
		Label:      do.Label,
		HostIP:     do.HostIP,
		HostPort:   do.HostPort,
		HostUser:   do.HostUser,
		Protocol:   do.Protocol,
		PyPath:     do.PyPath,
		Remark:     do.Remark,
		OSType:     do.OSType,
		SSHHostKey: do.HostKey,
	}
}

// ==================== Repository method implementations ====================

func (r *hostRepo) Create(ctx context.Context, do *biz.Host) (*biz.Host, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create host: invalid argument, model must not be nil")
		return nil, errors.New("create host: model must not be nil")
	}
	if do.Name == "" {
		return nil, errors.New("create host: name cannot be empty")
	}

	po := newHostPO(*do)
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
			"create host: model details",
			slog.Any("host_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create host", func(dbCtx context.Context) error {
		return db.DBCreateTX(dbCtx, r.data.gormdb, &hostPO{}, &po)
	}, slog.String("name", po.Name)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID)
}

func (r *hostRepo) Update(ctx context.Context, do *biz.Host) (*biz.Host, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update host: invalid argument")
		return nil, errors.New("update host: invalid argument")
	}
	if do.Name == "" {
		return nil, errors.New("update host: name cannot be empty")
	}

	po := newHostPO(*do)
	updates := po.ToUpdateMap()

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update host: updated fields",
			slog.Uint64("id", do.ID),
			slog.String("name", do.Name),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update host", func(dbCtx context.Context) error {
		var upErr error
		rowsAffected, upErr = db.DBUpdateTx(dbCtx, r.data.gormdb, &hostPO{}, updates, "id = ?", do.ID)
		return upErr
	}, slog.Uint64("id", do.ID), slog.String("name", do.Name)); err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, errors.New("update host: record not found")
	}

	return r.FindByID(ctx, do.ID)
}

func (r *hostRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete host: ID must not be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete host: primary key ID",
			slog.Uint64("id", id),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete host", func(dbCtx context.Context) error {
		var delErr error
		rowsAffected, delErr = db.DBDeleteTx(dbCtx, r.data.gormdb, &hostPO{}, "id = ?", id)
		return delErr
	}, slog.Uint64("id", id)); err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("delete host: record not found")
	}
	return nil
}

func (r *hostRepo) FindByID(ctx context.Context, id uint64) (*biz.Host, error) {
	if id == 0 {
		return nil, nil
	}

	var po hostPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find host by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, nil, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizHost(po)), nil
}

func (r *hostRepo) FindByIDs(ctx context.Context, ids []uint64) ([]biz.Host, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	var pos []hostPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find hosts by IDs", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Where("id IN ?", ids).Find(&pos).Error
	}, slog.Int("count", len(ids))); err != nil {
		return nil, err
	}

	res := make([]biz.Host, 0, len(pos))
	for i := range pos {
		res = append(res, toBizHost(pos[i]))
	}
	return res, nil
}

func (r *hostRepo) List(ctx context.Context, opts db.ListOptions) ([]biz.Host, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list hosts: request details",
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
		FilterColumnMap:     hostFilterColumns,
		OrderBy:             orderBy,
		AllowedOrderColumns: hostOrderColumns,
	}

	var pos []hostPO
	var total int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list hosts", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &hostPO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		return nil, 0, err
	}

	res := make([]biz.Host, 0, len(pos))
	for i := range pos {
		res = append(res, toBizHost(pos[i]))
	}
	return res, total, nil
}

// ExistsByHostIPPortUser reports whether an active host with the same connection
// tuple already exists. Additional filters allow callers to exclude a record
// (for example "id != ?" during an update).
func (r *hostRepo) ExistsByHostIPPortUser(ctx context.Context, ip string, port uint16, user string, filters []db.ListFilter) (bool, error) {
	if ip == "" || user == "" {
		return false, errors.New("exists host: IP and user cannot be empty")
	}

	var count int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "check host connection tuple", func(dbCtx context.Context) error {
		query, err := db.BuildQuery(r.data.gormdb.WithContext(dbCtx), &hostPO{}, db.QueryParams{
			Filters:         filters,
			FilterColumnMap: hostFilterColumns,
		})
		if err != nil {
			return err
		}
		return query.
			Where("host_ip = ? AND host_port = ? AND host_user = ?", ip, port, user).
			Count(&count).Error
	}, slog.String("host_ip", ip), slog.Uint64("host_port", uint64(port)), slog.String("host_user", user)); err != nil {
		return false, err
	}
	return count > 0, nil
}
