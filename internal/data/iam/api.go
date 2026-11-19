package iam

import (
	"context"
	stderrors "errors"
	"log/slog"
	"strings"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	biz "grain/internal/biz/iam"
	"grain/pkg/auth"
	"grain/pkg/db"
)

type apiRepo struct {
	data   *Data
	logger *slog.Logger
}

// NewApiRepo creates an API repository instance and returns the biz.ApiRepo interface
func NewApiRepo(
	data *Data,
	logger *slog.Logger,
) biz.ApiRepo {
	if logger == nil {
		logger = slog.Default()
	}
	return &apiRepo{
		data:   data,
		logger: logger,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizApi(po apiPO) biz.Api {
	return biz.Api{
		ID:        po.ID,
		URL:       po.URL,
		Method:    po.Method,
		Label:     po.Label,
		Descr:     po.Descr,
		CreatedAt: po.CreatedAt,
		UpdatedAt: po.UpdatedAt,
	}
}

func newApiPO(do biz.Api) apiPO {
	return apiPO{
		ID:     do.ID,
		URL:    strings.TrimSpace(do.URL),
		Method: strings.ToUpper(strings.TrimSpace(do.Method)),
		Label:  do.Label,
		Descr:  do.Descr,
	}
}

// ==================== Repository method implementations ====================

func (r *apiRepo) Create(ctx context.Context, do *biz.Api) (*biz.Api, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create API: invalid argument, model cannot be nil")
		return nil, errors.New("create API: model cannot be nil")
	}
	if do.URL == "" || do.Method == "" {
		r.logger.WarnContext(ctx, "create API: url and method cannot be empty")
		return nil, errors.New("create API: url and method cannot be empty")
	}

	po := newApiPO(*do)
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
			"create API: model details",
			slog.Any("api_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create API", func(dbCtx context.Context) error {
		return db.DBCreate(dbCtx, r.data.gormdb, &apiPO{}, &po)
	}, slog.String("url", po.URL), slog.String("method", po.Method)); err != nil {
		return nil, err
	}

	return new(toBizApi(po)), nil
}

func (r *apiRepo) Update(ctx context.Context, do *biz.Api) (*biz.Api, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update API: invalid argument")
		return nil, errors.New("update API: invalid argument")
	}
	if do.URL == "" || do.Method == "" {
		r.logger.WarnContext(ctx, "update API: url and method cannot be empty")
		return nil, errors.New("update API: url and method cannot be empty")
	}

	po := newApiPO(*do)
	updates := po.ToUpdateMap()

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update API: update data",
			slog.Any("updates", updates),
			slog.Uint64("id", uint64(do.ID)),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update API", func(dbCtx context.Context) error {
		var updateErr error
		rowsAffected, updateErr = db.DBUpdate(dbCtx, r.data.gormdb, &apiPO{}, updates, "id = ?", do.ID)
		return updateErr
	}, slog.Uint64("id", uint64(do.ID)), slog.String("url", do.URL), slog.String("method", do.Method)); err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, errors.New("update API: record not found")
	}

	return r.FindByID(ctx, do.ID)
}

func (r *apiRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete API: ID cannot be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete API: primary key ID",
			slog.Uint64("id", id),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete API", func(dbCtx context.Context) error {
		var delErr error
		rowsAffected, delErr = db.DBDelete(dbCtx, r.data.gormdb, &apiPO{}, "id = ?", id)
		return delErr
	}, slog.Uint64("id", id)); err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("delete API: record not found")
	}
	return nil
}

func (r *apiRepo) FindByID(ctx context.Context, id uint64) (*biz.Api, error) {
	if id == 0 {
		return nil, errors.New("find API: ID cannot be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find API by ID",
			slog.Uint64("id", id),
		)
	}

	var po apiPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find API by ID", func(dbCtx context.Context) error {
		return db.DBFind(dbCtx, r.data.gormdb, &po, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizApi(po)), nil
}

func (r *apiRepo) FindByIDs(ctx context.Context, ids []uint64) ([]biz.Api, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find APIs by IDs",
			slog.Any("ids", ids),
		)
	}

	var pos []apiPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find APIs by IDs", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Where("id IN ?", ids).Find(&pos).Error
	}, slog.Int("count", len(ids))); err != nil {
		return nil, err
	}

	res := make([]biz.Api, 0, len(pos))
	for i := range pos {
		res = append(res, toBizApi(pos[i]))
	}
	return res, nil
}

func (r *apiRepo) FindByURLAndMethod(ctx context.Context, url, method string) (*biz.Api, error) {
	if url == "" || method == "" {
		return nil, errors.New("find API: URL and method cannot be empty")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find API by URL and method",
			slog.String("url", url),
			slog.String("method", method),
		)
	}

	var po apiPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find API by URL and method", func(dbCtx context.Context) error {
		return db.DBFind(dbCtx, r.data.gormdb, &po, "url = ? AND method = ?", url, method)
	}, slog.String("url", url), slog.String("method", method)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return new(toBizApi(po)), nil
}

func (r *apiRepo) FindByRoutes(ctx context.Context, routes []biz.ApiRoute) ([]biz.Api, error) {
	if len(routes) == 0 {
		return nil, nil
	}

	var conditions []string
	var args []any
	for _, rt := range routes {
		url := strings.TrimSpace(rt.URL)
		method := strings.ToUpper(strings.TrimSpace(rt.Method))
		if url == "" || method == "" {
			continue
		}
		conditions = append(conditions, "(url = ? AND method = ?)")
		args = append(args, url, method)
	}
	if len(conditions) == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find APIs by routes",
			slog.Int("route_count", len(routes)),
		)
	}

	var pos []apiPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find APIs by routes", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Where(strings.Join(conditions, " OR "), args...).Find(&pos).Error
	}, slog.Int("route_count", len(routes))); err != nil {
		return nil, err
	}

	res := make([]biz.Api, len(pos))
	for i := range pos {
		res[i] = toBizApi(pos[i])
	}
	return res, nil
}

func (r *apiRepo) List(ctx context.Context, opts db.ListOptions) ([]biz.Api, int64, error) {

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list APIs: request details",
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
		FilterColumnMap:     apiFilterColumns,
		OrderBy:             orderBy,
		AllowedOrderColumns: apiOrderColumns,
	}

	var pos []apiPO
	var total int64

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list APIs", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &apiPO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		return nil, 0, err
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		ids := db.MapToUint64s(pos, func(p apiPO) uint64 { return p.ID })
		r.logger.DebugContext(
			ctx,
			"list APIs: fetched record details",
			slog.Int64("total", total),
			slog.String("api_ids", db.JoinUint64(ids, ",")),
		)
	}

	res := make([]biz.Api, 0, len(pos))
	for i := range pos {
		res = append(res, toBizApi(pos[i]))
	}
	return res, total, nil
}

// SyncRoutes idempotently backfills routes into iam_api: deduplicates by (url, method), leaving existing rows unchanged.
func (r *apiRepo) SyncRoutes(ctx context.Context, routes []biz.ApiRoute) (int, error) {
	if len(routes) == 0 {
		return 0, nil
	}

	seen := make(map[string]struct{}, len(routes))
	pos := make([]apiPO, 0, len(routes))

	for _, route := range routes {
		url := strings.TrimSpace(route.URL)
		method := strings.ToUpper(strings.TrimSpace(route.Method))
		if url == "" || method == "" {
			continue
		}

		key := method + ":" + url
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		pos = append(pos, apiPO{
			URL:    url,
			Method: method,
			Label:  route.Label,
			Descr:  route.Descr,
		})
	}
	if len(pos) == 0 {
		return 0, nil
	}

	var created int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "sync API routes", func(dbCtx context.Context) error {
		res := r.data.gormdb.WithContext(dbCtx).
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "url"}, {Name: "method"}},
				DoNothing: true,
			}).
			CreateInBatches(pos, 100)
		if res.Error != nil {
			return res.Error
		}
		created = res.RowsAffected
		return nil
	}, slog.Int("route_count", len(routes))); err != nil {
		return 0, err
	}
	if created > 0 {
		r.logger.InfoContext(ctx, "synced API routes to catalog", slog.Int64("created", created), slog.Int("total", len(routes)))
	}
	return int(created), nil
}

// ==================== Casbin policy management ====================

func (r *apiRepo) AddPolicy(
	ctx context.Context,
	do *biz.Api,
) error {
	if do == nil {
		return errors.New("add API policy: model cannot be nil")
	}
	if do.ID == 0 {
		return errors.New("add API policy: API ID cannot be 0")
	}
	if do.URL == "" {
		return errors.New("add API policy: URL cannot be empty")
	}
	if do.Method == "" {
		return errors.New("add API policy: request method cannot be empty")
	}

	return r.AddPolicies(ctx, []biz.Api{*do})
}

func (r *apiRepo) AddPolicies(
	ctx context.Context,
	apis []biz.Api,
) error {
	if len(apis) == 0 {
		return nil
	}

	rules := make([][]string, 0, len(apis))
	for _, a := range apis {
		if a.ID == 0 || a.URL == "" || a.Method == "" {
			continue
		}
		sub := auth.ApiToSubject(a.ID)
		rules = append(rules, []string{sub, a.URL, a.Method})
	}
	if len(rules) == 0 {
		return nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"add API policies batch: request details",
			slog.Int("rules_count", len(rules)),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "add API policies batch", func(opCtx context.Context) error {
		return AddPolicies(opCtx, r.data.enforcer, rules)
	}, slog.Int("rules_count", len(rules)))
}

func (r *apiRepo) UpdatePolicy(
	ctx context.Context,
	oldApi, newApi *biz.Api,
) error {
	if oldApi == nil || newApi == nil {
		return errors.New("update API policy: arguments cannot be nil")
	}
	if oldApi.ID == 0 || newApi.ID == 0 {
		return errors.New("update API policy: API ID cannot be 0")
	}
	if oldApi.URL == "" || newApi.URL == "" {
		return errors.New("update API policy: URL cannot be empty")
	}
	if oldApi.Method == "" || newApi.Method == "" {
		return errors.New("update API policy: request method cannot be empty")
	}

	// Short-circuit if policy rules haven't changed (e.g. only label or descr updated)
	if oldApi.ID == newApi.ID && oldApi.URL == newApi.URL && oldApi.Method == newApi.Method {
		return nil
	}

	oldSub := auth.ApiToSubject(oldApi.ID)
	newSub := auth.ApiToSubject(newApi.ID)

	oldRules := [][]string{{oldSub, oldApi.URL, oldApi.Method}}
	newRules := [][]string{{newSub, newApi.URL, newApi.Method}}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update API policy: rule replacement",
			slog.Any("old_rules", oldRules),
			slog.Any("new_rules", newRules),
		)
	}

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "update API policy", func(opCtx context.Context) error {
		if err := RemovePolicies(opCtx, r.data.enforcer, oldRules); err != nil {
			return errors.WrapIf(err, "failed to remove old API policies")
		}
		if err := AddPolicies(opCtx, r.data.enforcer, newRules); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(opCtx), 2*time.Second)
			defer cancel()
			if recErr := AddPolicies(rollbackCtx, r.data.enforcer, oldRules); recErr != nil {
				return errors.WrapIf(stderrors.Join(err, recErr), "failed to add new API policies and restore old policy")
			}
			return errors.WrapIf(err, "failed to add new API policies")
		}
		return nil
	}, slog.Uint64("old_api_id", uint64(oldApi.ID)), slog.Uint64("new_api_id", uint64(newApi.ID)))
}

func (r *apiRepo) RemovePolicy(
	ctx context.Context,
	do *biz.Api,
	removeInherited bool,
) error {
	if do == nil {
		return errors.New("remove API policy: model cannot be nil")
	}
	if do.ID == 0 {
		return errors.New("remove API policy: API ID cannot be 0")
	}
	if do.URL == "" {
		return errors.New("remove API policy: URL cannot be empty")
	}
	if do.Method == "" {
		return errors.New("remove API policy: request method cannot be empty")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"remove API policy: request details",
			slog.Any("api", do),
			slog.Bool("removeInherited", removeInherited),
		)
	}

	sub := auth.ApiToSubject(do.ID)

	return runPolicyOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, "remove API policy", func(opCtx context.Context) error {
		if removeInherited {
			if _, err := RemoveFilteredGroupingPolicy(opCtx, r.data.enforcer, 1, sub); err != nil {
				return errors.WrapIf(err, "failed to remove grouping policies inheriting from this API")
			}
		}

		rules := [][]string{{sub, do.URL, do.Method}}
		return RemovePolicies(opCtx, r.data.enforcer, rules)
	}, slog.Uint64("api_id", uint64(do.ID)), slog.String("url", do.URL), slog.String("method", do.Method))
}
