package iam

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"

	biz "grain/internal/biz/iam"
	"grain/pkg/db"
)

type userRepo struct {
	data       *Data
	cache      UserCache
	logger     *slog.Logger
	ttlSeconds int64
}

// NewUserRepo creates a user repository instance and returns the biz.UserRepo interface
func NewUserRepo(
	data *Data,
	logger *slog.Logger,
	refreshTokenExpiration time.Duration,
	cache ...UserCache,
) biz.UserRepo {
	if logger == nil {
		logger = slog.Default()
	}
	ttlExpiration := refreshTokenExpiration
	if ttlExpiration == 0 {
		ttlExpiration = 7 * 24 * time.Hour
	}
	ttlSeconds := int64(ttlExpiration / time.Second)

	var uc UserCache
	if len(cache) > 0 && cache[0] != nil {
		uc = cache[0]
	} else if data != nil && data.userCache != nil {
		uc = data.userCache
	} else {
		uc = NewMemoryUserCache()
	}

	return &userRepo{
		data:       data,
		cache:      uc,
		logger:     logger,
		ttlSeconds: ttlSeconds,
	}
}

// ==================== DO ↔ PO conversion ====================

func toBizUser(po *userPO) *biz.User {
	if po == nil {
		return nil
	}
	u := &biz.User{
		ID:           po.ID,
		Username:     po.Username,
		Password:     po.Password,
		IsActive:     po.IsActive,
		RoleID:       po.RoleID,
		TokenVersion: po.TokenVersion,
		CreatedAt:    po.CreatedAt,
		UpdatedAt:    po.UpdatedAt,
	}

	if po.Role.ID > 0 {
		u.Role = toBizRole(&po.Role)
	}

	return u
}

func newUserPO(do *biz.User) *userPO {
	if do == nil {
		return nil
	}
	return &userPO{
		ID:           do.ID,
		CreatedAt:    do.CreatedAt,
		UpdatedAt:    do.UpdatedAt,
		Username:     do.Username,
		Password:     do.Password,
		IsActive:     do.IsActive,
		RoleID:       do.RoleID,
		TokenVersion: do.TokenVersion,
	}
}

// ==================== Repository method implementations ====================

func (r *userRepo) Create(ctx context.Context, do *biz.User) (*biz.User, error) {
	if do == nil {
		r.logger.WarnContext(ctx, "create user: invalid argument, model must not be nil")
		return nil, errors.New("create user: model must not be nil")
	}
	if do.Username == "" {
		return nil, errors.New("create user: username cannot be empty")
	}

	po := newUserPO(do)
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
			"create user: model details",
			slog.Any("user_po", po),
		)
	}

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "create user", func(dbCtx context.Context) error {
		return db.DBCreateTX(dbCtx, r.data.gormdb, &userPO{}, po)
	}, slog.String("username", po.Username)); err != nil {
		return nil, err
	}

	return r.FindByID(ctx, po.ID, "Role")
}

func (r *userRepo) Update(ctx context.Context, do *biz.User) (*biz.User, error) {
	if do == nil || do.ID == 0 {
		r.logger.WarnContext(ctx, "update user: invalid argument")
		return nil, errors.New("update user: invalid argument")
	}
	if do.Username == "" {
		return nil, errors.New("update user: username cannot be empty")
	}

	po := newUserPO(do)
	updates := po.ToUpdateMap()

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"update user: updated fields",
			slog.Uint64("id", uint64(do.ID)),
			slog.String("username", do.Username),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "update user", func(dbCtx context.Context) error {
		var upErr error
		rowsAffected, upErr = db.DBUpdateTx(dbCtx, r.data.gormdb, &userPO{}, updates, "id = ?", do.ID)
		return upErr
	}, slog.Uint64("id", uint64(do.ID)), slog.String("username", do.Username)); err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, errors.New("update user: record not found")
	}

	return r.FindByID(ctx, do.ID, "Role")
}

func (r *userRepo) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("delete user: ID must not be 0")
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"delete user: primary key ID",
			slog.Uint64("id", id),
		)
	}

	var rowsAffected int64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "delete user", func(dbCtx context.Context) error {
		var delErr error
		rowsAffected, delErr = db.DBDeleteTx(dbCtx, r.data.gormdb, &userPO{}, "id = ?", id)
		return delErr
	}, slog.Uint64("id", id)); err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("delete user: record not found")
	}
	r.invalidateTokenVersionCache(ctx, id)
	return nil
}

func (r *userRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*biz.User, error) {
	if id == 0 {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find user by ID",
			slog.Uint64("id", id),
		)
	}

	var po userPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find user by ID", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, preloads, "id = ?", id)
	}, slog.Uint64("id", id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return toBizUser(&po), nil
}

func (r *userRepo) FindByUsername(ctx context.Context, username string, preloads ...string) (*biz.User, error) {
	if username == "" {
		return nil, nil
	}

	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"find user by username",
			slog.String("username", username),
		)
	}

	var po userPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "find user by username", func(dbCtx context.Context) error {
		return db.DBFindOne(dbCtx, r.data.gormdb, &po, preloads, "username = ?", username)
	}, slog.String("username", username)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return toBizUser(&po), nil
}

func (r *userRepo) List(ctx context.Context, opts biz.UserListOptions) ([]*biz.User, int64, error) {
	if r.logger.Enabled(ctx, slog.LevelDebug) {
		r.logger.DebugContext(
			ctx,
			"list users: request details",
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
		FilterColumnMap:     userFilterColumns,
		Preloads:            []string{"Role"},
		OrderBy:             orderBy,
		AllowedOrderColumns: userOrderColumns,
	}

	var pos []userPO
	var total int64

	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpList, "list users", func(dbCtx context.Context) error {
		var listErr error
		total, listErr = db.DBListAndCount(dbCtx, r.data.gormdb, &userPO{}, &pos, qp)
		return listErr
	}, slog.Int("offset", opts.Offset), slog.Int("page_size", opts.PageSize), slog.Int("filters", len(opts.Filters))); err != nil {
		return nil, 0, err
	}

	res := make([]*biz.User, 0, len(pos))
	for i := range pos {
		res = append(res, toBizUser(&pos[i]))
	}
	return res, total, nil
}

// invalidateTokenVersionCache deletes the cached token version so the next read falls back
// to the authoritative database value.
func (r *userRepo) invalidateTokenVersionCache(ctx context.Context, userID uint64) {
	if r.cache == nil {
		return
	}
	if err := r.cache.DeleteTokenVersion(ctx, userID); err != nil {
		r.logger.WarnContext(ctx, "failed to invalidate user token version cache", slog.Uint64("user_id", userID), slog.Any("error", err))
	}
}

func (r *userRepo) setTokenVersionCache(ctx context.Context, userID uint64, version uint64) error {
	if r.cache == nil {
		return nil
	}
	ttl := time.Duration(r.ttlSeconds) * time.Second
	err := r.cache.SetTokenVersion(ctx, userID, version, ttl)
	if err != nil {
		r.logger.WarnContext(ctx, "failed to update user token version cache", slog.Uint64("user_id", userID), slog.Uint64("version", version), slog.Any("error", err))
		// The database commit already succeeded and is authoritative. Drop the possibly stale cache
		// entry so the next request reads the database instead of serving an outdated version
		// until the TTL expires (which would keep revoked tokens valid).
		r.invalidateTokenVersionCache(ctx, userID)
	}
	return err
}

// ListIDsByRole returns all user IDs under a role so that sessions can be revoked in bulk after a role permission change.
func (r *userRepo) ListIDsByRole(ctx context.Context, roleID uint64) ([]uint64, error) {
	if roleID == 0 {
		return nil, nil
	}
	var ids []uint64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "list user IDs by role", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).
			Model(&userPO{}).
			Where("role_id = ?", roleID).
			Pluck("id", &ids).Error
	}, slog.Uint64("role_id", roleID)); err != nil {
		return nil, err
	}
	return ids, nil
}

// ==================== Token version and session revocation ====================

func (r *userRepo) IncrementTokenVersion(ctx context.Context, userID uint64) error {
	var version uint64
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "increment user token version", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Transaction(func(tx *gorm.DB) error {
			res := tx.Model(&userPO{}).
				Where("id = ?", userID).
				Update("token_version", gorm.Expr("token_version + 1"))
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return errors.New("user not found, cannot increment token version")
			}

			var po userPO
			if err := tx.Select("id", "token_version").Where("id = ?", userID).Take(&po).Error; err != nil {
				return err
			}
			version = po.TokenVersion

			// Write pending outbox entry in the same transaction
			outbox := TokenRevocationOutboxPO{
				UserID:  userID,
				Version: version,
				Status:  "pending",
			}
			return tx.Create(&outbox).Error
		})
	}, slog.Uint64("user_id", userID)); err != nil {
		return err
	}

	if r.cache != nil {
		if cacheErr := r.setTokenVersionCache(ctx, userID, version); cacheErr != nil {
			return cacheErr
		}
		// Successfully updated cache: mark outbox entry as synced
		_ = r.data.gormdb.WithContext(ctx).Model(&TokenRevocationOutboxPO{}).
			Where("user_id = ? AND version = ?", userID, version).
			Update("status", "synced").Error
	}
	return nil
}

func (r *userRepo) IncrementTokenVersionBatch(ctx context.Context, userIDs []uint64) error {
	if len(userIDs) == 0 {
		return nil
	}

	sortedIDs := slices.Clone(userIDs)
	slices.Sort(sortedIDs)
	sortedIDs = slices.Compact(sortedIDs)
	if len(sortedIDs) == 0 {
		return nil
	}

	versions := make(map[uint64]uint64, len(sortedIDs))
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpWrite, "batch increment user token versions", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&userPO{}).
				Where("id IN ?", sortedIDs).
				Update("token_version", gorm.Expr("token_version + 1")).Error; err != nil {
				return err
			}

			var pos []userPO
			if err := tx.Select("id", "token_version").Where("id IN ?", sortedIDs).Find(&pos).Error; err != nil {
				return err
			}
			var outboxes []TokenRevocationOutboxPO
			for _, p := range pos {
				versions[p.ID] = p.TokenVersion
				outboxes = append(outboxes, TokenRevocationOutboxPO{
					UserID:  p.ID,
					Version: p.TokenVersion,
					Status:  "pending",
				})
			}
			if len(outboxes) > 0 {
				if err := tx.Create(&outboxes).Error; err != nil {
					return err
				}
			}
			return nil
		})
	}, slog.Int("user_count", len(sortedIDs))); err != nil {
		return err
	}

	if r.cache != nil {
		var firstErr error
		var syncedIDs []uint64
		for _, id := range sortedIDs {
			version, ok := versions[id]
			if !ok {
				continue
			}
			if err := r.setTokenVersionCache(ctx, id, version); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				syncedIDs = append(syncedIDs, id)
			}
		}
		if len(syncedIDs) > 0 {
			_ = r.data.gormdb.WithContext(ctx).Model(&TokenRevocationOutboxPO{}).
				Where("user_id IN ? AND status = 'pending'", syncedIDs).
				Update("status", "synced").Error
		}
		return firstErr
	}
	return nil
}

func (r *userRepo) GetTokenVersion(ctx context.Context, userID uint64) (uint64, error) {
	if userID == 0 {
		return 0, errors.New("get token version: user ID must not be 0")
	}

	if r.cache != nil {
		val, err := r.cache.GetTokenVersion(ctx, userID)
		if err == nil {
			return val, nil
		}
		if !errors.Is(err, ErrCacheMiss) {
			return 0, err
		}
	}

	var po userPO
	if err := db.RunDBOp(ctx, r.logger, &r.data.dbTimeout, &r.data.dbSlow, db.OpRead, "get user token version", func(dbCtx context.Context) error {
		return r.data.gormdb.WithContext(dbCtx).Select("id", "token_version").Where("id = ?", userID).Take(&po).Error
	}, slog.Uint64("user_id", userID)); err != nil {
		return 0, err
	}

	if r.cache != nil {
		if err := r.setTokenVersionCache(ctx, userID, po.TokenVersion); err != nil {
			r.logger.WarnContext(ctx, "failed to write back user token version cache", slog.Uint64("user_id", userID), slog.Any("error", err))
		} else {
			_ = r.data.gormdb.WithContext(ctx).Model(&TokenRevocationOutboxPO{}).
				Where("user_id = ? AND version <= ? AND status = 'pending'", userID, po.TokenVersion).
				Update("status", "synced").Error
		}
	}
	return po.TokenVersion, nil
}

func (r *userRepo) EnsureTokenVersionCache(ctx context.Context, userID uint64, version uint64) error {
	if r.cache == nil {
		return nil
	}
	return r.setTokenVersionCache(ctx, userID, version)
}

func (r *userRepo) RotateRefreshTokenFamily(ctx context.Context, familyID, oldJTI, newJTI string, userID uint64, ttl time.Duration) (biz.RotateFamilyResult, error) {
	if r.cache == nil {
		return biz.RotateFamilyFailed, errors.New("rotate refresh token family: cache is not initialized")
	}

	return r.cache.RotateRefreshTokenFamily(ctx, familyID, oldJTI, newJTI, userID, ttl)
}

func (r *userRepo) ConsumeRefreshToken(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	if r.cache == nil {
		return false, errors.New("revoke jti: cache is not initialized")
	}
	ok, err := r.cache.ConsumeRefreshToken(ctx, jti, ttl)
	if err != nil {
		r.logger.WarnContext(ctx, "failed to write refresh token revocation state", slog.String("jti", jti), slog.Any("error", err))
	}
	return ok, err
}
