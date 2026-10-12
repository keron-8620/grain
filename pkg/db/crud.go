// Package db provides common methods for database CRUD operations,
// including transaction handling, association updates, and standard querying.
package db

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && time.Now().After(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// DBPanic is a generic GORM panic recovery function (must be used in a deferred closure, e.g. defer func() { err = DBPanic(ctx, db, err) }()).
// Features: 1. Catches panic and converts to standard error 2. Rolls back transaction (transaction context only) 3. Logs detailed info (stack trace, SQL context).
// Parameters:
//   - ctx: context used for logging and GORM operations
//   - db: GORM database instance (pass tx instance for transactions, standard db instance otherwise)
//   - bizErr: original error to return if no panic occurred
//
// Return value:
//   - error: wrapped error with panic details on panic; original error on normal flow
func DBPanic(ctx context.Context, db *gorm.DB, bizErr error) error {
	// 1. Recover from panic
	r := recover()
	if r == nil {
		// No panic, return original business error
		return bizErr
	}

	// 2. Safely rollback transaction (defensive check to prevent nil pointer panic)
	if db != nil && db.Statement != nil && db.Statement.ConnPool != nil {
		// Log on rollback failure without affecting main flow
		if rollbackErr := db.Rollback().Error; rollbackErr != nil && db.Logger != nil {
			db.Logger.Error(ctx, "failed to rollback transaction", "panic", r, "rollback_err", rollbackErr)
		}
	}

	// 3. Build error message
	stackInfo := string(debug.Stack())
	errMsg := "database operation panicked"

	// 4. Log full details (SQL, parameters, stack trace, panic content)
	if db != nil && db.Logger != nil {
		logFields := []any{
			"panic", r,
			"stack", stackInfo,
		}
		// Safely append SQL context
		if db.Statement != nil {
			logFields = append(logFields, "sql", db.Statement.SQL.String())
			logFields = append(logFields, "vars", db.Statement.Vars)
		}
		db.Logger.Error(ctx, errMsg, logFields...)
	}

	return errors.NewWithDetails("recovered database panic", "panic", r)
}

// DBRecover is a deferred panic recovery helper.
// It catches panics, logs SQL context and stack trace, safely rolls back the transaction,
// and assigns the recovered error to *err.
// Must be invoked as: defer DBRecover(ctx, tx, &err)
func DBRecover(ctx context.Context, db *gorm.DB, err *error) {
	r := recover()
	if r == nil {
		return
	}

	if db != nil && db.Statement != nil && db.Statement.ConnPool != nil {
		if rollbackErr := db.Rollback().Error; rollbackErr != nil && db.Logger != nil {
			db.Logger.Error(ctx, "failed to rollback transaction", "panic", r, "rollback_err", rollbackErr)
		}
	}

	stackInfo := string(debug.Stack())
	if db != nil && db.Logger != nil {
		logFields := []any{
			"panic", r,
			"stack", stackInfo,
		}
		if db.Statement != nil {
			logFields = append(logFields, "sql", db.Statement.SQL.String())
			logFields = append(logFields, "vars", db.Statement.Vars)
		}
		db.Logger.Error(ctx, "database operation panicked", logFields...)
	}

	if err != nil {
		*err = errors.NewWithDetails("recovered database panic", "panic", r)
	}
}

// DBCreate creates a database record
// ctx: context
// db: GORM database instance
// model: target model
// value: data to create
// Returns possible error from operation
func DBCreate(ctx context.Context, db *gorm.DB, model, value any) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	if err := db.WithContext(ctx).Model(model).Create(value).Error; err != nil {
		return errors.WrapIf(err, "failed to create database record")
	}
	return nil
}

// WithTransaction handles transaction commit, rollback, and panic recovery uniformly.
// It supports nested transactions and savepoints via GORM's native Transaction mechanism.
func WithTransaction(ctx context.Context, db *gorm.DB, fn func(tx *gorm.DB) error) (err error) {
	if ctx == nil {
		return errors.New("context instance is nil")
	}
	if db == nil {
		return errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.NewWithDetails(
				"database transaction panicked",
				"panic", recovered,
				"stack", string(debug.Stack()),
			)
		}
	}()

	return db.WithContext(ctx).Transaction(fn)
}

// withTransaction is kept for package-internal and backward compatibility.
func withTransaction(ctx context.Context, db *gorm.DB, fn func(tx *gorm.DB) error) error {
	return WithTransaction(ctx, db, fn)
}

// DBCreateTX creates a database record within an explicit transaction.
//
// Transaction Note: When SkipDefaultTransaction is false (the GORM default), single-record
// DBCreate already executes within an internal transaction. DBCreateTX is provided for cases
// where explicit transaction demarcations are desired or when SkipDefaultTransaction is true.
func DBCreateTX(ctx context.Context, db *gorm.DB, model, value any) error {
	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		if err := tx.Model(model).Create(value).Error; err != nil {
			return errors.WrapIf(err, "failed to create database record")
		}
		return nil
	})
}

// DBCreateRelationTx creates a database record and appends associations within a transaction.
// Association keys in upmap are iterated in deterministic sorted order to prevent database deadlocks.
func DBCreateRelationTx(ctx context.Context, db *gorm.DB, model, value any, upmap map[string]any) error {
	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		if err := tx.Model(model).Create(value).Error; err != nil {
			return errors.WrapIf(err, "failed to create database record")
		}
		if len(upmap) == 0 {
			return nil
		}
		keys := make([]string, 0, len(upmap))
		for k := range upmap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := tx.Model(value).Association(k).Append(upmap[k]); err != nil {
				return errors.WrapIf(err, "failed to update association")
			}
		}
		return nil
	})
}

// DBUpdate updates database records, supporting association updates
// ctx: context
// db: GORM database instance
// m: target model
// data: main table update data (can be nil or empty map)
// conds: query conditions
// Returns possible error from operation
func DBUpdate(ctx context.Context, db *gorm.DB, m any, data map[string]any, conds ...any) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	// Return immediately if nothing to update
	if len(data) == 0 {
		return nil
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return errors.WithStack(gorm.ErrMissingWhereClause)
	}

	if err := db.WithContext(ctx).Model(m).Where(conds[0], conds[1:]...).Updates(data).Error; err != nil {
		return errors.WrapIf(err, "failed to update database record")
	}
	return nil
}

// DBUpdateTx updates database records within an explicit transaction.
func DBUpdateTx(ctx context.Context, db *gorm.DB, m any, data map[string]any, conds ...any) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	// Return immediately if nothing to update
	if len(data) == 0 {
		return nil
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return errors.WithStack(gorm.ErrMissingWhereClause)
	}

	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		if err := tx.Model(m).Where(conds[0], conds[1:]...).Updates(data).Error; err != nil {
			return errors.WrapIf(err, "failed to update database record")
		}
		return nil
	})
}

// DBUpdateRelationTx updates main table data and replaces associations within a transaction.
// Association keys in upmap are iterated in deterministic sorted order to prevent database deadlocks.
func DBUpdateRelationTx(ctx context.Context, db *gorm.DB, m any, data map[string]any, upmap map[string]any, conds ...any) error {
	// Check if query conditions are provided
	if len(conds) == 0 {
		return errors.WithStack(gorm.ErrMissingWhereClause)
	}

	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		if len(data) > 0 {
			if err := tx.Model(m).Where(conds[0], conds[1:]...).Updates(data).Error; err != nil {
				return errors.WrapIf(err, "failed to update database record")
			}
		}

		if err := tx.Where(conds[0], conds[1:]...).First(m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errors.WrapIf(err, "record not found")
			}
			return errors.WrapIf(err, "failed to query record")
		}

		if len(upmap) == 0 {
			return nil
		}

		keys := make([]string, 0, len(upmap))
		for k := range upmap {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			if err := tx.Model(m).Association(k).Replace(upmap[k]); err != nil {
				return errors.WrapIf(err, "failed to update association")
			}
		}
		return nil
	})
}

// DBDelete deletes database records matching the provided conditions.
//
// Best Practice: When SkipDefaultTransaction is false (the GORM default), GORM already executes
// single-table deletes within an internal transaction. Use DBDelete for standard single-table
// operations. Use WithTransaction when multiple database operations must succeed or fail together.
func DBDelete(ctx context.Context, db *gorm.DB, model any, conds ...any) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return gorm.ErrMissingWhereClause
	}

	if err := db.WithContext(ctx).Delete(model, conds...).Error; err != nil {
		return errors.WrapIf(err, "failed to delete database record")
	}
	return nil
}

// DBDeleteTx deletes database records within an explicit transaction.
// ctx: context
// db: GORM database instance
// model: target model
// conds: query conditions
// Returns possible error from operation
func DBDeleteTx(ctx context.Context, db *gorm.DB, model any, conds ...any) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return gorm.ErrMissingWhereClause
	}

	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		if err := tx.Delete(model, conds...).Error; err != nil {
			return errors.WrapIf(err, "failed to delete database record")
		}
		return nil
	})
}

// DBGet queries a single database record, supporting preloading associations
// ctx: context
// db: GORM database instance
// preloads: list of associations to preload
// m: destination object for query result
// conds: query conditions
// Returns possible error from operation
func DBGet(ctx context.Context, db *gorm.DB, preloads []string, m any, conds ...any) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	dbCtx := db.WithContext(ctx)

	// Preload associations
	for _, preload := range preloads {
		dbCtx = dbCtx.Preload(preload)
	}

	// Query the first matching record
	err := dbCtx.First(m, conds...).Error
	return errors.WrapIf(err, "failed to query database record")
}

// DBList queries a list of database records, supporting pagination, ordering, conditions, and structured filters
// ctx: context
// db: GORM database instance
// model: target model
// value: destination object for query results
// query: query parameters
// Returns possible error from operation
func DBList(ctx context.Context, db *gorm.DB, model, value any, query QueryParams) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	mdb, err := BuildQuery(db.WithContext(ctx), model, query)
	if err != nil {
		return err
	}

	// Execute query
	result := mdb.Find(value)
	if result.Error != nil {
		return errors.WrapIf(result.Error, "failed to query database record")
	}

	return nil
}

// BuildQuery constructs a GORM query builder from QueryParams, applying:
// 1. Model
// 2. Legacy Query map (in deterministic sorted order)
// 3. Structured Filters (via ApplyListFilters with safe field validation and LIKE escaping)
// 4. Columns / Omit
// 5. OrderBy (with ValidateOrderBy SQL identifier validation)
// 6. Pagination (Limit / Offset)
// 7. Preload associations
func BuildQuery(db *gorm.DB, model any, query QueryParams) (*gorm.DB, error) {
	if db == nil {
		return nil, errors.New("database instance is nil")
	}
	mdb := db.Model(model)

	// 1. Add legacy query conditions in deterministic sorted order
	if len(query.Query) > 0 {
		keys := make([]string, 0, len(query.Query))
		for k := range query.Query {
			if k == "" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			mdb = mdb.Where(k, query.Query[k])
		}
	}

	// 2. Add structured AIP filters
	if len(query.Filters) > 0 {
		var err error
		mdb, err = ApplyListFilters(mdb, query.Filters)
		if err != nil {
			return nil, err
		}
	}

	// 3. Specify selected and omitted fields (Columns takes precedence if both are specified)
	if len(query.Columns) > 0 {
		mdb = mdb.Select(query.Columns)
	} else if len(query.Omit) > 0 {
		mdb = mdb.Omit(query.Omit...)
	}

	// 4. Validate and apply ordering conditions
	if len(query.OrderBy) > 0 {
		if err := ValidateOrderBy(query.OrderBy); err != nil {
			return nil, err
		}
		mdb = mdb.Order(strings.Join(query.OrderBy, ","))
	}

	// 5. Add pagination conditions
	if query.Limit > 0 {
		mdb = mdb.Limit(query.Limit)
	}
	if query.Offset > 0 {
		mdb = mdb.Offset(query.Offset)
	}

	// 6. Preload associations
	for _, preload := range query.Preloads {
		mdb = mdb.Preload(preload)
	}

	return mdb, nil
}

// DBCount counts database records matching the provided query map.
func DBCount(ctx context.Context, db *gorm.DB, model any, query map[string]any) (int64, error) {
	return DBCountWithParams(ctx, db, model, QueryParams{Query: query})
}

// DBCountWithParams counts records using the full QueryParams structure (supporting both Query and Filters).
// Pagination, ordering, and preloads are automatically omitted for counting.
func DBCountWithParams(ctx context.Context, db *gorm.DB, model any, query QueryParams) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}

	countParams := QueryParams{
		Query:   query.Query,
		Filters: query.Filters,
	}
	mdb, err := BuildQuery(db.WithContext(ctx), model, countParams)
	if err != nil {
		return 0, err
	}

	var count int64 = 0
	if err := mdb.Count(&count).Error; err != nil {
		return 0, errors.WrapIf(err, "failed to count database records")
	}

	return count, nil
}

// ValidateOrderBy validates each ordering clause in orderBy against SQL injection.
// Each element can be a single expression (e.g. "created_at DESC") or comma-separated expressions.
// Allowed syntax for each expression:
//
//	<identifier> [ASC|DESC]
//
// where <identifier> is a valid SQL column identifier (optional table.column format)
// consisting only of letters, numbers, and underscores (max 64 characters per segment,
// starting with a letter or underscore).
// If allowedColumns is non-empty, the column identifier must also match one of the allowed columns (case-insensitive).
func ValidateOrderBy(clauses []string, allowedColumns ...string) error {
	if len(clauses) == 0 {
		return nil
	}
	var allowMap map[string]struct{}
	if len(allowedColumns) > 0 {
		allowMap = make(map[string]struct{}, len(allowedColumns))
		for _, col := range allowedColumns {
			allowMap[strings.ToLower(col)] = struct{}{}
		}
	}

	for _, clause := range clauses {
		trimmed := strings.TrimSpace(clause)
		if trimmed == "" {
			continue
		}
		parts := strings.Split(trimmed, ",")
		for _, part := range parts {
			p := strings.TrimSpace(part)
			if p == "" {
				return fmt.Errorf("%w: empty order_by clause", ErrInvalidListOption)
			}
			fields := strings.Fields(p)
			if len(fields) > 2 {
				return fmt.Errorf("%w: invalid order_by clause %q", ErrInvalidListOption, p)
			}
			col := fields[0]
			if err := validateSQLIdentifier(col); err != nil {
				return fmt.Errorf("%w: invalid order_by column %q: %v", ErrInvalidListOption, col, err)
			}
			if allowMap != nil {
				lookup := strings.ToLower(col)
				if idx := strings.LastIndex(lookup, "."); idx != -1 {
					lookup = lookup[idx+1:]
				}
				if _, ok := allowMap[lookup]; !ok {
					return fmt.Errorf("%w: column %q is not sortable", ErrInvalidListOption, col)
				}
			}
			if len(fields) == 2 {
				dir := strings.ToUpper(fields[1])
				if dir != "ASC" && dir != "DESC" {
					return fmt.Errorf("%w: invalid order direction %q (must be ASC or DESC)", ErrInvalidListOption, fields[1])
				}
			}
		}
	}
	return nil
}

func validateSQLIdentifier(ident string) error {
	if ident == "" {
		return errors.New("identifier cannot be empty")
	}
	segments := strings.Split(ident, ".")
	if len(segments) > 2 {
		return errors.New("identifier cannot contain more than one dot")
	}
	for _, seg := range segments {
		if len(seg) == 0 || len(seg) > 64 {
			return errors.New("identifier segment length must be between 1 and 64")
		}
		for i, r := range seg {
			if i == 0 {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
					return errors.New("identifier segment must start with a letter or underscore")
				}
			} else {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
					return fmt.Errorf("identifier contains invalid character %q", r)
				}
			}
		}
	}
	return nil
}

// QueryParams represents query parameters for configuring list queries
type QueryParams struct {
	Preloads []string       // List of associations to preload
	Query    map[string]any // Legacy/raw query condition mapping
	Filters  []ListFilter   // Structured AIP list filters
	OrderBy  []string       // List of ordering fields
	Limit    int            // Page size
	Offset   int            // Page offset
	Omit     []string       // List of fields to omit
	Columns  []string       // List of fields to select
}

func (q *QueryParams) LogValue() slog.Value {
	if q == nil {
		return slog.StringValue("<nil>")
	}

	filterAttrs := make([]string, 0, len(q.Filters))
	for _, f := range q.Filters {
		filterAttrs = append(filterAttrs, fmt.Sprintf("%s %s %v", f.Field, f.Op, f.Value))
	}

	return slog.GroupValue(
		slog.String("preloads", strings.Join(q.Preloads, ",")),
		slog.Any("query", q.Query),
		slog.String("filters", strings.Join(filterAttrs, "; ")),
		slog.String("order_by", strings.Join(q.OrderBy, ",")),
		slog.Int("limit", q.Limit),
		slog.Int("offset", q.Offset),
		slog.String("omit", strings.Join(q.Omit, ",")),
		slog.String("columns", strings.Join(q.Columns, ",")),
	)
}
