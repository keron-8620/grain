// Package db provides common methods for database CRUD operations,
// including transaction handling, association updates, and standard querying.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

func wrapCrudError(ctx context.Context, err error, msg string) error {
	if err == nil {
		return nil
	}
	mapped := MapError(err)
	if hasDBOpTrace(ctx) {
		return mapped
	}
	return errors.WrapIf(mapped, msg)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && time.Now().After(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// handleRecoveredPanic handles transaction rollback, stack extraction, and logging for panics.
// When autoRollback is true, it rolls back the active transaction if not already handled.
func handleRecoveredPanic(ctx context.Context, db *gorm.DB, r any, logMsg, errDetails string, autoRollback bool) error {
	if r == nil {
		return nil
	}

	if autoRollback && db != nil && db.Statement != nil && db.Statement.ConnPool != nil {
		if committer, ok := db.Statement.ConnPool.(gorm.TxCommitter); ok && committer != nil {
			if rollbackErr := db.WithContext(ctx).Rollback().Error; rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) && !errors.Is(rollbackErr, ErrInvalidTransaction) && !errors.Is(rollbackErr, gorm.ErrInvalidTransaction) && db.Logger != nil {
				db.Logger.Error(ctx, "failed to rollback transaction: panic=%v, rollback_err=%v", r, rollbackErr)
			}
		}
	}

	stackInfo := string(debug.Stack())
	if db != nil && db.Logger != nil {
		if db.Statement != nil && db.Statement.SQL.Len() > 0 {
			db.Logger.Error(ctx, "%s: panic=%v, sql=%s, vars=%v\n%s", logMsg, r, db.Statement.SQL.String(), db.Statement.Vars, stackInfo)
		} else {
			db.Logger.Error(ctx, "%s: panic=%v\n%s", logMsg, r, stackInfo)
		}
	}

	return errors.NewWithDetails(errDetails, "panic", r, "stack", stackInfo)
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
	recErr := handleRecoveredPanic(ctx, db, r, "database operation panicked", "recovered database panic", true)
	if err != nil {
		*err = recErr
	}
}

// DBCreate creates a database record
// ctx: context
// db: GORM database instance
// model: target model
// value: data to create
// Returns possible error from operation
func DBCreate(ctx context.Context, db *gorm.DB, model, value any) error {
	if db == nil {
		return errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}

	if err := db.WithContext(ctx).Model(model).Create(value).Error; err != nil {
		return wrapCrudError(ctx, err, "failed to create database record")
	}
	return nil
}

// withTransaction handles transaction commit, rollback, and panic recovery uniformly.
// It supports nested transactions and savepoints via GORM's native Transaction mechanism.
func withTransaction(ctx context.Context, db *gorm.DB, fn func(tx *gorm.DB) error) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if db == nil {
		return errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("transaction function is nil")
	}

	var currentTx *gorm.DB
	defer func() {
		if recovered := recover(); recovered != nil {
			targetDB := currentTx
			if targetDB == nil {
				targetDB = db
			}
			// GORM's native Transaction already performs rollback or rollback-to-savepoint
			// before re-panicking. Pass autoRollback=false so we do not issue a duplicate
			// rollback or inadvertently destroy an outer transaction in nested savepoint mode.
			err = handleRecoveredPanic(ctx, targetDB, recovered, "database transaction panicked", "database transaction panicked", false)
		}
	}()

	txErr := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		currentTx = tx
		return fn(tx)
	})
	if txErr != nil {
		return MapError(txErr)
	}
	return nil
}

// WithTransaction is kept for package-internal and backward compatibility.
func WithTransaction(ctx context.Context, db *gorm.DB, fn func(tx *gorm.DB) error) error {
	return withTransaction(ctx, db, fn)
}

// DBCreateTX creates a database record within an explicit transaction.
//
// Transaction Note: When SkipDefaultTransaction is false (the GORM default), single-record
// DBCreate already executes within an internal transaction. DBCreateTX is provided for cases
// where explicit transaction demarcations are desired or when SkipDefaultTransaction is true.
func DBCreateTX(ctx context.Context, db *gorm.DB, model, value any) error {
	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		if err := tx.Model(model).Create(value).Error; err != nil {
			return wrapCrudError(ctx, err, "failed to create database record")
		}
		return nil
	})
}

// DBCreateRelationTx creates a database record and appends associations within a transaction.
// Association keys in upmap are iterated in deterministic sorted order to prevent database deadlocks.
// Associations declared in upmap are omitted during primary record creation to prevent duplicate saves
// when value already contains populated association data.
func DBCreateRelationTx(ctx context.Context, db *gorm.DB, model, value any, upmap map[string]any) error {
	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		createDB := tx.Model(model)
		if len(upmap) == 0 {
			if err := createDB.Create(value).Error; err != nil {
				return wrapCrudError(ctx, err, "failed to create database record")
			}
			return nil
		}

		keys := make([]string, 0, len(upmap))
		for k := range upmap {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		if err := createDB.Omit(keys...).Create(value).Error; err != nil {
			return wrapCrudError(ctx, err, "failed to create database record")
		}

		for _, k := range keys {
			if err := tx.Model(value).Association(k).Append(upmap[k]); err != nil {
				return wrapCrudError(ctx, err, "failed to update association")
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
// Returns rows affected and possible error from operation
func DBUpdate(ctx context.Context, db *gorm.DB, m any, data map[string]any, conds ...any) (int64, error) {
	if db == nil {
		return 0, errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}

	// Return immediately if nothing to update
	if len(data) == 0 {
		return 0, nil
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return 0, errors.WithStack(ErrMissingWhereClause)
	}

	res := db.WithContext(ctx).Model(m).Where(conds[0], conds[1:]...).Updates(data)
	if res.Error != nil {
		return 0, wrapCrudError(ctx, res.Error, "failed to update database record")
	}
	return res.RowsAffected, nil
}

// DBUpdateTx updates database records within an explicit transaction.
func DBUpdateTx(ctx context.Context, db *gorm.DB, m any, data map[string]any, conds ...any) (rowsAffected int64, err error) {
	if db == nil {
		return 0, errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return 0, errors.WithStack(ErrMissingWhereClause)
	}

	// Return immediately if nothing to update
	if len(data) == 0 {
		return 0, nil
	}

	err = withTransaction(ctx, db, func(tx *gorm.DB) error {
		res := tx.Model(m).Where(conds[0], conds[1:]...).Updates(data)
		if res.Error != nil {
			return wrapCrudError(ctx, res.Error, "failed to update database record")
		}
		rowsAffected = res.RowsAffected
		return nil
	})
	return rowsAffected, err
}

// DBUpdateRelationTx updates main table data and replaces associations within a transaction.
// Association keys in upmap are iterated in deterministic sorted order to prevent database deadlocks.
//
// Important Scope & Usage Semantics:
//  1. Single-Record Scope: Because GORM association replacement operates on a loaded model instance,
//     this function queries and updates ONLY the first record matching conds (via First(m)).
//  2. Model Parameter (m): m must be a non-nil pointer to a model struct. It is populated in-place
//     with the queried record before applying updates and association replacements.
//  3. Primary Key Behavior: If m already has a non-zero primary key set, GORM's First(m) automatically
//     combines that primary key with conds. Pass a zero-initialized struct pointer (e.g. &User{}) when
//     locating the record purely by conds.
func DBUpdateRelationTx(ctx context.Context, db *gorm.DB, m any, data map[string]any, upmap map[string]any, conds ...any) error {
	if db == nil {
		return errors.New("database instance is nil")
	}
	if m == nil {
		return errors.New("model instance cannot be nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	// Check if query conditions are provided
	if len(conds) == 0 {
		return errors.WithStack(ErrMissingWhereClause)
	}

	return withTransaction(ctx, db, func(tx *gorm.DB) error {
		if err := tx.Where(conds[0], conds[1:]...).First(m).Error; err != nil {
			if errors.Is(err, ErrRecordNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
				return wrapCrudError(ctx, ErrRecordNotFound, "record not found")
			}
			return wrapCrudError(ctx, err, "failed to query record")
		}

		if len(data) > 0 {
			if err := tx.Model(m).Updates(data).Error; err != nil {
				return wrapCrudError(ctx, err, "failed to update database record")
			}
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
				return wrapCrudError(ctx, err, "failed to update association")
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
// Returns rows affected and possible error from operation.
func DBDelete(ctx context.Context, db *gorm.DB, model any, conds ...any) (int64, error) {
	if db == nil {
		return 0, errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return 0, errors.WithStack(ErrMissingWhereClause)
	}

	res := db.WithContext(ctx).Delete(model, conds...)
	if res.Error != nil {
		return 0, wrapCrudError(ctx, res.Error, "failed to delete database record")
	}
	return res.RowsAffected, nil
}

// DBDeleteTx deletes database records within an explicit transaction.
// ctx: context
// db: GORM database instance
// model: target model
// conds: query conditions
// Returns rows affected and possible error from operation.
func DBDeleteTx(ctx context.Context, db *gorm.DB, model any, conds ...any) (rowsAffected int64, err error) {
	if db == nil {
		return 0, errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}

	// Check if query conditions are provided
	if len(conds) == 0 {
		return 0, errors.WithStack(ErrMissingWhereClause)
	}

	err = withTransaction(ctx, db, func(tx *gorm.DB) error {
		res := tx.Delete(model, conds...)
		if res.Error != nil {
			return wrapCrudError(ctx, res.Error, "failed to delete database record")
		}
		rowsAffected = res.RowsAffected
		return nil
	})
	return rowsAffected, err
}

// DBFindOne queries a single database record with optional association preloads.
// It follows the package's standard (ctx, db, model, ...) parameter ordering convention.
func DBFindOne(ctx context.Context, db *gorm.DB, m any, preloads []string, conds ...any) error {
	if db == nil {
		return errors.New("database instance is nil")
	}
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
	return wrapCrudError(ctx, err, "failed to query database record")
}

// DBFind queries a single database record matching conds without association preloads.
// It follows the package's standard (ctx, db, model, ...) parameter ordering convention.
func DBFind(ctx context.Context, db *gorm.DB, m any, conds ...any) error {
	return DBFindOne(ctx, db, m, nil, conds...)
}

// DBList queries a list of database records, supporting pagination, ordering, conditions, and structured filters
// ctx: context
// db: GORM database instance
// model: target model
// value: destination object for query results
// query: query parameters
// Returns possible error from operation
func DBList(ctx context.Context, db *gorm.DB, model, value any, query QueryParams) error {
	if db == nil {
		return errors.New("database instance is nil")
	}
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
		return wrapCrudError(ctx, result.Error, "failed to query database record")
	}

	return nil
}

// DBListAndCount validates QueryParams and builds the filtered base query once,
// executing both a COUNT query and (when total > 0) a paginated list query.
func DBListAndCount(ctx context.Context, db *gorm.DB, model, value any, query QueryParams) (int64, error) {
	if db == nil {
		return 0, errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}

	// Validate non-filter query modifiers upfront so malformed options fail before any SQL round-trip.
	normalizedOrder, err := validateAndNormalizeModifiers(query)
	if err != nil {
		return 0, err
	}

	filterDB, err := buildFilterQuery(db.WithContext(ctx), model, query)
	if err != nil {
		return 0, err
	}

	var total int64
	if err := filterDB.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return 0, wrapCrudError(ctx, err, "failed to count database records")
	}

	if total == 0 {
		resetSliceValue(value)
		return 0, nil
	}

	listDB := applyValidatedModifiers(filterDB, query, normalizedOrder)
	if err := listDB.Find(value).Error; err != nil {
		return 0, wrapCrudError(ctx, err, "failed to query database record")
	}

	return total, nil
}

func resetSliceValue(value any) {
	if value == nil {
		return
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Pointer && !rv.IsNil() {
		elem := rv.Elem()
		if elem.Kind() == reflect.Slice && elem.Len() > 0 {
			elem.SetLen(0)
		}
	}
}

func buildFilterQuery(db *gorm.DB, model any, query QueryParams) (*gorm.DB, error) {
	if db == nil {
		return nil, errors.New("database instance is nil")
	}
	mdb := db.Model(model)
	if len(query.Filters) > 0 {
		var err error
		mdb, err = applyListFiltersWithOptions(mdb, query.Filters, query.AllowedFilterColumns, query.FilterColumnMap)
		if err != nil {
			return nil, err
		}
	}
	return mdb, nil
}

func validateAndNormalizeModifiers(query QueryParams) ([]string, error) {
	if len(query.Columns) > 0 {
		for _, col := range query.Columns {
			if err := validateSQLIdentifier(col); err != nil {
				return nil, fmt.Errorf("%w: invalid select column %q: %v", ErrInvalidListOption, col, err)
			}
		}
	} else if len(query.Omit) > 0 {
		for _, col := range query.Omit {
			if err := validateSQLIdentifier(col); err != nil {
				return nil, fmt.Errorf("%w: invalid omit column %q: %v", ErrInvalidListOption, col, err)
			}
		}
	}

	var normalizedOrder []string
	if len(query.OrderBy) > 0 {
		normalizedOrder = make([]string, 0, len(query.OrderBy))
		for _, clause := range query.OrderBy {
			trimmed := strings.TrimSpace(clause)
			if trimmed == "" {
				continue
			}
			sanitized, err := SanitizeOrderBy(trimmed, query.AllowedOrderColumns)
			if err != nil {
				return nil, err
			}
			if sanitized != "" {
				normalizedOrder = append(normalizedOrder, sanitized)
			}
		}
	}
	return normalizedOrder, nil
}

func applyValidatedModifiers(mdb *gorm.DB, query QueryParams, normalizedOrder []string) *gorm.DB {
	if len(query.Columns) > 0 {
		mdb = mdb.Select(query.Columns)
	} else if len(query.Omit) > 0 {
		mdb = mdb.Omit(query.Omit...)
	}

	if len(normalizedOrder) > 0 {
		mdb = mdb.Order(strings.Join(normalizedOrder, ", "))
	}

	if query.Limit > 0 {
		mdb = mdb.Limit(query.Limit)
	}
	if query.Offset > 0 {
		mdb = mdb.Offset(query.Offset)
	}

	for _, preload := range query.Preloads {
		mdb = mdb.Preload(preload)
	}

	return mdb
}

// BuildQuery constructs a GORM query builder from QueryParams, applying:
// 1. Model
// 2. Structured Filters (with optional AllowedFilterColumns / FilterColumnMap, safe field validation, and LIKE escaping)
// 3. Columns / Omit (with validateSQLIdentifier validation)
// 4. OrderBy (with SanitizeOrderBy SQL identifier validation and -column normalization)
// 5. Pagination (Limit / Offset)
// 6. Preload associations
func BuildQuery(db *gorm.DB, model any, query QueryParams) (*gorm.DB, error) {
	mdb, err := buildFilterQuery(db, model, query)
	if err != nil {
		return nil, err
	}

	normalizedOrder, err := validateAndNormalizeModifiers(query)
	if err != nil {
		return nil, err
	}

	return applyValidatedModifiers(mdb, query, normalizedOrder), nil
}

// DBCount counts database records matching the Filters in QueryParams.
// Pagination, ordering, columns, omit, and preloads are automatically omitted for counting.
func DBCount(ctx context.Context, db *gorm.DB, model any, query QueryParams) (int64, error) {
	if db == nil {
		return 0, errors.New("database instance is nil")
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}

	mdb, err := buildFilterQuery(db.WithContext(ctx), model, query)
	if err != nil {
		return 0, err
	}

	var count int64 = 0
	if err := mdb.Count(&count).Error; err != nil {
		return 0, wrapCrudError(ctx, err, "failed to count database records")
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
	var allowed map[string]struct{}
	if len(allowedColumns) > 0 {
		allowed = NewColumnSet(allowedColumns...)
	}

	for _, clause := range clauses {
		trimmed := strings.TrimSpace(clause)
		if trimmed == "" {
			continue
		}
		if _, err := SanitizeOrderBy(trimmed, allowed); err != nil {
			return err
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
	Preloads             []string            // List of associations to preload
	Filters              []ListFilter        // Structured AIP list filters
	AllowedFilterColumns map[string]struct{} // Optional allowlist of filterable columns (created via NewColumnSet); enforced by BuildQuery when non-nil
	FilterColumnMap      map[string]string   // Optional field-to-column mapping allowlist; when non-nil, only keys in the map are allowed and mapped to their column names
	OrderBy              []string            // List of ordering fields
	AllowedOrderColumns  map[string]struct{} // Optional allowlist of sortable columns (created via NewColumnSet); enforced by BuildQuery when non-nil
	Limit                int                 // Page size
	Offset               int                 // Page offset
	Omit                 []string            // List of fields to omit
	Columns              []string            // List of fields to select
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
		slog.String("filters", strings.Join(filterAttrs, "; ")),
		slog.String("order_by", strings.Join(q.OrderBy, ",")),
		slog.Int("limit", q.Limit),
		slog.Int("offset", q.Offset),
		slog.String("omit", strings.Join(q.Omit, ",")),
		slog.String("columns", strings.Join(q.Columns, ",")),
	)
}
