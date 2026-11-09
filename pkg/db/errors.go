package db

import (
	"context"
	"database/sql"
	"strings"
	"sync"

	"emperror.dev/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// SentinelError represents a database sentinel error that also matches its corresponding GORM/SQL error.
type SentinelError struct {
	msg     string
	gormErr error
}

func (e *SentinelError) Error() string {
	return e.msg
}

// Is reports whether e matches target, including matching the underlying GORM/SQL error.
func (e *SentinelError) Is(target error) bool {
	if target == nil {
		return false
	}
	if e == target {
		return true
	}
	if e.gormErr != nil && errors.Is(e.gormErr, target) {
		return true
	}
	return false
}

// newSentinelError creates a new SentinelError with a message and an optional underlying GORM error target.
func newSentinelError(msg string, gormErr error) *SentinelError {
	return &SentinelError{
		msg:     msg,
		gormErr: gormErr,
	}
}

// NewSentinelError creates an exported SentinelError with a custom message.
func NewSentinelError(msg string) *SentinelError {
	return newSentinelError(msg, nil)
}

// Common database sentinel errors re-mapped from GORM and standard database/sql errors into pkg/db.
var (
	// ErrRecordNotFound occurs when a query returns no matching record.
	ErrRecordNotFound = newSentinelError("record not found", gorm.ErrRecordNotFound)

	// ErrInvalidTransaction occurs when attempting an invalid transaction operation (e.g. Commit/Rollback on a completed transaction).
	ErrInvalidTransaction = newSentinelError("invalid transaction", gorm.ErrInvalidTransaction)

	// ErrNotImplemented occurs when a database feature or driver method is not implemented.
	ErrNotImplemented = newSentinelError("not implemented", gorm.ErrNotImplemented)

	// ErrMissingWhereClause occurs when an update or delete query lacks required WHERE conditions.
	ErrMissingWhereClause = newSentinelError("WHERE conditions required", gorm.ErrMissingWhereClause)

	// ErrUnsupportedRelation occurs when an unsupported relationship is referenced in preload or association.
	ErrUnsupportedRelation = newSentinelError("unsupported relations", gorm.ErrUnsupportedRelation)

	// ErrPrimaryKeyRequired occurs when an operation requires a primary key value that was not provided.
	ErrPrimaryKeyRequired = newSentinelError("primary key required", gorm.ErrPrimaryKeyRequired)

	// ErrModelValueRequired occurs when a model value is required but was not provided.
	ErrModelValueRequired = newSentinelError("model value required", gorm.ErrModelValueRequired)

	// ErrModelAccessibleFieldsRequired occurs when accessible fields are required on the model.
	ErrModelAccessibleFieldsRequired = newSentinelError("model accessible fields required", gorm.ErrModelAccessibleFieldsRequired)

	// ErrSubQueryRequired occurs when a subquery is required.
	ErrSubQueryRequired = newSentinelError("sub query required", gorm.ErrSubQueryRequired)

	// ErrInvalidData occurs when data provided is unsupported or invalid.
	ErrInvalidData = newSentinelError("unsupported data", gorm.ErrInvalidData)

	// ErrUnsupportedDriver occurs when an unsupported database driver is specified.
	ErrUnsupportedDriver = newSentinelError("unsupported driver", gorm.ErrUnsupportedDriver)

	// ErrRegistered occurs when an entity is already registered.
	ErrRegistered = newSentinelError("registered", gorm.ErrRegistered)

	// ErrInvalidField occurs when an invalid field is referenced.
	ErrInvalidField = newSentinelError("invalid field", gorm.ErrInvalidField)

	// ErrEmptySlice occurs when an empty slice is provided to an operation that requires elements.
	ErrEmptySlice = newSentinelError("empty slice found", gorm.ErrEmptySlice)

	// ErrDryRunModeUnsupported occurs when dry run mode is unsupported.
	ErrDryRunModeUnsupported = newSentinelError("dry run mode unsupported", gorm.ErrDryRunModeUnsupported)

	// ErrInvalidDB occurs when the database instance is invalid or connection is closed.
	ErrInvalidDB = newSentinelError("invalid db", gorm.ErrInvalidDB)

	// ErrInvalidValue occurs when a value is invalid (e.g. should be a pointer to struct or slice).
	ErrInvalidValue = newSentinelError("invalid value, should be pointer to struct or slice", gorm.ErrInvalidValue)

	// ErrInvalidValueOfLength occurs when association values do not match length.
	ErrInvalidValueOfLength = newSentinelError("invalid association values, length doesn't match", gorm.ErrInvalidValueOfLength)

	// ErrPreloadNotAllowed occurs when preload is not allowed (e.g. when count is used).
	ErrPreloadNotAllowed = newSentinelError("preload is not allowed when count is used", gorm.ErrPreloadNotAllowed)

	// ErrDuplicatedKey occurs when a unique constraint or primary key violation happens.
	ErrDuplicatedKey = newSentinelError("duplicated key not allowed", gorm.ErrDuplicatedKey)

	// ErrForeignKeyViolated occurs when a foreign key constraint is violated.
	ErrForeignKeyViolated = newSentinelError("violates foreign key constraint", gorm.ErrForeignKeyViolated)

	// ErrCheckConstraintViolated occurs when a check constraint is violated.
	ErrCheckConstraintViolated = newSentinelError("violates check constraint", gorm.ErrCheckConstraintViolated)

	// ErrUnsupportedDataType occurs when an unsupported data type is encountered in schema definition.
	ErrUnsupportedDataType = newSentinelError("unsupported data type", schema.ErrUnsupportedDataType)
)

type gormErrorMapping struct {
	target   error
	sentinel *SentinelError
}

var (
	customErrMu         sync.RWMutex
	customErrorMappings []gormErrorMapping

	builtinMappings = []gormErrorMapping{
		{target: gorm.ErrRecordNotFound, sentinel: ErrRecordNotFound},
		{target: sql.ErrNoRows, sentinel: ErrRecordNotFound},
		{target: gorm.ErrDuplicatedKey, sentinel: ErrDuplicatedKey},
		{target: gorm.ErrForeignKeyViolated, sentinel: ErrForeignKeyViolated},
		{target: gorm.ErrCheckConstraintViolated, sentinel: ErrCheckConstraintViolated},
		{target: gorm.ErrMissingWhereClause, sentinel: ErrMissingWhereClause},
		{target: gorm.ErrPrimaryKeyRequired, sentinel: ErrPrimaryKeyRequired},
		{target: gorm.ErrModelValueRequired, sentinel: ErrModelValueRequired},
		{target: gorm.ErrModelAccessibleFieldsRequired, sentinel: ErrModelAccessibleFieldsRequired},
		{target: gorm.ErrSubQueryRequired, sentinel: ErrSubQueryRequired},
		{target: gorm.ErrInvalidData, sentinel: ErrInvalidData},
		{target: schema.ErrUnsupportedDataType, sentinel: ErrUnsupportedDataType},
		{target: gorm.ErrInvalidField, sentinel: ErrInvalidField},
		{target: gorm.ErrEmptySlice, sentinel: ErrEmptySlice},
		{target: gorm.ErrInvalidValue, sentinel: ErrInvalidValue},
		{target: gorm.ErrInvalidValueOfLength, sentinel: ErrInvalidValueOfLength},
		{target: gorm.ErrPreloadNotAllowed, sentinel: ErrPreloadNotAllowed},
		{target: gorm.ErrInvalidTransaction, sentinel: ErrInvalidTransaction},
		{target: sql.ErrTxDone, sentinel: ErrInvalidTransaction},
		{target: gorm.ErrNotImplemented, sentinel: ErrNotImplemented},
		{target: gorm.ErrUnsupportedRelation, sentinel: ErrUnsupportedRelation},
		{target: gorm.ErrUnsupportedDriver, sentinel: ErrUnsupportedDriver},
		{target: gorm.ErrRegistered, sentinel: ErrRegistered},
		{target: gorm.ErrDryRunModeUnsupported, sentinel: ErrDryRunModeUnsupported},
		{target: gorm.ErrInvalidDB, sentinel: ErrInvalidDB},
		{target: sql.ErrConnDone, sentinel: ErrInvalidDB},
	}
)

// dbMappedError wraps an underlying database/driver error with a pkg/db SentinelError,
// retaining both the sentinel identity and the underlying cause/message.
type dbMappedError struct {
	sentinel *SentinelError
	cause    error
}

func (m *dbMappedError) Error() string {
	if m.cause != nil && m.cause.Error() != m.sentinel.Error() {
		return m.sentinel.Error() + ": " + m.cause.Error()
	}
	return m.sentinel.Error()
}

func (m *dbMappedError) Unwrap() error {
	return m.sentinel
}

func (m *dbMappedError) Cause() error {
	return m.cause
}

func (m *dbMappedError) Is(target error) bool {
	if target == nil {
		return false
	}
	if errors.Is(m.sentinel, target) {
		return true
	}
	if m.cause != nil && errors.Is(m.cause, target) {
		return true
	}
	return false
}

func (m *dbMappedError) As(target any) bool {
	if errors.As(m.sentinel, target) {
		return true
	}
	if m.cause != nil && errors.As(m.cause, target) {
		return true
	}
	return false
}

func wrapMapped(sentinel *SentinelError, cause error) error {
	if cause == nil || cause == sentinel || cause == sentinel.gormErr {
		return sentinel
	}
	return &dbMappedError{
		sentinel: sentinel,
		cause:    cause,
	}
}

// matchDriverConstraintError serves as the primary line of defense in the Data layer,
// matching raw driver error text (e.g., MySQL error codes, PostgreSQL SQLSTATEs, and SQLite constraint text)
// that were not translated by gorm.ErrorTranslator into standard GORM sentinel errors.
//
// Dual-Defense Architecture & Maintenance Convention:
//   - Primary Line of Defense: pkg/db.matchDriverConstraintError (Data layer).
//   - Secondary Fallback:      pkg/errorx.matchDriverErrorText (Biz layer).
//
// MAINTENANCE NOTE:
// Keep the error text patterns synchronized between this function and pkg/errorx.matchDriverErrorText.
// Whenever a new dialect (e.g., Oracle, ClickHouse, Dameng) or error pattern is introduced, update both places.
func matchDriverConstraintError(err error) *SentinelError {
	msg := strings.ToLower(err.Error())

	for _, marker := range []string{
		"duplicate entry",
		"duplicate key",
		"unique constraint",
		"error 1062",
		"sqlstate 23505",
	} {
		if strings.Contains(msg, marker) {
			return ErrDuplicatedKey
		}
	}

	for _, marker := range []string{
		"foreign key constraint",
		"violates foreign key",
		"cannot delete or update a parent row",
		"cannot add or update a child row",
		"constraint failed: foreign key",
		"error 1451",
		"error 1452",
		"sqlstate 23503",
	} {
		if strings.Contains(msg, marker) {
			return ErrForeignKeyViolated
		}
	}

	for _, marker := range []string{
		"check constraint",
		"violates check constraint",
		"constraint failed: check",
		"error 3819",
		"sqlstate 23514",
	} {
		if strings.Contains(msg, marker) {
			return ErrCheckConstraintViolated
		}
	}

	return nil
}

// MapError maps any GORM, database/sql, or driver error to pkg/db's sentinel errors.
// If err is already a pkg/db SentinelError or dbMappedError, it is returned as is.
// If err is a context error (context.Canceled, context.DeadlineExceeded), it is returned untouched.
// If err matches a known GORM/database error, it is returned as the corresponding pkg/db error.
// If err is unrecognized, it is returned as is.
func MapError(err error) error {
	if err == nil {
		return nil
	}

	// 1. If err is already a SentinelError or dbMappedError, return as-is
	var (
		se *SentinelError
		me *dbMappedError
	)
	if errors.As(err, &se) || errors.As(err, &me) {
		return err
	}

	// 2. Do not remap context cancellation/deadline errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	// 3. Check custom error mappings first (allows overriding)
	customErrMu.RLock()
	for _, entry := range customErrorMappings {
		if errors.Is(err, entry.target) {
			customErrMu.RUnlock()
			return wrapMapped(entry.sentinel, err)
		}
	}
	customErrMu.RUnlock()

	// 4. Check builtin mappings
	for _, entry := range builtinMappings {
		if errors.Is(err, entry.target) {
			return wrapMapped(entry.sentinel, err)
		}
	}

	// 5. Fallback driver constraint text matching
	if sentinel := matchDriverConstraintError(err); sentinel != nil {
		return wrapMapped(sentinel, err)
	}

	// 6. Unknown / unmapped error, return as-is
	return err
}

// RegisterError registers or overrides a mapping from target error to a pkg/db SentinelError (concurrency-safe).
func RegisterError(target error, sentinel *SentinelError) {
	if target == nil || sentinel == nil {
		return
	}
	customErrMu.Lock()
	defer customErrMu.Unlock()
	for i := range customErrorMappings {
		if customErrorMappings[i].target == target {
			customErrorMappings[i].sentinel = sentinel
			return
		}
	}
	customErrorMappings = append(customErrorMappings, gormErrorMapping{
		target:   target,
		sentinel: sentinel,
	})
}

// IsRecordNotFound reports whether err represents a "record not found" error.
func IsRecordNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrRecordNotFound) || errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, sql.ErrNoRows)
}

// IsDuplicatedKey reports whether err represents a duplicate key / unique constraint violation.
func IsDuplicatedKey(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrDuplicatedKey) || errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	return matchDriverConstraintError(err) == ErrDuplicatedKey
}

// IsForeignKeyViolated reports whether err represents a foreign key constraint violation.
func IsForeignKeyViolated(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrForeignKeyViolated) || errors.Is(err, gorm.ErrForeignKeyViolated) {
		return true
	}
	return matchDriverConstraintError(err) == ErrForeignKeyViolated
}

// IsCheckConstraintViolated reports whether err represents a check constraint violation.
func IsCheckConstraintViolated(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrCheckConstraintViolated) || errors.Is(err, gorm.ErrCheckConstraintViolated) {
		return true
	}
	return matchDriverConstraintError(err) == ErrCheckConstraintViolated
}

// IsMissingWhereClause reports whether err represents a missing WHERE conditions error.
func IsMissingWhereClause(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrMissingWhereClause) || errors.Is(err, gorm.ErrMissingWhereClause)
}

// IsInvalidTransaction reports whether err represents an invalid transaction error.
func IsInvalidTransaction(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrInvalidTransaction) || errors.Is(err, gorm.ErrInvalidTransaction) || errors.Is(err, sql.ErrTxDone)
}
