package db

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"emperror.dev/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func TestSentinelErrors_DefinitionsAndMessages(t *testing.T) {
	tests := []struct {
		name     string
		sentinel *SentinelError
		expected string
		gormErr  error
	}{
		{"ErrRecordNotFound", ErrRecordNotFound, "record not found", gorm.ErrRecordNotFound},
		{"ErrInvalidTransaction", ErrInvalidTransaction, "invalid transaction", gorm.ErrInvalidTransaction},
		{"ErrNotImplemented", ErrNotImplemented, "not implemented", gorm.ErrNotImplemented},
		{"ErrMissingWhereClause", ErrMissingWhereClause, "WHERE conditions required", gorm.ErrMissingWhereClause},
		{"ErrUnsupportedRelation", ErrUnsupportedRelation, "unsupported relations", gorm.ErrUnsupportedRelation},
		{"ErrPrimaryKeyRequired", ErrPrimaryKeyRequired, "primary key required", gorm.ErrPrimaryKeyRequired},
		{"ErrModelValueRequired", ErrModelValueRequired, "model value required", gorm.ErrModelValueRequired},
		{"ErrModelAccessibleFieldsRequired", ErrModelAccessibleFieldsRequired, "model accessible fields required", gorm.ErrModelAccessibleFieldsRequired},
		{"ErrSubQueryRequired", ErrSubQueryRequired, "sub query required", gorm.ErrSubQueryRequired},
		{"ErrInvalidData", ErrInvalidData, "unsupported data", gorm.ErrInvalidData},
		{"ErrUnsupportedDriver", ErrUnsupportedDriver, "unsupported driver", gorm.ErrUnsupportedDriver},
		{"ErrRegistered", ErrRegistered, "registered", gorm.ErrRegistered},
		{"ErrInvalidField", ErrInvalidField, "invalid field", gorm.ErrInvalidField},
		{"ErrEmptySlice", ErrEmptySlice, "empty slice found", gorm.ErrEmptySlice},
		{"ErrDryRunModeUnsupported", ErrDryRunModeUnsupported, "dry run mode unsupported", gorm.ErrDryRunModeUnsupported},
		{"ErrInvalidDB", ErrInvalidDB, "invalid db", gorm.ErrInvalidDB},
		{"ErrInvalidValue", ErrInvalidValue, "invalid value, should be pointer to struct or slice", gorm.ErrInvalidValue},
		{"ErrInvalidValueOfLength", ErrInvalidValueOfLength, "invalid association values, length doesn't match", gorm.ErrInvalidValueOfLength},
		{"ErrPreloadNotAllowed", ErrPreloadNotAllowed, "preload is not allowed when count is used", gorm.ErrPreloadNotAllowed},
		{"ErrDuplicatedKey", ErrDuplicatedKey, "duplicated key not allowed", gorm.ErrDuplicatedKey},
		{"ErrForeignKeyViolated", ErrForeignKeyViolated, "violates foreign key constraint", gorm.ErrForeignKeyViolated},
		{"ErrCheckConstraintViolated", ErrCheckConstraintViolated, "violates check constraint", gorm.ErrCheckConstraintViolated},
		{"ErrUnsupportedDataType", ErrUnsupportedDataType, "unsupported data type", schema.ErrUnsupportedDataType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.sentinel.Error())
			assert.True(t, errors.Is(tt.sentinel, tt.sentinel))
			if tt.gormErr != nil {
				assert.True(t, errors.Is(tt.sentinel, tt.gormErr), "should match corresponding GORM error")
			}
		})
	}
}

func TestSentinelError_Is(t *testing.T) {
	assert.False(t, ErrRecordNotFound.Is(nil))
	assert.False(t, ErrRecordNotFound.Is(ErrDuplicatedKey))
	assert.False(t, ErrRecordNotFound.Is(gorm.ErrDuplicatedKey))
	assert.True(t, ErrRecordNotFound.Is(gorm.ErrRecordNotFound))

	custom := NewSentinelError("custom sentinel")
	assert.True(t, custom.Is(custom))
	assert.False(t, custom.Is(ErrRecordNotFound))
}

func TestMapError_GormBuiltinErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected *SentinelError
	}{
		{"gorm.ErrRecordNotFound", gorm.ErrRecordNotFound, ErrRecordNotFound},
		{"sql.ErrNoRows", sql.ErrNoRows, ErrRecordNotFound},
		{"gorm.ErrDuplicatedKey", gorm.ErrDuplicatedKey, ErrDuplicatedKey},
		{"gorm.ErrForeignKeyViolated", gorm.ErrForeignKeyViolated, ErrForeignKeyViolated},
		{"gorm.ErrCheckConstraintViolated", gorm.ErrCheckConstraintViolated, ErrCheckConstraintViolated},
		{"gorm.ErrMissingWhereClause", gorm.ErrMissingWhereClause, ErrMissingWhereClause},
		{"gorm.ErrPrimaryKeyRequired", gorm.ErrPrimaryKeyRequired, ErrPrimaryKeyRequired},
		{"gorm.ErrModelValueRequired", gorm.ErrModelValueRequired, ErrModelValueRequired},
		{"gorm.ErrModelAccessibleFieldsRequired", gorm.ErrModelAccessibleFieldsRequired, ErrModelAccessibleFieldsRequired},
		{"gorm.ErrSubQueryRequired", gorm.ErrSubQueryRequired, ErrSubQueryRequired},
		{"gorm.ErrInvalidData", gorm.ErrInvalidData, ErrInvalidData},
		{"schema.ErrUnsupportedDataType", schema.ErrUnsupportedDataType, ErrUnsupportedDataType},
		{"gorm.ErrInvalidField", gorm.ErrInvalidField, ErrInvalidField},
		{"gorm.ErrEmptySlice", gorm.ErrEmptySlice, ErrEmptySlice},
		{"gorm.ErrInvalidValue", gorm.ErrInvalidValue, ErrInvalidValue},
		{"gorm.ErrInvalidValueOfLength", gorm.ErrInvalidValueOfLength, ErrInvalidValueOfLength},
		{"gorm.ErrPreloadNotAllowed", gorm.ErrPreloadNotAllowed, ErrPreloadNotAllowed},
		{"gorm.ErrInvalidTransaction", gorm.ErrInvalidTransaction, ErrInvalidTransaction},
		{"sql.ErrTxDone", sql.ErrTxDone, ErrInvalidTransaction},
		{"gorm.ErrNotImplemented", gorm.ErrNotImplemented, ErrNotImplemented},
		{"gorm.ErrUnsupportedRelation", gorm.ErrUnsupportedRelation, ErrUnsupportedRelation},
		{"gorm.ErrUnsupportedDriver", gorm.ErrUnsupportedDriver, ErrUnsupportedDriver},
		{"gorm.ErrRegistered", gorm.ErrRegistered, ErrRegistered},
		{"gorm.ErrDryRunModeUnsupported", gorm.ErrDryRunModeUnsupported, ErrDryRunModeUnsupported},
		{"gorm.ErrInvalidDB", gorm.ErrInvalidDB, ErrInvalidDB},
		{"sql.ErrConnDone", sql.ErrConnDone, ErrInvalidDB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapped := MapError(tt.input)
			require.Error(t, mapped)
			assert.True(t, errors.Is(mapped, tt.expected), "mapped error should match expected sentinel")
			assert.True(t, errors.Is(mapped, tt.input), "mapped error should preserve matching original target")
		})
	}
}

func TestMapError_DriverConstraintStrings(t *testing.T) {
	tests := []struct {
		name     string
		rawMsg   string
		expected *SentinelError
	}{
		{"MySQL 1062 duplicate", "Error 1062 (23000): Duplicate entry 'admin' for key 'users.idx_username'", ErrDuplicatedKey},
		{"PostgreSQL 23505 duplicate", "ERROR: duplicate key value violates unique constraint \"users_pkey\" (SQLSTATE 23505)", ErrDuplicatedKey},
		{"SQLite UNIQUE constraint", "UNIQUE constraint failed: users.username", ErrDuplicatedKey},
		{"MySQL 1451 FK", "Error 1451 (23000): Cannot delete or update a parent row: a foreign key constraint fails", ErrForeignKeyViolated},
		{"MySQL 1452 FK", "Error 1452 (23000): Cannot add or update a child row: a foreign key constraint fails", ErrForeignKeyViolated},
		{"PostgreSQL 23503 FK", "ERROR: insert or update on table \"user_roles\" violates foreign key constraint \"fk_role\" (SQLSTATE 23503)", ErrForeignKeyViolated},
		{"SQLite FK constraint", "constraint failed: foreign key", ErrForeignKeyViolated},
		{"MySQL 3819 CHECK", "Error 3819 (HY000): Check constraint 'chk_age' is violated", ErrCheckConstraintViolated},
		{"PostgreSQL 23514 CHECK", "ERROR: new row for relation \"users\" violates check constraint \"users_age_check\" (SQLSTATE 23514)", ErrCheckConstraintViolated},
		{"SQLite CHECK constraint", "constraint failed: check", ErrCheckConstraintViolated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawErr := errors.New(tt.rawMsg)
			mapped := MapError(rawErr)
			require.Error(t, mapped)
			assert.True(t, errors.Is(mapped, tt.expected), "should map to sentinel %v", tt.expected)
			assert.Contains(t, mapped.Error(), tt.rawMsg, "mapped error should preserve raw error context")
			assert.True(t, errors.Is(mapped, rawErr), "mapped error should match raw error")
		})
	}
}

func TestMapError_SpecialCases(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.NoError(t, MapError(nil))
	})

	t.Run("already SentinelError", func(t *testing.T) {
		assert.Equal(t, ErrRecordNotFound, MapError(ErrRecordNotFound))
	})

	t.Run("already wrapped SentinelError", func(t *testing.T) {
		wrapped := errors.Wrap(ErrRecordNotFound, "wrapped query")
		mapped := MapError(wrapped)
		assert.Equal(t, wrapped, mapped)
		assert.True(t, errors.Is(mapped, ErrRecordNotFound))
	})

	t.Run("context errors untouched", func(t *testing.T) {
		assert.Equal(t, context.Canceled, MapError(context.Canceled))
		assert.Equal(t, context.DeadlineExceeded, MapError(context.DeadlineExceeded))
	})

	t.Run("unknown error untouched", func(t *testing.T) {
		unknown := errors.New("something bizarre occurred")
		mapped := MapError(unknown)
		assert.Equal(t, unknown, mapped)
	})
}

func TestHelperFunctions(t *testing.T) {
	assert.True(t, IsRecordNotFound(ErrRecordNotFound))
	assert.True(t, IsRecordNotFound(gorm.ErrRecordNotFound))
	assert.True(t, IsRecordNotFound(MapError(gorm.ErrRecordNotFound)))
	assert.True(t, IsRecordNotFound(errors.Wrap(ErrRecordNotFound, "query failed")))
	assert.False(t, IsRecordNotFound(ErrDuplicatedKey))
	assert.False(t, IsRecordNotFound(nil))

	assert.True(t, IsDuplicatedKey(ErrDuplicatedKey))
	assert.True(t, IsDuplicatedKey(gorm.ErrDuplicatedKey))
	assert.True(t, IsDuplicatedKey(MapError(errors.New("Duplicate entry 'foo'"))))
	assert.False(t, IsDuplicatedKey(ErrRecordNotFound))
	assert.False(t, IsDuplicatedKey(nil))

	assert.True(t, IsForeignKeyViolated(ErrForeignKeyViolated))
	assert.True(t, IsForeignKeyViolated(gorm.ErrForeignKeyViolated))
	assert.False(t, IsForeignKeyViolated(ErrRecordNotFound))
	assert.False(t, IsForeignKeyViolated(nil))

	assert.True(t, IsCheckConstraintViolated(ErrCheckConstraintViolated))
	assert.True(t, IsCheckConstraintViolated(gorm.ErrCheckConstraintViolated))
	assert.False(t, IsCheckConstraintViolated(ErrRecordNotFound))
	assert.False(t, IsCheckConstraintViolated(nil))

	assert.True(t, IsMissingWhereClause(ErrMissingWhereClause))
	assert.True(t, IsMissingWhereClause(gorm.ErrMissingWhereClause))
	assert.False(t, IsMissingWhereClause(ErrRecordNotFound))
	assert.False(t, IsMissingWhereClause(nil))

	assert.True(t, IsInvalidTransaction(ErrInvalidTransaction))
	assert.True(t, IsInvalidTransaction(gorm.ErrInvalidTransaction))
	assert.True(t, IsInvalidTransaction(sql.ErrTxDone))
	assert.False(t, IsInvalidTransaction(ErrRecordNotFound))
	assert.False(t, IsInvalidTransaction(nil))
}

func TestRegisterError(t *testing.T) {
	customTarget := errors.New("custom db connection lost")
	customSentinel := NewSentinelError("custom connection lost sentinel")

	RegisterError(customTarget, customSentinel)

	mapped := MapError(customTarget)
	assert.True(t, errors.Is(mapped, customSentinel))

	// Nil arguments guard
	RegisterError(nil, customSentinel)
	RegisterError(customTarget, nil)
}

func TestDbMappedError_As(t *testing.T) {
	type customErrType struct {
		code int
	}

	customErr := &customErrStruct{code: 42}
	mapped := wrapMapped(ErrInvalidData, customErr)

	var target *customErrStruct
	require.True(t, errors.As(mapped, &target))
	assert.Equal(t, 42, target.code)

	var se *SentinelError
	require.True(t, errors.As(mapped, &se))
	assert.Equal(t, ErrInvalidData, se)
}

type customErrStruct struct {
	code int
}

func (c *customErrStruct) Error() string {
	return fmt.Sprintf("custom error code %d", c.code)
}

func TestCRUD_ReturnsMappedErrors(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	var err error

	// 1. Missing WHERE clause returns ErrMissingWhereClause
	_, err = DBUpdate(ctx, db, &TestUser{}, map[string]any{"name": "new"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingWhereClause))
	assert.True(t, IsMissingWhereClause(err))

	_, err = DBDelete(ctx, db, &TestUser{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingWhereClause))
	assert.True(t, IsMissingWhereClause(err))

	// 2. Querying non-existent record returns ErrRecordNotFound
	var u TestUser
	err = DBFindOne(ctx, db, &u, nil, "id = ?", 999999)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRecordNotFound))
	assert.True(t, IsRecordNotFound(err))

	// 3. Unique constraint violation returns ErrDuplicatedKey
	u1 := &TestUser{Name: "unique_user", Email: "unique@example.com", Age: 25}
	require.NoError(t, DBCreate(ctx, db, &TestUser{}, u1))

	// Creating same primary key to trigger duplicate key error
	u2 := &TestUser{ID: u1.ID, Name: "duplicate", Email: "dup@example.com", Age: 30}
	err = DBCreate(ctx, db, &TestUser{}, u2)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDuplicatedKey))
	assert.True(t, IsDuplicatedKey(err))
}
