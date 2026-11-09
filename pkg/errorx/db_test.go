package errorx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestFromDBError_Nil(t *testing.T) {
	assert.Nil(t, FromDBError(nil))
}

func TestFromDBError_AlreadyError(t *testing.T) {
	original := CodeResourceNotFound.Error("资源不存在")
	mapped := FromDBError(original)
	assert.Same(t, original, mapped)

	// 带自定义 msg 时覆盖并返回 Clone
	overridden := FromDBError(original, "用户不存在")
	assert.NotSame(t, original, overridden)
	assert.Equal(t, CodeResourceNotFound, overridden.Code)
	assert.Equal(t, "用户不存在", overridden.Msg)
}

func TestFromDBError_RecordNotFound(t *testing.T) {
	// gorm.ErrRecordNotFound
	err1 := FromDBError(gorm.ErrRecordNotFound)
	assert.NotNil(t, err1)
	assert.Equal(t, CodeRecordNotFound, err1.Code)
	assert.Equal(t, "记录未找到", err1.Msg)
	assert.True(t, errors.Is(err1, gorm.ErrRecordNotFound))
	assert.True(t, IsRecordNotFound(err1))

	// 原生 gorm.ErrRecordNotFound 直接判断
	assert.True(t, IsRecordNotFound(gorm.ErrRecordNotFound))

	// sql.ErrNoRows
	err2 := FromDBError(sql.ErrNoRows, "指定用户不存在")
	assert.NotNil(t, err2)
	assert.Equal(t, CodeRecordNotFound, err2.Code)
	assert.Equal(t, "指定用户不存在", err2.Msg)
	assert.True(t, IsRecordNotFound(err2))
	assert.True(t, IsRecordNotFound(sql.ErrNoRows))

	// 驱动原生文本特征
	driverErr := errors.New("sql: no rows in result set")
	err3 := FromDBError(driverErr)
	assert.Equal(t, CodeRecordNotFound, err3.Code)
	assert.True(t, IsRecordNotFound(err3))
	assert.True(t, IsRecordNotFound(driverErr))

	// 包装后的原生错误
	wrappedErr := errors.New("wrapped: " + gorm.ErrRecordNotFound.Error())
	assert.True(t, IsRecordNotFound(wrappedErr))

	// 非 RecordNotFound
	assert.False(t, IsRecordNotFound(nil))
	assert.False(t, IsRecordNotFound(errors.New("connection failed")))
	assert.False(t, IsRecordNotFound(CodeInvalidParam.Error()))
}

func TestFromDBError_Constraints(t *testing.T) {
	// gorm.ErrDuplicatedKey
	dupErr := FromDBError(gorm.ErrDuplicatedKey)
	assert.Equal(t, CodeDuplicatedKey, dupErr.Code)
	assert.True(t, IsDuplicatedKey(dupErr))
	assert.True(t, IsDuplicatedKey(gorm.ErrDuplicatedKey))

	// 驱动原生唯一键冲突文本
	driverDup := errors.New("Error 1062: Duplicate entry 'admin' for key 'users.idx_username'")
	assert.Equal(t, CodeDuplicatedKey, FromDBError(driverDup).Code)
	assert.True(t, IsDuplicatedKey(driverDup))

	// 非 DuplicatedKey
	assert.False(t, IsDuplicatedKey(nil))
	assert.False(t, IsDuplicatedKey(errors.New("random error")))

	// gorm.ErrForeignKeyViolated
	fkErr := FromDBError(gorm.ErrForeignKeyViolated)
	assert.Equal(t, CodeForeignKeyViolated, fkErr.Code)
	assert.True(t, IsForeignKeyViolated(fkErr))
	assert.True(t, IsForeignKeyViolated(gorm.ErrForeignKeyViolated))

	// 驱动原生外键约束文本
	driverFK := errors.New("violates foreign key constraint 'fk_users_role'")
	assert.Equal(t, CodeForeignKeyViolated, FromDBError(driverFK).Code)
	assert.True(t, IsForeignKeyViolated(driverFK))
	assert.False(t, IsForeignKeyViolated(nil))
	assert.False(t, IsForeignKeyViolated(errors.New("other error")))

	// gorm.ErrCheckConstraintViolated
	chkErr := FromDBError(gorm.ErrCheckConstraintViolated)
	assert.Equal(t, CodeCheckConstraintViolated, chkErr.Code)
	assert.True(t, IsCheckConstraintViolated(chkErr))
	assert.True(t, IsCheckConstraintViolated(gorm.ErrCheckConstraintViolated))

	// 驱动原生 check 约束文本
	driverChk := errors.New("error 3819: check constraint 'chk_age' is violated")
	assert.Equal(t, CodeCheckConstraintViolated, FromDBError(driverChk).Code)
	assert.True(t, IsCheckConstraintViolated(driverChk))
	assert.False(t, IsCheckConstraintViolated(nil))
	assert.False(t, IsCheckConstraintViolated(errors.New("other error")))
}

func TestFromDBError_ContextErrors(t *testing.T) {
	cancelErr := FromDBError(context.Canceled)
	assert.Equal(t, CodeCanceled, cancelErr.Code)

	timeoutErr := FromDBError(context.DeadlineExceeded)
	assert.Equal(t, CodeDeadlineExceeded, timeoutErr.Code)
}

func TestFromDBError_SystemAndQueryErrors(t *testing.T) {
	txErr := FromDBError(gorm.ErrInvalidTransaction)
	assert.Equal(t, CodeInvalidTransaction, txErr.Code)

	whereErr := FromDBError(gorm.ErrMissingWhereClause)
	assert.Equal(t, CodeMissingWhereClause, whereErr.Code)

	notImplErr := FromDBError(gorm.ErrNotImplemented)
	assert.Equal(t, CodeNotImplemented, notImplErr.Code)

	dbConnErr := FromDBError(gorm.ErrInvalidDB)
	assert.Equal(t, CodeInvalidDB, dbConnErr.Code)

	// 未知数据库错误兜底为 CodeDBError
	unknownErr := FromDBError(errors.New("dial tcp 127.0.0.1:3306: connect: connection refused"))
	assert.Equal(t, CodeDBError, unknownErr.Code)
	assert.Equal(t, "数据服务异常", unknownErr.Msg)
}

type customBizCodeErr struct {
	code BizCode
	msg  string
}

func (e *customBizCodeErr) Error() string   { return e.msg }
func (e *customBizCodeErr) BizCode() BizCode { return e.code }

type customErrorCodeErr struct {
	code int
	msg  string
}

func (e *customErrorCodeErr) Error() string { return e.msg }
func (e *customErrorCodeErr) ErrorCode() int { return e.code }

func TestFromDBError_InterfaceCoders(t *testing.T) {
	// 1. 测试 BizCoder 接口支持
	bizErr := &customBizCodeErr{code: CodeRecordNotFound, msg: "custom record not found"}
	mappedBizErr := FromDBError(bizErr)
	assert.Equal(t, CodeRecordNotFound, mappedBizErr.Code)
	assert.True(t, IsRecordNotFound(mappedBizErr))
	assert.True(t, IsRecordNotFound(bizErr))

	// 2. 测试 ErrorCoder 接口支持（返回整型，解耦 errorx）
	intErr := &customErrorCodeErr{code: int(CodeDuplicatedKey), msg: "custom duplicate key"}
	mappedIntErr := FromDBError(intErr)
	assert.Equal(t, CodeDuplicatedKey, mappedIntErr.Code)
	assert.True(t, IsDuplicatedKey(mappedIntErr))
	assert.True(t, IsDuplicatedKey(intErr))

	// 3. 测试外键与 Check 约束识别
	fkErr := &customErrorCodeErr{code: int(CodeForeignKeyViolated), msg: "custom fk error"}
	assert.Equal(t, CodeForeignKeyViolated, FromDBError(fkErr).Code)
	assert.True(t, IsForeignKeyViolated(fkErr))

	chkErr := &customBizCodeErr{code: CodeCheckConstraintViolated, msg: "custom chk error"}
	assert.Equal(t, CodeCheckConstraintViolated, FromDBError(chkErr).Code)
	assert.True(t, IsCheckConstraintViolated(chkErr))

	// 4. 包装嵌套错误 (wrapped error)
	wrappedErr := fmt.Errorf("repo query failed: %w", bizErr)
	mappedWrapped := FromDBError(wrappedErr)
	assert.Equal(t, CodeRecordNotFound, mappedWrapped.Code)
	assert.True(t, IsRecordNotFound(wrappedErr))

	// 5. 错误码返回 0 时回退到默认匹配机制
	zeroErr := &customErrorCodeErr{code: 0, msg: "no specific code"}
	mappedZero := FromDBError(zeroErr)
	assert.Equal(t, CodeDBError, mappedZero.Code)
}

// TestFromDBError_DriverContractAlignment verifies that the driver error text matching rules
// in pkg/errorx (secondary fallback) remain strictly synchronized with pkg/db (primary defense).
func TestFromDBError_DriverContractAlignment(t *testing.T) {
	tests := []struct {
		name         string
		rawMsg       string
		expectedCode BizCode
		assertFn     func(error) bool
	}{
		// Duplicate key violations (MySQL, PostgreSQL, SQLite)
		{"MySQL 1062 duplicate", "Error 1062 (23000): Duplicate entry 'admin' for key 'users.idx_username'", CodeDuplicatedKey, IsDuplicatedKey},
		{"PostgreSQL 23505 duplicate", "ERROR: duplicate key value violates unique constraint \"users_pkey\" (SQLSTATE 23505)", CodeDuplicatedKey, IsDuplicatedKey},
		{"SQLite UNIQUE constraint", "UNIQUE constraint failed: users.username", CodeDuplicatedKey, IsDuplicatedKey},

		// Foreign key violations (MySQL, PostgreSQL, SQLite)
		{"MySQL 1451 FK", "Error 1451 (23000): Cannot delete or update a parent row: a foreign key constraint fails", CodeForeignKeyViolated, IsForeignKeyViolated},
		{"MySQL 1452 FK", "Error 1452 (23000): Cannot add or update a child row: a foreign key constraint fails", CodeForeignKeyViolated, IsForeignKeyViolated},
		{"PostgreSQL 23503 FK", "ERROR: insert or update on table \"user_roles\" violates foreign key constraint \"fk_role\" (SQLSTATE 23503)", CodeForeignKeyViolated, IsForeignKeyViolated},
		{"SQLite FK constraint", "constraint failed: foreign key", CodeForeignKeyViolated, IsForeignKeyViolated},

		// Check constraint violations (MySQL, PostgreSQL, SQLite)
		{"MySQL 3819 CHECK", "Error 3819 (HY000): Check constraint 'chk_age' is violated", CodeCheckConstraintViolated, IsCheckConstraintViolated},
		{"PostgreSQL 23514 CHECK", "ERROR: new row for relation \"users\" violates check constraint \"users_age_check\" (SQLSTATE 23514)", CodeCheckConstraintViolated, IsCheckConstraintViolated},
		{"SQLite CHECK constraint", "constraint failed: check", CodeCheckConstraintViolated, IsCheckConstraintViolated},

		// Record not found text
		{"Record not found text", "record not found in table users", CodeRecordNotFound, IsRecordNotFound},
		{"No rows in result set text", "sql: no rows in result set", CodeRecordNotFound, IsRecordNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawErr := errors.New(tt.rawMsg)
			mapped := FromDBError(rawErr)
			assert.Equal(t, tt.expectedCode, mapped.Code, "FromDBError should map %s to %v", tt.name, tt.expectedCode)
			assert.True(t, tt.assertFn(rawErr), "assertFn should recognize raw error for %s", tt.name)
			assert.True(t, tt.assertFn(mapped), "assertFn should recognize mapped error for %s", tt.name)
		})
	}
}
