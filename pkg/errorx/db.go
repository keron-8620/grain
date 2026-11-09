package errorx

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// BizCoder 允许底层错误自主声明对应的 BizCode。
// 任何实现了 BizCode() BizCode 的错误均可在 FromDBError 中直接映射为对应的业务错误码。
type BizCoder interface {
	BizCode() BizCode
}

// ErrorCoder 允许任意底层技术层/基础设施错误在不依赖 errorx 包的前提下，
// 通过返回整型错误码完成解耦映射。
type ErrorCoder interface {
	ErrorCode() int
}

// FromDBError 将底层持久化层（GORM / database/sql / 驱动 / 自定义仓储等）返回的原始错误映射为具备明确语义的业务 *Error。
//
// 映射规则：
//   - 若 err 为 nil，直接返回 nil；
//   - 若 err 已是 *Error，直接返回（若提供了非空 msg[0]，则更新并返回克隆后的 *Error）；
//   - 若 err 实现了 BizCoder 或 ErrorCoder 接口，优先映射为其声明的业务错误码；
//   - 若 err 为 context.Canceled 或 context.DeadlineExceeded，分别映射为 CodeCanceled 和 CodeDeadlineExceeded；
//   - 若 err 匹配已知的 GORM/SQL 异常或数据库约束错误，映射为相应的业务错误码（如 CodeRecordNotFound, CodeDuplicatedKey 等）；
//   - 其他未识别的数据库底层错误，统一映射为 CodeDBError (数据服务异常)；
//   - 原始 err 会通过 emperror 挂载为 cause，保留原始堆栈和底层错误上下文，便于日志记录与排查。
func FromDBError(err error, msg ...string) *Error {
	if err == nil {
		return nil
	}

	// 1. 若已经是 *Error，保留或覆盖文案
	if e, ok := FromError(err); ok {
		if len(msg) > 0 && msg[0] != "" {
			cloned := Clone(e)
			cloned.Msg = msg[0]
			return cloned
		}
		return e
	}

	// 2. 匹配具体错误码
	code := mapDBErrorToCode(err)

	// 3. 构建 *Error
	var customMsg string
	if len(msg) > 0 {
		customMsg = msg[0]
	}

	return Wrap(err, code, customMsg)
}

// IsRecordNotFound 检查错误是否代表“记录未找到”错误 (CodeRecordNotFound)。
// 支持判断 *Error、实现了 BizCoder/ErrorCoder 的自定义错误、gorm.ErrRecordNotFound、sql.ErrNoRows 以及原生驱动文本特征。
func IsRecordNotFound(err error) bool {
	if err == nil {
		return false
	}
	if IsCode(err, CodeRecordNotFound) {
		return true
	}
	if matchCustomErrorCode(err) == CodeRecordNotFound {
		return true
	}
	if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, sql.ErrNoRows) {
		return true
	}
	return matchDriverErrorText(err) == CodeRecordNotFound
}

// IsDuplicatedKey 检查错误是否代表“唯一性约束冲突”错误 (CodeDuplicatedKey)。
// 支持判断 *Error、实现了 BizCoder/ErrorCoder 的自定义错误、gorm.ErrDuplicatedKey 以及原生驱动文本特征。
func IsDuplicatedKey(err error) bool {
	if err == nil {
		return false
	}
	if IsCode(err, CodeDuplicatedKey) {
		return true
	}
	if matchCustomErrorCode(err) == CodeDuplicatedKey {
		return true
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	return matchDriverErrorText(err) == CodeDuplicatedKey
}

// IsForeignKeyViolated 检查错误是否代表“外键约束冲突”错误 (CodeForeignKeyViolated)。
// 支持判断 *Error、实现了 BizCoder/ErrorCoder 的自定义错误、gorm.ErrForeignKeyViolated 以及原生驱动文本特征。
func IsForeignKeyViolated(err error) bool {
	if err == nil {
		return false
	}
	if IsCode(err, CodeForeignKeyViolated) {
		return true
	}
	if matchCustomErrorCode(err) == CodeForeignKeyViolated {
		return true
	}
	if errors.Is(err, gorm.ErrForeignKeyViolated) {
		return true
	}
	return matchDriverErrorText(err) == CodeForeignKeyViolated
}

// IsCheckConstraintViolated 检查错误是否代表“检查约束冲突”错误 (CodeCheckConstraintViolated)。
// 支持判断 *Error、实现了 BizCoder/ErrorCoder 的自定义错误、gorm.ErrCheckConstraintViolated 以及原生驱动文本特征。
func IsCheckConstraintViolated(err error) bool {
	if err == nil {
		return false
	}
	if IsCode(err, CodeCheckConstraintViolated) {
		return true
	}
	if matchCustomErrorCode(err) == CodeCheckConstraintViolated {
		return true
	}
	if errors.Is(err, gorm.ErrCheckConstraintViolated) {
		return true
	}
	return matchDriverErrorText(err) == CodeCheckConstraintViolated
}

// matchCustomErrorCode 尝试从实现了 BizCoder 或 ErrorCoder 接口的底层错误中提取错误码。
func matchCustomErrorCode(err error) BizCode {
	var bc BizCoder
	if errors.As(err, &bc) {
		if code := bc.BizCode(); code != 0 {
			return code
		}
	}
	var ec ErrorCoder
	if errors.As(err, &ec) {
		if code := BizCode(ec.ErrorCode()); code != 0 {
			return code
		}
	}
	return 0
}

// mapDBErrorToCode 将底层数据库/ORM错误映射为对应的 BizCode。
func mapDBErrorToCode(err error) BizCode {
	// 0. 优先识别实现了 BizCoder 或 ErrorCoder 的自定义数据层错误（解耦 Data 层错误体系）
	if code := matchCustomErrorCode(err); code != 0 {
		return code
	}

	// 1. 上下文异常优先识别
	if errors.Is(err, context.Canceled) {
		return CodeCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return CodeDeadlineExceeded
	}

	// 2. 查询未找到
	if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, sql.ErrNoRows) {
		return CodeRecordNotFound
	}

	// 3. 数据完整性与约束冲突
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return CodeDuplicatedKey
	}
	if errors.Is(err, gorm.ErrForeignKeyViolated) {
		return CodeForeignKeyViolated
	}
	if errors.Is(err, gorm.ErrCheckConstraintViolated) {
		return CodeCheckConstraintViolated
	}

	// 4. 业务数据与模型规则限制
	if errors.Is(err, gorm.ErrMissingWhereClause) {
		return CodeMissingWhereClause
	}
	if errors.Is(err, gorm.ErrPrimaryKeyRequired) {
		return CodePrimaryKeyRequired
	}
	if errors.Is(err, gorm.ErrModelValueRequired) {
		return CodeModelValueRequired
	}
	if errors.Is(err, gorm.ErrModelAccessibleFieldsRequired) {
		return CodeModelAccessibleFieldsRequired
	}
	if errors.Is(err, gorm.ErrSubQueryRequired) {
		return CodeSubQueryRequired
	}
	if errors.Is(err, gorm.ErrInvalidData) {
		return CodeInvalidData
	}
	if errors.Is(err, gorm.ErrInvalidField) {
		return CodeInvalidField
	}
	if errors.Is(err, gorm.ErrEmptySlice) {
		return CodeEmptySlice
	}
	if errors.Is(err, gorm.ErrInvalidValue) {
		return CodeInvalidValue
	}
	if errors.Is(err, gorm.ErrInvalidValueOfLength) {
		return CodeInvalidValueOfLength
	}
	if errors.Is(err, gorm.ErrPreloadNotAllowed) {
		return CodePreloadNotAllowed
	}

	// 5. 事务与底层系统级异常
	if errors.Is(err, gorm.ErrInvalidTransaction) || errors.Is(err, sql.ErrTxDone) {
		return CodeInvalidTransaction
	}
	if errors.Is(err, gorm.ErrNotImplemented) {
		return CodeNotImplemented
	}
	if errors.Is(err, gorm.ErrUnsupportedRelation) {
		return CodeUnsupportedRelation
	}
	if errors.Is(err, gorm.ErrUnsupportedDriver) {
		return CodeUnsupportedDriver
	}
	if errors.Is(err, schema.ErrUnsupportedDataType) {
		return CodeUnsupportedDriver
	}
	if errors.Is(err, gorm.ErrRegistered) {
		return CodeRegistered
	}
	if errors.Is(err, gorm.ErrDryRunModeUnsupported) {
		return CodeDryRunModeUnsupported
	}
	if errors.Is(err, gorm.ErrInvalidDB) || errors.Is(err, sql.ErrConnDone) {
		return CodeInvalidDB
	}

	// 6. 兜底匹配驱动层抛出但未经 GORM Translator 翻译的原生文本特征
	if code := matchDriverErrorText(err); code != 0 {
		return code
	}

	// 7. 默认兜底数据库服务异常
	return CodeDBError
}

// matchDriverErrorText acts as the secondary, defensive fallback in the Biz layer to match raw database
// driver error keywords (e.g., MySQL error codes, PostgreSQL SQLSTATEs, and SQLite constraint messages)
// that were not normalized by GORM's ErrorTranslator or the Data layer's MapError.
//
// Dual-Defense Architecture & Maintenance Convention:
//   - Primary Line of Defense: pkg/db.matchDriverConstraintError (Data layer).
//   - Secondary Fallback:      pkg/errorx.matchDriverErrorText (Biz layer).
//
// MAINTENANCE NOTE:
// Keep the error text patterns synchronized between this function and pkg/db.matchDriverConstraintError.
// Whenever a new dialect (e.g., Oracle, ClickHouse, Dameng) or error pattern is introduced, update both places.
func matchDriverErrorText(err error) BizCode {
	msg := strings.ToLower(err.Error())

	// 记录未找到特征
	if strings.Contains(msg, "record not found") || strings.Contains(msg, "no rows in result set") {
		return CodeRecordNotFound
	}

	// 唯一键冲突特征
	for _, marker := range []string{
		"duplicate entry",
		"duplicate key",
		"unique constraint",
		"error 1062",
		"sqlstate 23505",
	} {
		if strings.Contains(msg, marker) {
			return CodeDuplicatedKey
		}
	}

	// 外键约束特征
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
			return CodeForeignKeyViolated
		}
	}

	// Check 约束特征
	for _, marker := range []string{
		"check constraint",
		"violates check constraint",
		"constraint failed: check",
		"error 3819",
		"sqlstate 23514",
	} {
		if strings.Contains(msg, marker) {
			return CodeCheckConstraintViolated
		}
	}

	return 0
}
