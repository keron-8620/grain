package errorx

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestError_NewAndErrorf(t *testing.T) {
	err1 := New(CodeInvalidParam, "")
	assert.Equal(t, CodeInvalidParam, err1.Code)
	assert.Equal(t, "参数校验失败", err1.Msg)
	assert.Equal(t, "error: code = 10001 msg = 参数校验失败", err1.Error())

	err2 := Errorf(CodeResourceNotFound, "用户 %d 未找到", 1001)
	assert.Equal(t, CodeResourceNotFound, err2.Code)
	assert.Equal(t, "用户 1001 未找到", err2.Msg)
	assert.Nil(t, err2.Unwrap())
}

func TestError_WrapAndUnwrap(t *testing.T) {
	assert.Nil(t, Wrap(nil, CodeSystemError, "db fail"))
	assert.Nil(t, Wrapf(nil, CodeSystemError, "db fail: %s", "timeout"))

	baseErr := errors.New("connection reset by peer")
	wrapped := Wrap(baseErr, CodeDBError, "查询数据库失败")
	assert.NotNil(t, wrapped)
	assert.Equal(t, CodeDBError, wrapped.Code)
	assert.Equal(t, "查询数据库失败", wrapped.Msg)
	assert.NotNil(t, wrapped.Unwrap())
	assert.True(t, errors.Is(wrapped, baseErr))

	wrappedf := Wrapf(baseErr, CodeTimeout, "请求 %s 超时", "redis")
	assert.Equal(t, CodeTimeout, wrappedf.Code)
	assert.Equal(t, "请求 redis 超时", wrappedf.Msg)
}

func TestError_CloneAndImmutability(t *testing.T) {
	original := New(CodeInvalidParam, "参数错误")

	withField := original.WithField("field", "username")
	assert.NotSame(t, original, withField)
	assert.Empty(t, original.Metadata())
	assert.Equal(t, "username", withField.Metadata()["field"])

	withMeta := original.WithMetadata(map[string]any{"trace_id": "123456"})
	assert.NotSame(t, original, withMeta)
	assert.Equal(t, "123456", withMeta.Metadata()["trace_id"])

	withDetails := original.WithDetails("detail1", 2)
	assert.NotSame(t, original, withDetails)
	assert.Empty(t, original.Details)
	assert.Len(t, withDetails.Details, 2)

	causeErr := errors.New("underlying")
	withCause := original.WithCause(causeErr)
	assert.NotSame(t, original, withCause)
	assert.Nil(t, original.Unwrap())
	assert.NotNil(t, withCause.Unwrap())

	// nil receiver 测试
	var nilErr *Error
	assert.Nil(t, Clone(nilErr))
	assert.Nil(t, nilErr.WithField("a", 1))
	assert.Nil(t, nilErr.WithMetadata(nil))
	assert.Nil(t, nilErr.WithDetails(1))
	assert.Nil(t, nilErr.WithCause(errors.New("x")))
	assert.Nil(t, nilErr.WithStack())
	assert.Empty(t, nilErr.Stack())
	assert.Nil(t, nilErr.Metadata())
	assert.Empty(t, nilErr.Error())
	assert.Nil(t, nilErr.Unwrap())
	assert.True(t, nilErr.Is(nil))
}

func TestError_Concurrency(t *testing.T) {
	sentinel := New(CodeSystemError, "全局系统错误")
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			e := sentinel.WithField("index", idx).WithDetails(fmt.Sprintf("detail-%d", idx))
			assert.Equal(t, idx, e.Metadata()["index"])
			assert.Contains(t, e.Details, fmt.Sprintf("detail-%d", idx))
		}(i)
	}

	wg.Wait()
	assert.Empty(t, sentinel.Metadata())
	assert.Empty(t, sentinel.Details)
}

func TestError_Format(t *testing.T) {
	err := New(CodeInvalidParam, "参数错误").
		WithDetails("field 'age' invalid").
		WithField("req_id", "req-1")

	assert.Equal(t, "error: code = 10001 msg = 参数错误", fmt.Sprintf("%s", err))
	assert.Equal(t, "\"error: code = 10001 msg = 参数错误\"", fmt.Sprintf("%q", err))

	verbose := fmt.Sprintf("%+v", err)
	assert.Contains(t, verbose, "error: code = 10001 msg = 参数错误")
	assert.Contains(t, verbose, "details: [field 'age' invalid]")
	assert.Contains(t, verbose, "metadata: map[req_id:req-1]")

	// default verb 测试
	unsupportedVerb := fmt.Sprintf("%d", err)
	assert.Contains(t, unsupportedVerb, "%!d(errorx.Error=")
}

func TestError_LogValue(t *testing.T) {
	cause := errors.New("io error")
	err := Wrap(cause, CodeDBError, "db failed").
		WithField("table", "users").
		WithDetails("query timeout")

	val := err.LogValue()
	assert.Equal(t, slog.KindGroup, val.Kind())

	// nil error
	var nilErr *Error
	assert.Equal(t, slog.Value{}, nilErr.LogValue())
}

func TestError_FromErrorAndIsCode(t *testing.T) {
	e := CodeResourceNotFound.Error()

	from, ok := FromError(e)
	assert.True(t, ok)
	assert.Equal(t, CodeResourceNotFound, from.Code)

	assert.True(t, IsCode(e, CodeResourceNotFound))
	assert.False(t, IsCode(e, CodeInvalidParam))

	// wrap 后也能被识别
	wrapped := fmt.Errorf("wrapped: %w", e)
	fromWrapped, ok := FromError(wrapped)
	assert.True(t, ok)
	assert.Equal(t, CodeResourceNotFound, fromWrapped.Code)
	assert.True(t, IsCode(wrapped, CodeResourceNotFound))

	// 普通 error
	stdErr := errors.New("pure standard error")
	_, ok = FromError(stdErr)
	assert.False(t, ok)
	assert.False(t, IsCode(stdErr, CodeSystemError))
	assert.False(t, IsCode(nil, CodeOK))
}

func TestError_StackTracing(t *testing.T) {
	// 1. 服务端系统级错误 (2xxxx) 默认自动捕获堆栈
	serverErr := New(CodeSystemError, "系统故障")
	assert.NotEmpty(t, serverErr.Stack())
	assert.Contains(t, serverErr.Stack(), "error_test.go")
	assert.Nil(t, serverErr.Unwrap())
	assert.Equal(t, "error: code = 20000 msg = 系统故障", serverErr.Error())

	// Format %+v 包含堆栈
	formattedServerErr := fmt.Sprintf("%+v", serverErr)
	assert.Contains(t, formattedServerErr, "error: code = 20000 msg = 系统故障")
	assert.Contains(t, formattedServerErr, "error_test.go")

	// LogValue 包含 stack，但无冗余 cause
	val := serverErr.LogValue()
	assert.Equal(t, slog.KindGroup, val.Kind())
	attrs := val.Group()
	var hasStack, hasCause bool
	for _, a := range attrs {
		if a.Key == "stack" {
			hasStack = true
		}
		if a.Key == "cause" {
			hasCause = true
		}
	}
	assert.True(t, hasStack)
	assert.False(t, hasCause)

	// 2. 客户端错误默认不捕获堆栈以保持高性能
	clientErr := New(CodeInvalidParam, "参数错误")
	assert.Empty(t, clientErr.Stack())

	// 3. 显式 WithStack 增强（保护性克隆，不可变）
	stacked := clientErr.WithStack()
	assert.NotSame(t, clientErr, stacked)
	assert.Empty(t, clientErr.Stack())
	assert.NotEmpty(t, stacked.Stack())
	assert.Contains(t, stacked.Stack(), "error_test.go")

	// 已有 cause 的错误调用 WithStack
	underlying := errors.New("underlying io issue")
	wrapped := Wrap(underlying, CodeExternalError, "依赖故障")
	assert.NotEmpty(t, wrapped.Stack())
	assert.Contains(t, wrapped.Stack(), "underlying io issue")
	stackedWrapped := wrapped.WithStack()
	assert.NotEmpty(t, stackedWrapped.Stack())

	// 4. 显式构造函数 NewWithStack 与 ErrorfWithStack
	explicitStackErr := NewWithStack(CodeInvalidParam, "显式记录堆栈")
	assert.NotEmpty(t, explicitStackErr.Stack())
	assert.Contains(t, explicitStackErr.Stack(), "error_test.go")

	explicitFormatStackErr := ErrorfWithStack(CodeForbidden, "无权访问 %s", "/admin")
	assert.NotEmpty(t, explicitFormatStackErr.Stack())
	assert.Equal(t, "无权访问 /admin", explicitFormatStackErr.Msg)

	// 5. BizCode 扩展方法构建
	bizServerErr := CodeSystemError.Error("系统服务异常")
	assert.NotEmpty(t, bizServerErr.Stack())

	bizClientErr := CodeInvalidParam.Error("普通参数错误")
	assert.Empty(t, bizClientErr.Stack())

	bizStackErr := CodeInvalidParam.ErrorWithStack("带堆栈参数错误")
	assert.NotEmpty(t, bizStackErr.Stack())

	bizFormatStackErr := CodeInvalidParam.ErrorfWithStack("字段 %s 无效", "age")
	assert.NotEmpty(t, bizFormatStackErr.Stack())
	assert.Equal(t, "字段 age 无效", bizFormatStackErr.Msg)
}
