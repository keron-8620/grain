package errorx

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBizCode_Basics(t *testing.T) {
	code := CodeInvalidParam
	assert.Equal(t, 10001, code.Int())
	assert.Equal(t, "10001", code.String())
	assert.Equal(t, "参数校验失败", code.Message())

	// 分段判断
	assert.True(t, CodeOK.IsSuccess())
	assert.False(t, CodeInvalidParam.IsSuccess())

	assert.True(t, CodeInvalidParam.IsClientError())
	assert.True(t, CodeResourceNotFound.IsClientError())
	assert.True(t, CodeHostHeaderInvalid.IsClientError())
	assert.True(t, CodeTokenInvalid.IsClientError())
	assert.False(t, CodeSystemError.IsClientError())

	assert.True(t, CodeSystemError.IsServerError())
	assert.True(t, CodeDBError.IsServerError())
	assert.True(t, CodeInvalidTransaction.IsServerError())
	assert.False(t, CodeExternalError.IsServerError())

	assert.True(t, CodeExternalError.IsDependencyError())
	assert.True(t, CodeThirdPartyError.IsDependencyError())
	assert.True(t, CodeSSHConnectionFailed.IsDependencyError())
	assert.False(t, CodeBusinessError.IsDependencyError())

	assert.True(t, CodeBusinessError.IsBusinessError())
	assert.True(t, CodePreconditionFailed.IsBusinessError())
	assert.True(t, CodeRecordNotFound.IsBusinessError())
	assert.True(t, CodeCronSpecificationInvalid.IsBusinessError())
	assert.False(t, CodeInvalidParam.IsBusinessError())
}

func TestBizCode_ErrorConstructors(t *testing.T) {
	err1 := CodeInvalidParam.Error()
	assert.NotNil(t, err1)
	assert.Equal(t, CodeInvalidParam, err1.Code)
	assert.Equal(t, "参数校验失败", err1.Msg)

	err2 := CodeResourceNotFound.Error("指定订单不存在")
	assert.NotNil(t, err2)
	assert.Equal(t, CodeResourceNotFound, err2.Code)
	assert.Equal(t, "指定订单不存在", err2.Msg)

	err3 := CodeInvalidFormat.Errorf("字段 %s 格式错误", "email")
	assert.NotNil(t, err3)
	assert.Equal(t, CodeInvalidFormat, err3.Code)
	assert.Equal(t, "字段 email 格式错误", err3.Msg)
}

func TestBizCode_HTTPStatusMapping(t *testing.T) {
	tests := []struct {
		code           BizCode
		expectedStatus int
	}{
		{CodeOK, http.StatusOK},
		{CodeUnauthorized, http.StatusUnauthorized},
		{CodeTokenExpired, http.StatusUnauthorized},
		{CodeTokenInvalid, http.StatusUnauthorized},
		{CodeMissingAuth, http.StatusUnauthorized},
		{CodeTokenTypeMismatch, http.StatusUnauthorized},
		{CodeAuthFailed, http.StatusUnauthorized},
		{CodeForbidden, http.StatusForbidden},
		{CodeAccountLocked, http.StatusForbidden},
		{CodeResourceNotFound, http.StatusNotFound},
		{CodeRecordNotFound, http.StatusNotFound},
		{CodeDownloadFileNotFound, http.StatusNotFound},
		{CodeMethodNotAllowed, http.StatusMethodNotAllowed},
		{CodeResourceAlreadyExists, http.StatusConflict},
		{CodeDuplicatedKey, http.StatusConflict},
		{CodeForeignKeyViolated, http.StatusConflict},
		{CodeRequestBodyTooLarge, http.StatusRequestEntityTooLarge},
		{CodeUnsupportedMediaType, http.StatusUnsupportedMediaType},
		{CodeTooManyRequests, http.StatusTooManyRequests},
		{CodeRateLimitExceeded, http.StatusTooManyRequests},
		{CodeRequestTimeout, http.StatusRequestTimeout},
		{CodeTimeout, http.StatusGatewayTimeout},
		{CodeGatewayTimeout, http.StatusGatewayTimeout},
		{CodeDeadlineExceeded, http.StatusGatewayTimeout},
		{CodeExternalError, http.StatusBadGateway},
		{CodeThirdPartyError, http.StatusBadGateway},
		{CodeRPCError, http.StatusBadGateway},
		{CodeNotImplemented, http.StatusNotImplemented},
		{CodeInvalidParam, http.StatusBadRequest},
		{CodeSystemError, http.StatusInternalServerError},
		{CodeBusinessError, http.StatusBadRequest},
		{BizCode(99999), http.StatusInternalServerError}, // 未知
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expectedStatus, tt.code.HTTPStatus(), "code %d http status mismatch", tt.code)
	}

	// HTTPStatus(*Error) helper
	assert.Equal(t, http.StatusOK, HTTPStatus(nil))
	assert.Equal(t, http.StatusNotFound, HTTPStatus(CodeResourceNotFound.Error()))
}

func TestRegisterHTTPStatus(t *testing.T) {
	customCode := BizCode(49999)
	assert.Equal(t, http.StatusBadRequest, customCode.HTTPStatus())

	RegisterHTTPStatus(customCode, http.StatusTeapot)
	assert.Equal(t, http.StatusTeapot, customCode.HTTPStatus())

	RegisterHTTPStatuses(map[BizCode]int{
		customCode: http.StatusPaymentRequired,
	})
	assert.Equal(t, http.StatusPaymentRequired, customCode.HTTPStatus())
}

func TestRegisterErrorMessage(t *testing.T) {
	customCode := BizCode(48888)
	assert.Equal(t, "操作失败", customCode.Message())

	RegisterErrorMessage(customCode, "自定义业务失败提示")
	assert.Equal(t, "自定义业务失败提示", customCode.Message())

	RegisterErrorMessages(map[BizCode]string{
		customCode: "批量覆盖业务提示",
	})
	assert.Equal(t, "批量覆盖业务提示", customCode.Message())
}

func TestNewBizCodes_Messages(t *testing.T) {
	assert.Equal(t, "Host头无效", CodeHostHeaderInvalid.Message())
	assert.Equal(t, "检测为重放攻击", CodeReplayAttack.Message())
	assert.Equal(t, "时间戳已过期", CodeTimestampExpired.Message())
	assert.Equal(t, "无效的登录凭证", CodeTokenInvalid.Message())
	assert.Equal(t, "身份认证失败", CodeAuthFailed.Message())
	assert.Equal(t, "账号已被锁定", CodeAccountLocked.Message())
	assert.Equal(t, "记录未找到", CodeRecordNotFound.Message())
	assert.Equal(t, "唯一性约束冲突", CodeDuplicatedKey.Message())
	assert.Equal(t, "SSH连接失败", CodeSSHConnectionFailed.Message())
	assert.Equal(t, "计划任务表达式格式错误", CodeCronSpecificationInvalid.Message())
}
