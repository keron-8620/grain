package errorx

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockResponseContext struct {
	called     bool
	statusCode int
	body       map[string]any
}

func (m *mockResponseContext) AbortWithStatusJSON(code int, jsonObj any) {
	m.called = true
	m.statusCode = code
	if bodyMap, ok := jsonObj.(map[string]any); ok {
		m.body = bodyMap
	}
}

func TestRespondWithError_NilInputs(t *testing.T) {
	// 1. nil context, nil error
	RespondWithError(nil, nil)

	// 2. non-nil context, nil error
	mock := &mockResponseContext{}
	RespondWithError(mock, nil)
	assert.False(t, mock.called)

	// 3. nil context, non-nil error
	RespondWithError(nil, CodeInvalidParam.Error())
	assert.False(t, mock.called)
}

func TestRespondWithError_BizError(t *testing.T) {
	mock := &mockResponseContext{}
	err := CodeInvalidParam.Error("用户名不能为空")

	RespondWithError(mock, err)
	assert.True(t, mock.called)
	assert.Equal(t, http.StatusBadRequest, mock.statusCode)
	assert.Equal(t, CodeInvalidParam.Int(), mock.body["code"])
	assert.Equal(t, "用户名不能为空", mock.body["msg"])
	assert.Nil(t, mock.body["data"])
}

func TestRespondWithError_WithDetails(t *testing.T) {
	mock := &mockResponseContext{}
	err := CodeValidationFailed.Error().WithDetails("email invalid", "age must be positive")

	RespondWithError(mock, err)
	assert.True(t, mock.called)
	assert.Equal(t, http.StatusBadRequest, mock.statusCode)
	assert.Equal(t, CodeValidationFailed.Int(), mock.body["code"])
	assert.Equal(t, CodeValidationFailed.Message(), mock.body["msg"])

	details, ok := mock.body["data"].([]any)
	assert.True(t, ok)
	assert.Len(t, details, 2)
	assert.Contains(t, details, "email invalid")
	assert.Contains(t, details, "age must be positive")
}

func TestRespondWithError_StandardError(t *testing.T) {
	mock := &mockResponseContext{}
	rawErr := errors.New("raw database dead lock error")

	RespondWithError(mock, rawErr)
	assert.True(t, mock.called)
	assert.Equal(t, http.StatusInternalServerError, mock.statusCode)
	assert.Equal(t, CodeSystemError.Int(), mock.body["code"])
	assert.Equal(t, CodeSystemError.Message(), mock.body["msg"])
	assert.Nil(t, mock.body["data"])
}

func TestRespondWithError_WrappedError(t *testing.T) {
	mock := &mockResponseContext{}
	inner := CodeForbidden.Error("无权访问该资源")
	wrapped := fmt.Errorf("middleware auth check failed: %w", inner)

	RespondWithError(mock, wrapped)
	assert.True(t, mock.called)
	assert.Equal(t, http.StatusForbidden, mock.statusCode)
	assert.Equal(t, CodeForbidden.Int(), mock.body["code"])
	assert.Equal(t, "无权访问该资源", mock.body["msg"])
	assert.Nil(t, mock.body["data"])
}
