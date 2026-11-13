package common

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/db"
	"grain/pkg/errorx"
)

func TestResponseHelpers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/success", func(c *gin.Context) {
		Success(c, map[string]string{"foo": "bar"})
	})
	r.GET("/success-msg", func(c *gin.Context) {
		SuccessMsg(c, "custom message", map[string]int{"val": 42})
	})
	r.GET("/failure-custom", func(c *gin.Context) {
		Failure(c, errorx.CodeInvalidParam.Error("参数错误测试"))
	})
	r.GET("/failure-raw", func(c *gin.Context) {
		Failure(c, errors.New("raw internal error"))
	})

	t.Run("Success helper", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/success", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp Response
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.Code)
		assert.Equal(t, "ok", resp.Msg)
	})

	t.Run("SuccessMsg helper", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/success-msg", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp Response
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.Code)
		assert.Equal(t, "custom message", resp.Msg)
	})

	t.Run("Failure custom error helper", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/failure-custom", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp Response
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, errorx.CodeInvalidParam.Int(), resp.Code)
		assert.Equal(t, "参数错误测试", resp.Msg)
	})

	t.Run("Failure raw error helper", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/failure-raw", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestParamsHelpers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/items/:id", func(c *gin.Context) {
		id, err := ParseUintID(c, "id")
		if err != nil {
			Failure(c, err)
			return
		}
		Success(c, id)
	})

	t.Run("ParseUintID valid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/items/123", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ParseUintID invalid string or zero", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/items/abc", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		reqZero := httptest.NewRequest(http.MethodGet, "/items/0", nil)
		wZero := httptest.NewRecorder()
		r.ServeHTTP(wZero, reqZero)
		assert.Equal(t, http.StatusBadRequest, wZero.Code)
	})

	t.Run("ParsePagination calculations and clamps", func(t *testing.T) {
		// 默认值
		offset, limit := ParsePagination(0, 0)
		assert.Equal(t, 0, offset)
		assert.Equal(t, db.DefaultPageSize, limit)

		// 正常值
		offset, limit = ParsePagination(2, 10)
		assert.Equal(t, 10, offset)
		assert.Equal(t, 10, limit)

		// 超过最大上限
		offset, limit = ParsePagination(1, 999)
		assert.Equal(t, 0, offset)
		assert.Equal(t, db.MaxPageSize, limit)
	})
}
