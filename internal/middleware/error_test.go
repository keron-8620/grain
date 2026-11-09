package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"grain/pkg/errorx"
)

func TestErrorMiddleware(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	setupRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(ErrorMiddleware(logger))
		return r
	}

	t.Run("normal request succeeds", func(t *testing.T) {
		r := setupRouter()
		r.GET("/normal", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/normal", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ok", w.Body.String())
	})

	t.Run("panic with error recovers and returns 500", func(t *testing.T) {
		r := setupRouter()
		r.GET("/panic-err", func(c *gin.Context) {
			panic(errors.New("unexpected database error"))
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/panic-err", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20005") // CodeUnknown
	})

	t.Run("panic with string recovers and returns 500", func(t *testing.T) {
		r := setupRouter()
		r.GET("/panic-str", func(c *gin.Context) {
			panic("panic string message")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/panic-str", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20005")
	})

	t.Run("panic with arbitrary object recovers and returns 500", func(t *testing.T) {
		r := setupRouter()
		r.GET("/panic-obj", func(c *gin.Context) {
			panic(struct{ Code int }{Code: 999})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/panic-obj", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20005")
	})

	t.Run("panic after writer already written does not double-write", func(t *testing.T) {
		r := setupRouter()
		r.GET("/panic-written", func(c *gin.Context) {
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.Write([]byte("already written content"))
			panic("crash after write")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/panic-written", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "already written content", w.Body.String())
	})

	t.Run("broken pipe panic is gracefully aborted", func(t *testing.T) {
		r := setupRouter()
		r.GET("/broken-pipe", func(c *gin.Context) {
			panic(syscall.EPIPE)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/broken-pipe", nil)
		r.ServeHTTP(w, req)

		// Aborts without writing the 500 JSON response
		assert.NotContains(t, w.Body.String(), "10500")
	})

	t.Run("unhandled error in context formatted with errorx", func(t *testing.T) {
		r := setupRouter()
		r.GET("/errorx-test", func(c *gin.Context) {
			_ = c.Error(errorx.CodeResourceNotFound.Error())
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/errorx-test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "10404")
	})

	t.Run("unhandled standard error in context formatted as system error", func(t *testing.T) {
		r := setupRouter()
		r.GET("/std-err-test", func(c *gin.Context) {
			_ = c.Error(errors.New("db query failed"))
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/std-err-test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "20000") // CodeSystemError
	})

	t.Run("unhandled error in context after writer written does not double-write", func(t *testing.T) {
		r := setupRouter()
		r.GET("/err-written-test", func(c *gin.Context) {
			c.String(http.StatusOK, "response already sent")
			_ = c.Error(errors.New("late error"))
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/err-written-test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "response already sent", w.Body.String())
	})
}
