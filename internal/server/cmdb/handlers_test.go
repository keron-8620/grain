package cmdb

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/internal/conf"
	"grain/pkg/auth"
)

type envelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func serveJSON(t *testing.T, engine *gin.Engine, method, path string, body any) envelope {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var env envelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "body: %s", w.Body.String())
	return env
}

// TestCMDBHandlers exercises the HTTP layer with claims injected directly (the
// JWT/Casbin middleware is covered by the IAM and job integration tests).
func TestCMDBHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalStorage := conf.StorageDir
	conf.StorageDir = t.TempDir()
	t.Cleanup(func() { conf.StorageDir = originalStorage })

	srv, err := New(Options{GormDB: setupCMDBTestDB(t), Bootstrap: &conf.Bootstrap{}})
	require.NoError(t, err)

	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		ctx := auth.SetJwtClaims(c.Request.Context(), &auth.JwtClaims{
			UserInfo: auth.UserInfo{UserID: 1, Username: "tester"},
		})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	// Register the handlers without the JWT middleware; claims are injected above.
	group := engine.Group("/api/v1")
	group.POST("/hosts", srv.Service.CreateHost)
	group.GET("/hosts", srv.Service.ListHosts)
	group.GET("/hosts/:id", srv.Service.GetHost)
	group.PUT("/hosts/:id", srv.Service.UpdateHost)
	group.DELETE("/hosts/:id", srv.Service.DeleteHost)

	created := serveJSON(t, engine, http.MethodPost, "/api/v1/hosts", map[string]any{
		"name":      "db-01",
		"label":     "prod",
		"host_ip":   "10.0.0.11",
		"host_user": "root",
		"protocol":  "ssh",
	})
	require.Equal(t, 0, created.Code, "create failed: %+v", created)
	var host struct {
		ID       uint64 `json:"id"`
		HostPort uint16 `json:"host_port"`
	}
	require.NoError(t, json.Unmarshal(created.Data, &host))
	require.NotZero(t, host.ID)
	assert.EqualValues(t, 22, host.HostPort, "ssh port defaults to 22")

	list := serveJSON(t, engine, http.MethodGet, "/api/v1/hosts?page=1&page_size=10", nil)
	require.Equal(t, 0, list.Code)
	var page struct {
		Total int64 `json:"total"`
		List  []struct {
			Name string `json:"name"`
		} `json:"list"`
	}
	require.NoError(t, json.Unmarshal(list.Data, &page))
	assert.EqualValues(t, 1, page.Total)
	require.Len(t, page.List, 1)
	assert.Equal(t, "db-01", page.List[0].Name)

	updated := serveJSON(t, engine, http.MethodPut, "/api/v1/hosts/1", map[string]any{
		"name":      "db-02",
		"host_ip":   "10.0.0.11",
		"host_user": "root",
	})
	require.Equal(t, 0, updated.Code, "update failed: %+v", updated)

	got := serveJSON(t, engine, http.MethodGet, "/api/v1/hosts/1", nil)
	require.Equal(t, 0, got.Code)
	var detail struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		HostPort uint16 `json:"host_port"`
	}
	require.NoError(t, json.Unmarshal(got.Data, &detail))
	assert.Equal(t, "db-02", detail.Name)
	assert.Equal(t, "ssh", detail.Protocol, "omitted protocol must be preserved")
	assert.EqualValues(t, 22, detail.HostPort, "omitted port must be preserved")

	deleted := serveJSON(t, engine, http.MethodDelete, "/api/v1/hosts/1", nil)
	require.Equal(t, 0, deleted.Code)

	missing := serveJSON(t, engine, http.MethodGet, "/api/v1/hosts/1", nil)
	assert.NotEqual(t, 0, missing.Code)

	// Invalid query parameters must be rejected by binding.
	bad := serveJSON(t, engine, http.MethodGet, "/api/v1/hosts?protocol=ftp", nil)
	assert.NotEqual(t, 0, bad.Code)
}
