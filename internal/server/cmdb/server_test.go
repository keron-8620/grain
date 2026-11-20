package cmdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	bizcmdb "grain/internal/biz/cmdb"
	"grain/internal/conf"
	datacmdb "grain/internal/data/cmdb"
	"grain/pkg/db"
)

func setupCMDBTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	c := &db.DBConf{
		Type:         "sqlite",
		Dsn:          fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString()),
		MaxIdleConns: 1,
		MaxOpenConns: 1,
	}
	gormDB, err := db.NewGormDB(c, db.NewGormConfig(nil))
	require.NoError(t, err)
	require.NoError(t, datacmdb.AutoMigrate(gormDB))
	return gormDB
}

func TestServer_New_RequiresDB(t *testing.T) {
	_, err := New(Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gorm DB is required")
}

func TestServer_RegistersHostRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalStorage := conf.StorageDir
	conf.StorageDir = t.TempDir()
	t.Cleanup(func() { conf.StorageDir = originalStorage })

	srv, err := New(Options{GormDB: setupCMDBTestDB(t), Bootstrap: &conf.Bootstrap{}})
	require.NoError(t, err)

	engine := gin.New()
	srv.RegisterRoutes(engine)

	routes := make(map[string]struct{}, len(engine.Routes()))
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}
	for _, route := range []string{
		"POST /api/v1/hosts",
		"GET /api/v1/hosts",
		"GET /api/v1/hosts/:id",
		"PUT /api/v1/hosts/:id",
		"POST /api/v1/hosts/:id/refresh-key",
		"DELETE /api/v1/hosts/:id",
	} {
		_, ok := routes[route]
		assert.True(t, ok, "route %q must be registered", route)
	}
}

func TestServer_HostLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalStorage := conf.StorageDir
	storage := t.TempDir()
	conf.StorageDir = storage
	t.Cleanup(func() { conf.StorageDir = originalStorage })

	srv, err := New(Options{GormDB: setupCMDBTestDB(t), Bootstrap: &conf.Bootstrap{}})
	require.NoError(t, err)

	ctx := context.Background()
	host, err := srv.Hosts.Create(ctx, &bizcmdb.Host{
		Name:     "web-01",
		Label:    "prod",
		HostIP:   "127.0.0.1",
		HostUser: "root",
		Protocol: "ssh",
	})
	require.NoError(t, err)
	assert.Equal(t, uint16(22), host.HostPort)

	varsPath := filepath.Join(storage, "host_vars", fmt.Sprintf("host_%d.yaml", host.ID))
	_, err = os.Stat(varsPath)
	require.NoError(t, err, "ansible host vars must be exported")

	list, total, err := srv.Hosts.List(ctx, db.ListOptions{Offset: 0, PageSize: 20})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, list, 1)
	assert.Equal(t, "web-01", list[0].Name)

	require.NoError(t, srv.Hosts.Delete(ctx, host.ID))
	_, err = os.Stat(varsPath)
	assert.True(t, os.IsNotExist(err), "host vars must be removed with the host")
}
