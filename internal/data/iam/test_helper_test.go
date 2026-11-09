package iam

import (
	"fmt"
	"testing"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"grain/internal/conf"
	"grain/pkg/auth"
	"grain/pkg/db"
)

// setupTestDB creates an isolated in-memory SQLite database and runs AutoMigrate.
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	c := &db.DBConf{
		Type:            "sqlite",
		Dsn:             fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString()),
		MaxIdleConns:    1,
		MaxOpenConns:    1,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := db.NewGormConfig(nil)
	gormDB, err := db.NewGormDB(c, gc)
	require.NoError(t, err)

	err = AutoMigrate(gormDB)
	require.NoError(t, err)

	return gormDB
}

// testBatchAdapter embeds stringadapter.Adapter and adds BatchAdapter methods.
type testBatchAdapter struct {
	*stringadapter.Adapter
}

func (a *testBatchAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return nil
}

func (a *testBatchAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return nil
}

// setupTestEnforcer initializes a Casbin SyncedEnforcer with the standard IAM RBAC model.
func setupTestEnforcer(t *testing.T) *casbin.SyncedEnforcer {
	t.Helper()

	cm, err := model.NewModelFromString(conf.DefaultRBACModel)
	require.NoError(t, err)

	adapter := &testBatchAdapter{Adapter: stringadapter.NewAdapter("p, _init_, /_init_, GET")}
	enf, err := casbin.NewSyncedEnforcer(cm, adapter)
	require.NoError(t, err)

	return enf
}

// setupTestData constructs a test Data container with SQLite DB, Casbin, and in-memory UserCache.
func setupTestData(t *testing.T) (*Data, *gorm.DB, *casbin.SyncedEnforcer, UserCache) {
	t.Helper()

	gormDB := setupTestDB(t)
	enf := setupTestEnforcer(t)
	uc := NewMemoryUserCache(0)

	data := NewData(
		gormDB,
		uc,
		enf,
		db.DBTimeout{},
		db.DBSlowThreshold{},
		auth.JWTConfig{},
	)

	return data, gormDB, enf, uc
}
