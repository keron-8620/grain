package job

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

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

	gormDB, err := db.NewGormDB(c, db.NewGormConfig(nil))
	require.NoError(t, err)

	err = AutoMigrate(gormDB)
	require.NoError(t, err)

	return gormDB
}

// setupTestData constructs a Data container backed by an isolated SQLite database.
func setupTestData(t *testing.T) *Data {
	t.Helper()
	return NewData(setupTestDB(t), db.DBTimeout{}, db.DBSlowThreshold{}, nil)
}
