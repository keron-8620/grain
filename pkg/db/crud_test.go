package db

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"

	"emperror.dev/errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type TestRole struct {
	BaseModel
	Name string `gorm:"column:name;size:50"`
}

type TestUser struct {
	StandardModel
	Name  string     `gorm:"column:name;size:50"`
	Email string     `gorm:"column:email;size:100"`
	Age   int        `gorm:"column:age"`
	Roles []TestRole `gorm:"many2many:test_user_roles;"`
}

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	c := &DBConf{
		Type:            "sqlite",
		Dsn:             fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString()),
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	gc := NewGormConfig(nil)
	db, err := NewGormDB(c, gc)
	require.NoError(t, err)

	err = db.AutoMigrate(&TestRole{}, &TestUser{})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = CloseGormDB(db)
	})

	return db
}

func setupTestDBWithLogger(t *testing.T) *gorm.DB {
	t.Helper()

	c := &DBConf{
		Type:            "sqlite",
		Dsn:             fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString()),
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}

	dbLog := log.New(os.Stdout, "[TEST_DB] ", log.LstdFlags)
	gc := NewGormConfig(dbLog)
	db, err := NewGormDB(c, gc)
	require.NoError(t, err)

	err = db.AutoMigrate(&TestRole{}, &TestUser{})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = CloseGormDB(db)
	})

	return db
}

// -------------------- contextError Tests --------------------

func TestContextError(t *testing.T) {
	t.Run("nil context error", func(t *testing.T) {
		assert.NoError(t, contextError(context.Background()))
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.ErrorIs(t, contextError(ctx), context.Canceled)
	})

	t.Run("deadline exceeded via context", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
		defer cancel()
		assert.ErrorIs(t, contextError(ctx), context.DeadlineExceeded)
	})
}

// -------------------- DBRecover Tests --------------------

func TestDBRecover(t *testing.T) {
	db := setupTestDBWithLogger(t)
	ctx := context.Background()

	t.Run("no panic does not modify err", func(t *testing.T) {
		var err error
		func() {
			defer DBRecover(ctx, db, &err)
		}()
		assert.NoError(t, err)
	})

	t.Run("panic with nil db sets err", func(t *testing.T) {
		var err error
		assert.NotPanics(t, func() {
			defer DBRecover(ctx, nil, &err)
			panic("panic without db")
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "recovered database panic")
	})

	t.Run("panic sets err and rolls back transaction", func(t *testing.T) {
		tx := db.Begin()
		require.NoError(t, tx.Error)

		var err error
		assert.NotPanics(t, func() {
			defer DBRecover(ctx, tx, &err)
			tx.Create(&TestUser{Name: "recover_user"})
			panic("simulated transaction failure for recover")
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "recovered database panic")

		var count int64
		require.NoError(t, db.Model(&TestUser{}).Where("name = ?", "recover_user").Count(&count).Error)
		assert.Equal(t, int64(0), count)
	})
}

// -------------------- withTransaction Tests --------------------

func TestWithTransaction(t *testing.T) {
	db := setupTestDB(t)

	t.Run("nil db returns error", func(t *testing.T) {
		err := withTransaction(context.Background(), nil, func(tx *gorm.DB) error {
			return nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database instance is nil")
	})

	t.Run("nil fn returns error", func(t *testing.T) {
		err := WithTransaction(context.Background(), db, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "transaction function is nil")
	})

	t.Run("nil context defaults to background", func(t *testing.T) {
		//nolint:staticcheck // testing explicit nil ctx behavior
		err := withTransaction(nil, db, func(tx *gorm.DB) error {
			return tx.Create(&TestUser{Name: "nil_ctx_user"}).Error
		})
		require.NoError(t, err)

		var count int64
		require.NoError(t, db.Model(&TestUser{}).Where("name = ?", "nil_ctx_user").Count(&count).Error)
		assert.Equal(t, int64(1), count)
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := withTransaction(ctx, db, func(tx *gorm.DB) error {
			return nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("panic inside fn is recovered and rolled back using inner tx", func(t *testing.T) {
		dbWithLog := setupTestDBWithLogger(t)
		err := withTransaction(context.Background(), dbWithLog, func(tx *gorm.DB) error {
			tx.Create(&TestUser{Name: "panic_rollback_user"})
			tx.Statement.SQL.WriteString("INSERT INTO test_users")
			panic("boom")
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database transaction panicked")

		var count int64
		require.NoError(t, dbWithLog.Model(&TestUser{}).Where("name = ?", "panic_rollback_user").Count(&count).Error)
		assert.Equal(t, int64(0), count)
	})

	t.Run("error returned by fn rolls back", func(t *testing.T) {
		err := withTransaction(context.Background(), db, func(tx *gorm.DB) error {
			tx.Create(&TestUser{Name: "err_rollback_user"})
			return errors.New("manual abort")
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "manual abort")

		var count int64
		require.NoError(t, db.Model(&TestUser{}).Where("name = ?", "err_rollback_user").Count(&count).Error)
		assert.Equal(t, int64(0), count)
	})
}

// -------------------- DBCreate Tests --------------------

func TestDBCreate(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("successful creation", func(t *testing.T) {
		user := &TestUser{Name: "alice", Email: "alice@example.com", Age: 25}
		err := DBCreate(ctx, db, &TestUser{}, user)
		require.NoError(t, err)
		assert.NotZero(t, user.ID)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		user := &TestUser{Name: "canceled"}
		err := DBCreate(canceledCtx, db, &TestUser{}, user)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("db failure on missing table", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		err := DBCreate(ctx, db, &NonExistent{}, &NonExistent{ID: 1})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create database record")
	})
}

// -------------------- DBCreateTX Tests --------------------

func TestDBCreateTX(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("successful transactional creation", func(t *testing.T) {
		user := &TestUser{Name: "bob", Email: "bob@example.com", Age: 30}
		err := DBCreateTX(ctx, db, &TestUser{}, user)
		require.NoError(t, err)
		assert.NotZero(t, user.ID)

		var found TestUser
		require.NoError(t, db.First(&found, user.ID).Error)
		assert.Equal(t, "bob", found.Name)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err := DBCreateTX(canceledCtx, db, &TestUser{}, &TestUser{Name: "bob_canceled"})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("transactional creation failure", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		err := DBCreateTX(ctx, db, &NonExistent{}, &NonExistent{ID: 1})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create database record")
	})

	t.Run("recovers panic as error", func(t *testing.T) {
		callbackName := "test:panic_before_create_tx"
		err := db.Callback().Create().Before("gorm:create").Register(callbackName, func(*gorm.DB) {
			panic("forced create panic")
		})
		require.NoError(t, err)
		defer func() {
			_ = db.Callback().Create().Remove(callbackName)
		}()

		err = DBCreateTX(ctx, db, &TestUser{}, &TestUser{Name: "panic_tx"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database transaction panicked")
	})
}

// -------------------- DBCreateRelationTx Tests --------------------

func TestDBCreateRelationTx(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("successful creation with relation", func(t *testing.T) {
		role1 := TestRole{Name: "admin"}
		role2 := TestRole{Name: "editor"}
		require.NoError(t, db.Create(&role1).Error)
		require.NoError(t, db.Create(&role2).Error)

		user := &TestUser{Name: "charlie", Email: "charlie@example.com", Age: 28}
		upmap := map[string]any{
			"Roles": []TestRole{role1, role2},
		}

		err := DBCreateRelationTx(ctx, db, &TestUser{}, user, upmap)
		require.NoError(t, err)
		assert.NotZero(t, user.ID)

		var fetched TestUser
		err = db.Preload("Roles").First(&fetched, user.ID).Error
		require.NoError(t, err)
		assert.Len(t, fetched.Roles, 2)
	})

	t.Run("avoids duplicate association creation when struct field is pre-populated", func(t *testing.T) {
		role1 := TestRole{Name: "role_pre_1"}
		role2 := TestRole{Name: "role_pre_2"}
		require.NoError(t, db.Create(&role1).Error)
		require.NoError(t, db.Create(&role2).Error)

		user := &TestUser{
			Name:  "prepopulated_user",
			Email: "prepopulated@example.com",
			Age:   26,
			Roles: []TestRole{role1, role2},
		}
		upmap := map[string]any{
			"Roles": []TestRole{role1, role2},
		}

		err := DBCreateRelationTx(ctx, db, &TestUser{}, user, upmap)
		require.NoError(t, err)
		assert.NotZero(t, user.ID)

		var fetched TestUser
		err = db.Preload("Roles").First(&fetched, user.ID).Error
		require.NoError(t, err)
		assert.Len(t, fetched.Roles, 2)
	})

	t.Run("empty relation map succeeds", func(t *testing.T) {
		user := &TestUser{Name: "david", Email: "david@example.com", Age: 22}
		err := DBCreateRelationTx(ctx, db, &TestUser{}, user, map[string]any{})
		require.NoError(t, err)
		assert.NotZero(t, user.ID)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err := DBCreateRelationTx(canceledCtx, db, &TestUser{}, &TestUser{Name: "david_canceled"}, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("creation failure on invalid model", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		err := DBCreateRelationTx(ctx, db, &NonExistent{}, &NonExistent{ID: 1}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create database record")
	})

	t.Run("relation update failure on invalid association name", func(t *testing.T) {
		user := &TestUser{Name: "bad_rel_user", Email: "bad_rel@example.com"}
		upmap := map[string]any{
			"NonExistentRelation": "value",
		}
		err := DBCreateRelationTx(ctx, db, &TestUser{}, user, upmap)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update association")
	})
}

// -------------------- DBUpdate Tests --------------------

func TestDBUpdate(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("successful update", func(t *testing.T) {
		user := &TestUser{Name: "update_user", Email: "update@example.com", Age: 20}
		require.NoError(t, db.Create(user).Error)

		rows, err := DBUpdate(ctx, db, &TestUser{}, map[string]any{"age": 21, "name": "updated_name"}, "id = ?", user.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(1), rows)

		var updated TestUser
		require.NoError(t, db.First(&updated, user.ID).Error)
		assert.Equal(t, 21, updated.Age)
		assert.Equal(t, "updated_name", updated.Name)
	})

	t.Run("empty data map is a no-op", func(t *testing.T) {
		rows, err := DBUpdate(ctx, db, &TestUser{}, map[string]any{}, "id = ?", 1)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), rows)
	})

	t.Run("missing where clause returns error", func(t *testing.T) {
		rows, err := DBUpdate(ctx, db, &TestUser{}, map[string]any{"age": 30})
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, gorm.ErrMissingWhereClause)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		rows, err := DBUpdate(canceledCtx, db, &TestUser{}, map[string]any{"age": 30}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("update failure on invalid table", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		rows, err := DBUpdate(ctx, db, &NonExistent{}, map[string]any{"id": 2}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.Contains(t, err.Error(), "failed to update database record")
	})
}

// -------------------- DBUpdateTx Tests --------------------

func TestDBUpdateTx(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("successful update in transaction", func(t *testing.T) {
		user := &TestUser{Name: "update_tx_user", Email: "tx@example.com", Age: 25}
		require.NoError(t, db.Create(user).Error)

		rows, err := DBUpdateTx(ctx, db, &TestUser{}, map[string]any{"age": 26}, "id = ?", user.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(1), rows)

		var updated TestUser
		require.NoError(t, db.First(&updated, user.ID).Error)
		assert.Equal(t, 26, updated.Age)
	})

	t.Run("empty data map is a no-op", func(t *testing.T) {
		rows, err := DBUpdateTx(ctx, db, &TestUser{}, map[string]any{}, "id = ?", 1)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), rows)
	})

	t.Run("missing where clause returns error", func(t *testing.T) {
		rows, err := DBUpdateTx(ctx, db, &TestUser{}, map[string]any{"age": 30})
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, gorm.ErrMissingWhereClause)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		rows, err := DBUpdateTx(canceledCtx, db, &TestUser{}, map[string]any{"age": 30}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("update tx failure on invalid table", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		rows, err := DBUpdateTx(ctx, db, &NonExistent{}, map[string]any{"id": 2}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.Contains(t, err.Error(), "failed to update database record")
	})
}

// -------------------- DBUpdateRelationTx Tests --------------------

func TestDBUpdateRelationTx(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("missing where clause returns error", func(t *testing.T) {
		err := DBUpdateRelationTx(ctx, db, &TestUser{}, map[string]any{"age": 30}, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, gorm.ErrMissingWhereClause)
	})

	t.Run("record not found returns error", func(t *testing.T) {
		err := DBUpdateRelationTx(ctx, db, &TestUser{}, map[string]any{"age": 30}, nil, "id = ?", 999999)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "record not found")
	})

	t.Run("successful update with data and relation replacement", func(t *testing.T) {
		role1 := TestRole{Name: "role1"}
		role2 := TestRole{Name: "role2"}
		role3 := TestRole{Name: "role3"}
		require.NoError(t, db.Create(&role1).Error)
		require.NoError(t, db.Create(&role2).Error)
		require.NoError(t, db.Create(&role3).Error)

		user := &TestUser{Name: "user_rel", Age: 20}
		require.NoError(t, db.Create(user).Error)
		require.NoError(t, db.Model(user).Association("Roles").Append([]TestRole{role1, role2}))

		data := map[string]any{"age": 22}
		upmap := map[string]any{
			"Roles": []TestRole{role3},
		}

		err := DBUpdateRelationTx(ctx, db, &TestUser{}, data, upmap, "id = ?", user.ID)
		require.NoError(t, err)

		var fetched TestUser
		require.NoError(t, db.Preload("Roles").First(&fetched, user.ID).Error)
		assert.Equal(t, 22, fetched.Age)
		require.Len(t, fetched.Roles, 1)
		assert.Equal(t, "role3", fetched.Roles[0].Name)
	})

	t.Run("successful update with empty data and relation replacement", func(t *testing.T) {
		role1 := TestRole{Name: "r1"}
		role2 := TestRole{Name: "r2"}
		require.NoError(t, db.Create(&role1).Error)
		require.NoError(t, db.Create(&role2).Error)

		user := &TestUser{Name: "user_empty_data", Age: 30}
		require.NoError(t, db.Create(user).Error)

		upmap := map[string]any{
			"Roles": []TestRole{role1, role2},
		}

		err := DBUpdateRelationTx(ctx, db, &TestUser{}, nil, upmap, "id = ?", user.ID)
		require.NoError(t, err)

		var fetched TestUser
		require.NoError(t, db.Preload("Roles").First(&fetched, user.ID).Error)
		assert.Len(t, fetched.Roles, 2)
	})

	t.Run("failure on invalid association", func(t *testing.T) {
		user := &TestUser{Name: "user_invalid_assoc"}
		require.NoError(t, db.Create(user).Error)

		upmap := map[string]any{
			"InvalidAssociation": "bad",
		}
		err := DBUpdateRelationTx(ctx, db, &TestUser{}, nil, upmap, "id = ?", user.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update association")
	})

	t.Run("failure on invalid query update", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		err := DBUpdateRelationTx(ctx, db, &NonExistent{}, map[string]any{"id": 1}, nil, "id = ?", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to query record")
	})

	t.Run("failure on invalid update data", func(t *testing.T) {
		user := &TestUser{Name: "err_update_user"}
		require.NoError(t, db.Create(user).Error)

		err := DBUpdateRelationTx(ctx, db, &TestUser{}, map[string]any{"non_existent_column": 1}, nil, "id = ?", user.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update database record")
	})

	t.Run("update condition column succeeds with relation replacement", func(t *testing.T) {
		role := TestRole{Name: "r_cond"}
		require.NoError(t, db.Create(&role).Error)

		user := &TestUser{Name: "old_cond_name", Age: 20}
		require.NoError(t, db.Create(user).Error)

		data := map[string]any{"name": "new_cond_name"}
		upmap := map[string]any{"Roles": []TestRole{role}}
		err := DBUpdateRelationTx(ctx, db, &TestUser{}, data, upmap, "name = ?", "old_cond_name")
		require.NoError(t, err)

		var fetched TestUser
		require.NoError(t, db.Preload("Roles").First(&fetched, user.ID).Error)
		assert.Equal(t, "new_cond_name", fetched.Name)
		require.Len(t, fetched.Roles, 1)
	})
}

// -------------------- DBDeleteTx Tests --------------------

func TestDBDeleteTx(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("missing where clause returns error", func(t *testing.T) {
		rows, err := DBDeleteTx(ctx, db, &TestUser{})
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, gorm.ErrMissingWhereClause)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		rows, err := DBDeleteTx(canceledCtx, db, &TestUser{}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("successful deletion", func(t *testing.T) {
		user := &TestUser{Name: "delete_user"}
		require.NoError(t, db.Create(user).Error)

		rows, err := DBDeleteTx(ctx, db, &TestUser{}, "id = ?", user.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(1), rows)

		var count int64
		require.NoError(t, db.Model(&TestUser{}).Where("id = ?", user.ID).Count(&count).Error)
		assert.Equal(t, int64(0), count)
	})

	t.Run("delete failure on invalid table", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		rows, err := DBDeleteTx(ctx, db, &NonExistent{}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.Contains(t, err.Error(), "failed to delete database record")
	})
}

// -------------------- DBDelete Tests --------------------

func TestDBDelete(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("missing where clause returns error", func(t *testing.T) {
		rows, err := DBDelete(ctx, db, &TestUser{})
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, gorm.ErrMissingWhereClause)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		rows, err := DBDelete(canceledCtx, db, &TestUser{}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("successful deletion", func(t *testing.T) {
		user := &TestUser{Name: "delete_user_plain"}
		require.NoError(t, db.Create(user).Error)

		rows, err := DBDelete(ctx, db, &TestUser{}, "id = ?", user.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(1), rows)

		var count int64
		require.NoError(t, db.Model(&TestUser{}).Where("id = ?", user.ID).Count(&count).Error)
		assert.Equal(t, int64(0), count)
	})

	t.Run("delete failure on invalid table", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		rows, err := DBDelete(ctx, db, &NonExistent{}, "id = ?", 1)
		require.Error(t, err)
		assert.Equal(t, int64(0), rows)
		assert.Contains(t, err.Error(), "failed to delete database record")
	})
}

// -------------------- DBGet Tests --------------------

func TestDBFindOne(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("successful get without preloads", func(t *testing.T) {
		user := &TestUser{Name: "get_user", Email: "get@example.com", Age: 33}
		require.NoError(t, db.Create(user).Error)

		var fetched TestUser
		err := DBFindOne(ctx, db, &fetched, nil, "id = ?", user.ID)
		require.NoError(t, err)
		assert.Equal(t, "get_user", fetched.Name)
		assert.Equal(t, 33, fetched.Age)
	})

	t.Run("successful get with preloads", func(t *testing.T) {
		role := TestRole{Name: "get_role"}
		require.NoError(t, db.Create(&role).Error)

		user := &TestUser{Name: "get_user_preload"}
		require.NoError(t, db.Create(user).Error)
		require.NoError(t, db.Model(user).Association("Roles").Append(&role))

		var fetched TestUser
		err := DBFindOne(ctx, db, &fetched, []string{"Roles"}, "id = ?", user.ID)
		require.NoError(t, err)
		assert.Len(t, fetched.Roles, 1)
		assert.Equal(t, "get_role", fetched.Roles[0].Name)
	})

	t.Run("record not found returns error", func(t *testing.T) {
		var fetched TestUser
		err := DBFindOne(ctx, db, &fetched, nil, "id = ?", 999999)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to query database record")
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		var fetched TestUser
		err := DBFindOne(canceledCtx, db, &fetched, nil, "id = ?", 1)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// -------------------- DBList Tests --------------------

func TestDBList(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	for i := 1; i <= 10; i++ {
		require.NoError(t, db.Create(&TestUser{
			Name:  fmt.Sprintf("user_%02d", i),
			Email: fmt.Sprintf("user_%02d@example.com", i),
			Age:   20 + i,
		}).Error)
	}

	t.Run("query with conditions and sorting", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			Filters: []ListFilter{
				{Field: "name", Op: ListFilterEquals, Value: "user_03"},
			},
			OrderBy: []string{"age DESC"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "user_03", users[0].Name)
	})

	t.Run("query with limit and offset", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			OrderBy: []string{"id ASC"},
			Limit:   3,
			Offset:  2,
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.NoError(t, err)
		require.Len(t, users, 3)
		assert.Equal(t, "user_03", users[0].Name)
		assert.Equal(t, "user_04", users[1].Name)
		assert.Equal(t, "user_05", users[2].Name)
	})

	t.Run("query with specific columns", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			Columns: []string{"name"},
			Limit:   2,
			OrderBy: []string{"id ASC"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.NoError(t, err)
		require.Len(t, users, 2)
		assert.NotEmpty(t, users[0].Name)
		assert.Empty(t, users[0].Email)
		assert.Zero(t, users[0].Age)
	})

	t.Run("query with omit", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			Omit:    []string{"email"},
			Limit:   2,
			OrderBy: []string{"id ASC"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.NoError(t, err)
		require.Len(t, users, 2)
		assert.NotEmpty(t, users[0].Name)
		assert.Empty(t, users[0].Email)
		assert.NotZero(t, users[0].Age)
	})

	t.Run("query with preloads", func(t *testing.T) {
		role := TestRole{Name: "list_role"}
		require.NoError(t, db.Create(&role).Error)

		var firstUser TestUser
		require.NoError(t, db.First(&firstUser).Error)
		require.NoError(t, db.Model(&firstUser).Association("Roles").Append(&role))

		var users []TestUser
		query := QueryParams{
			Filters: []ListFilter{
				{Field: "id", Op: ListFilterEquals, Value: firstUser.ID},
			},
			Preloads: []string{"Roles"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.NoError(t, err)
		require.Len(t, users, 1)
		require.Len(t, users[0].Roles, 1)
		assert.Equal(t, "list_role", users[0].Roles[0].Name)
	})

	t.Run("query with structured filters and order validation", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			Filters: []ListFilter{
				{Field: "name", Op: ListFilterEquals, Value: "user_03"},
			},
			OrderBy: []string{"id DESC"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "user_03", users[0].Name)
	})

	t.Run("query with leading minus order normalizes to descending", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			OrderBy: []string{"-age"},
			Limit:   2,
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.NoError(t, err)
		require.Len(t, users, 2)
		assert.True(t, users[0].Age > users[1].Age)
	})

	t.Run("query with invalid columns returns error", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			Columns: []string{"name; DROP TABLE users;--"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
	})

	t.Run("query with invalid omit returns error", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			Omit: []string{"name; DROP TABLE users;--"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
	})

	t.Run("query with invalid order returns error", func(t *testing.T) {
		var users []TestUser
		query := QueryParams{
			OrderBy: []string{"name; DROP TABLE users;--"},
		}
		err := DBList(ctx, db, &TestUser{}, &users, query)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		var users []TestUser
		err := DBList(canceledCtx, db, &TestUser{}, &users, QueryParams{})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("db failure returns error", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		var list []NonExistent
		err := DBList(ctx, db, &NonExistent{}, &list, QueryParams{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to query database record")
	})
}

// -------------------- DBCount Tests --------------------

func TestDBCount(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		require.NoError(t, db.Create(&TestUser{
			Name: "count_user",
			Age:  20 + i,
		}).Error)
	}

	t.Run("count with single filter", func(t *testing.T) {
		count, err := DBCount(ctx, db, &TestUser{}, QueryParams{
			Filters: []ListFilter{
				{Field: "name", Op: ListFilterEquals, Value: "count_user"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, int64(5), count)
	})

	t.Run("count with multiple filters", func(t *testing.T) {
		count, err := DBCount(ctx, db, &TestUser{}, QueryParams{
			Filters: []ListFilter{
				{Field: "name", Op: ListFilterEquals, Value: "count_user"},
				{Field: "age", Op: ListFilterGreaterEquals, Value: 23},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, int64(3), count) // 23, 24, 25
	})

	t.Run("count with empty query params", func(t *testing.T) {
		count, err := DBCount(ctx, db, &TestUser{}, QueryParams{})
		require.NoError(t, err)
		assert.Equal(t, int64(5), count)
	})

	t.Run("count with invalid filter returns error", func(t *testing.T) {
		_, err := DBCount(ctx, db, &TestUser{}, QueryParams{
			Filters: []ListFilter{
				{Field: "name; DROP TABLE users;--", Op: ListFilterEquals, Value: "x"},
			},
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
	})

	t.Run("context canceled returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := DBCount(canceledCtx, db, &TestUser{}, QueryParams{})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("db failure returns error", func(t *testing.T) {
		type NonExistent struct {
			ID uint `gorm:"primaryKey"`
		}
		_, err := DBCount(ctx, db, &NonExistent{}, QueryParams{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to count database records")
	})
}

// -------------------- ValidateOrderBy Tests --------------------

func TestValidateOrderBy(t *testing.T) {
	t.Run("valid ordering clauses", func(t *testing.T) {
		valid := []string{
			"id ASC",
			"name desc",
			"users.created_at DESC",
			"score ASC, title DESC",
			"age",
		}
		assert.NoError(t, ValidateOrderBy(valid))
	})

	t.Run("empty clauses", func(t *testing.T) {
		assert.NoError(t, ValidateOrderBy(nil))
		assert.NoError(t, ValidateOrderBy([]string{"", "   "}))
	})

	t.Run("injection attempts rejected", func(t *testing.T) {
		injections := [][]string{
			{"id; DROP TABLE users;--"},
			{"id, (SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)"},
			{"id' OR '1'='1"},
			{"1id ASC"},
			{"id ASCENDING"},
			{"id desc, , name asc"},
			{"a.b.c DESC"},
		}
		for _, inj := range injections {
			err := ValidateOrderBy(inj)
			assert.Error(t, err, "expected error for %v", inj)
		}
	})

	t.Run("with allowed columns", func(t *testing.T) {
		allowed := []string{"id", "name", "created_at"}
		assert.NoError(t, ValidateOrderBy([]string{"id ASC", "users.name desc"}, allowed...))

		err := ValidateOrderBy([]string{"secret ASC"}, allowed...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not sortable")
	})
}

// -------------------- QueryParams.LogValue Tests --------------------

func TestQueryParams_LogValue(t *testing.T) {
	t.Run("nil receiver returns nil string value", func(t *testing.T) {
		var qp *QueryParams
		val := qp.LogValue()
		assert.Equal(t, slog.KindString, val.Kind())
		assert.Equal(t, "<nil>", val.String())
	})

	t.Run("non-nil receiver returns group value", func(t *testing.T) {
		qp := &QueryParams{
			Preloads: []string{"Roles", "Profile"},
			Filters: []ListFilter{
				{Field: "name", Op: ListFilterEquals, Value: "tester"},
				{Field: "age", Op: ListFilterGreaterEquals, Value: 30},
			},
			OrderBy: []string{"created_at DESC", "id ASC"},
			Limit:   20,
			Offset:  10,
			Omit:    []string{"password"},
			Columns: []string{"id", "name", "email"},
		}

		val := qp.LogValue()
		assert.Equal(t, slog.KindGroup, val.Kind())

		attrs := val.Group()
		attrMap := make(map[string]slog.Value, len(attrs))
		for _, a := range attrs {
			attrMap[a.Key] = a.Value
		}

		assert.Equal(t, "Roles,Profile", attrMap["preloads"].String())
		assert.Equal(t, "name = tester; age >= 30", attrMap["filters"].String())
		assert.Equal(t, "created_at DESC,id ASC", attrMap["order_by"].String())
		assert.Equal(t, int64(20), attrMap["limit"].Int64())
		assert.Equal(t, int64(10), attrMap["offset"].Int64())
		assert.Equal(t, "password", attrMap["omit"].String())
		assert.Equal(t, "id,name,email", attrMap["columns"].String())
		assert.NotContains(t, attrMap, "query")
	})

	t.Run("struct with filters returns group value", func(t *testing.T) {
		qp := &QueryParams{
			Filters: []ListFilter{
				{Field: "username", Op: ListFilterEquals, Value: "alice"},
			},
		}
		val := qp.LogValue()
		assert.Equal(t, slog.KindGroup, val.Kind())
	})

	t.Run("empty struct returns valid group value", func(t *testing.T) {
		qp := &QueryParams{}
		val := qp.LogValue()
		assert.Equal(t, slog.KindGroup, val.Kind())
	})
}

// -------------------- Model LogAttr Tests --------------------

func TestModelLogAttr(t *testing.T) {
	t.Run("BaseModel LogAttr", func(t *testing.T) {
		base := BaseModel{ID: 101}
		attr := base.LogAttr()[0]
		assert.Equal(t, "id", attr.Key)
		assert.Equal(t, uint64(101), attr.Value.Uint64())
	})

	t.Run("StandardModel LogAttr", func(t *testing.T) {
		now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
		std := StandardModel{
			BaseModel: BaseModel{ID: 202},
			CreatedAt: now,
			UpdatedAt: now,
		}
		attrs := std.LogAttr()
		require.Len(t, attrs, 3)
		assert.Equal(t, "id", attrs[0].Key)
		assert.Equal(t, uint64(202), attrs[0].Value.Uint64())
		assert.Equal(t, "created_at", attrs[1].Key)
		assert.Equal(t, now.Format(time.DateTime), attrs[1].Value.String())
		assert.Equal(t, "updated_at", attrs[2].Key)
		assert.Equal(t, now.Format(time.DateTime), attrs[2].Value.String())
	})

	t.Run("SoftDeleteModel LogAttr", func(t *testing.T) {
		now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
		delTime := time.Date(2026, 9, 14, 13, 0, 0, 0, time.UTC)

		// Un-deleted
		active := SoftDeleteModel{
			StandardModel: StandardModel{
				BaseModel: BaseModel{ID: 301},
				CreatedAt: now,
				UpdatedAt: now,
			},
		}
		activeAttrs := active.LogAttr()
		require.Len(t, activeAttrs, 3)
		assert.Equal(t, uint64(301), activeAttrs[0].Value.Uint64())

		// Soft-deleted
		deleted := SoftDeleteModel{
			StandardModel: StandardModel{
				BaseModel: BaseModel{ID: 302},
				CreatedAt: now,
				UpdatedAt: now,
			},
			DeletedAt: gorm.DeletedAt{Time: delTime, Valid: true},
		}
		delAttrs := deleted.LogAttr()
		require.Len(t, delAttrs, 4)
		assert.Equal(t, "deleted_at", delAttrs[3].Key)
		assert.Equal(t, delTime.Format(time.DateTime), delAttrs[3].Value.String())
	})
}

// -------------------- JoinUint Tests --------------------

func TestJoinUint64_And_JoinUint64(t *testing.T) {
	t.Run("JoinUint64 empty", func(t *testing.T) {
		assert.Equal(t, "", JoinUint64(nil, ","))
		assert.Equal(t, "", JoinUint64([]uint64{}, ","))
	})

	t.Run("JoinUint64 single", func(t *testing.T) {
		assert.Equal(t, "42", JoinUint64([]uint64{42}, ","))
	})

	t.Run("JoinUint64 multiple with max uint64", func(t *testing.T) {
		nums := []uint64{1, 4294967295, 100}
		assert.Equal(t, "1,4294967295,100", JoinUint64(nums, ","))
		assert.Equal(t, "1 - 4294967295 - 100", JoinUint64(nums, " - "))
	})

}

func TestMapTo_And_MapToUint64s(t *testing.T) {
	type item struct {
		id   uint64
		name string
	}
	items := []item{
		{id: 10, name: "ten"},
		{id: 20, name: "twenty"},
		{id: 30, name: "thirty"},
	}

	t.Run("MapTo generic", func(t *testing.T) {
		names := MapTo(items, func(i item) string { return i.name })
		assert.Equal(t, []string{"ten", "twenty", "thirty"}, names)
	})

	t.Run("MapToUint64s", func(t *testing.T) {
		ids := MapToUint64s(items, func(i item) uint64 { return i.id })
		assert.Equal(t, []uint64{10, 20, 30}, ids)

		empty := MapToUint64s([]item{}, func(i item) uint64 { return i.id })
		assert.Empty(t, empty)
	})
}

func TestWithTransaction_NestedSavepointPanic(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Outer transaction creates a user, inner nested transaction panics.
	// Because WithTransaction does not issue a duplicate full Rollback(),
	// only the inner savepoint is rolled back and the outer transaction can still commit!
	err := WithTransaction(ctx, db, func(outerTx *gorm.DB) error {
		if err := outerTx.Create(&TestUser{Name: "outer_survives"}).Error; err != nil {
			return err
		}

		innerErr := WithTransaction(ctx, outerTx, func(innerTx *gorm.DB) error {
			_ = innerTx.Create(&TestUser{Name: "inner_panics"}).Error
			panic("inner savepoint panic")
		})
		require.Error(t, innerErr)
		assert.Contains(t, innerErr.Error(), "database transaction panicked")

		// Outer transaction continues and commits
		return nil
	})
	require.NoError(t, err)

	var outerCount, innerCount int64
	require.NoError(t, db.Model(&TestUser{}).Where("name = ?", "outer_survives").Count(&outerCount).Error)
	require.NoError(t, db.Model(&TestUser{}).Where("name = ?", "inner_panics").Count(&innerCount).Error)
	assert.Equal(t, int64(1), outerCount, "outer transaction record should survive inner savepoint panic")
	assert.Equal(t, int64(0), innerCount, "inner savepoint record should be rolled back")
}

func TestDBUpdateRelationTx_InputValidation(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("nil db returns error", func(t *testing.T) {
		err := DBUpdateRelationTx(ctx, nil, &TestUser{}, map[string]any{"name": "x"}, nil, "id = ?", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database instance is nil")
	})

	t.Run("nil model returns error", func(t *testing.T) {
		err := DBUpdateRelationTx(ctx, db, nil, map[string]any{"name": "x"}, nil, "id = ?", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "model instance cannot be nil")
	})

	t.Run("canceled context returns error", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()
		err := DBUpdateRelationTx(canceledCtx, db, &TestUser{}, map[string]any{"name": "x"}, nil, "id = ?", 1)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestDBFind_And_DBFindOne(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	role := TestRole{Name: "admin_role"}
	require.NoError(t, db.Create(&role).Error)
	user := TestUser{Name: "find_target", Email: "find@example.com", Age: 28, Roles: []TestRole{role}}
	require.NoError(t, db.Create(&user).Error)

	t.Run("DBFind without preloads", func(t *testing.T) {
		var got TestUser
		err := DBFind(ctx, db, &got, "name = ?", "find_target")
		require.NoError(t, err)
		assert.Equal(t, "find@example.com", got.Email)
		assert.Empty(t, got.Roles)
	})

	t.Run("DBFindOne with preloads", func(t *testing.T) {
		var got TestUser
		err := DBFindOne(ctx, db, &got, []string{"Roles"}, "name = ?", "find_target")
		require.NoError(t, err)
		assert.Equal(t, "find@example.com", got.Email)
		require.Len(t, got.Roles, 1)
		assert.Equal(t, "admin_role", got.Roles[0].Name)
	})
}

func TestBuildQuery_AllowedOrderColumns(t *testing.T) {
	db := setupTestDB(t)
	allowed := NewColumnSet("id", "name", "age")

	t.Run("allowed order column succeeds", func(t *testing.T) {
		qp := QueryParams{
			OrderBy:             []string{"-age", "name asc"},
			AllowedOrderColumns: allowed,
		}
		q, err := BuildQuery(db, &TestUser{}, qp)
		require.NoError(t, err)
		assert.NotNil(t, q)
	})

	t.Run("disallowed order column fails with ErrInvalidListOption", func(t *testing.T) {
		qp := QueryParams{
			OrderBy:             []string{"email desc"},
			AllowedOrderColumns: allowed,
		}
		_, err := BuildQuery(db, &TestUser{}, qp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "not sortable")
	})
}

func TestBuildQuery_FilterAllowlistAndMapping(t *testing.T) {
	db := setupTestDB(t)

	t.Run("AllowedFilterColumns permits allowed column and rejects others", func(t *testing.T) {
		allowed := NewColumnSet("name", "age")
		qpOK := QueryParams{
			Filters:              []ListFilter{{Field: "name", Op: ListFilterEquals, Value: "alice"}},
			AllowedFilterColumns: allowed,
		}
		q, err := BuildQuery(db, &TestUser{}, qpOK)
		require.NoError(t, err)
		assert.NotNil(t, q)

		qpBad := QueryParams{
			Filters:              []ListFilter{{Field: "email", Op: ListFilterEquals, Value: "alice@example.com"}},
			AllowedFilterColumns: allowed,
		}
		_, err = BuildQuery(db, &TestUser{}, qpBad)
		require.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "not filterable")
	})

	t.Run("FilterColumnMap maps field to column and rejects undeclared fields", func(t *testing.T) {
		colMap := map[string]string{
			"user_name": "name",
		}
		qpOK := QueryParams{
			Filters:         []ListFilter{{Field: "user_name", Op: ListFilterEquals, Value: "alice"}},
			FilterColumnMap: colMap,
		}
		q, err := BuildQuery(db, &TestUser{}, qpOK)
		require.NoError(t, err)
		assert.NotNil(t, q)

		qpBad := QueryParams{
			Filters:         []ListFilter{{Field: "email", Op: ListFilterEquals, Value: "alice@example.com"}},
			FilterColumnMap: colMap,
		}
		_, err = BuildQuery(db, &TestUser{}, qpBad)
		require.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "not filterable")
	})
}

func TestDBListAndCount(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		require.NoError(t, db.Create(&TestUser{
			Name:  fmt.Sprintf("lc_user_%d", i),
			Email: fmt.Sprintf("lc_%d@example.com", i),
			Age:   20 + i,
		}).Error)
	}

	t.Run("returns total count and paginated slice", func(t *testing.T) {
		var users []TestUser
		total, err := DBListAndCount(ctx, db, &TestUser{}, &users, QueryParams{
			Filters: []ListFilter{
				{Field: "user_age", Op: ListFilterGreaterEquals, Value: 22},
			},
			FilterColumnMap:     map[string]string{"user_age": "age"},
			OrderBy:             []string{"-age"},
			AllowedOrderColumns: NewColumnSet("age", "id"),
			Limit:               2,
			Offset:              1,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(4), total) // ages 22, 23, 24, 25
		require.Len(t, users, 2)
		assert.Equal(t, 24, users[0].Age)
		assert.Equal(t, 23, users[1].Age)
	})

	t.Run("total zero short-circuits Find and resets non-empty slice", func(t *testing.T) {
		users := []TestUser{{Name: "stale"}}
		total, err := DBListAndCount(ctx, db, &TestUser{}, &users, QueryParams{
			Filters: []ListFilter{
				{Field: "name", Op: ListFilterEquals, Value: "non_existent"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, users)
	})

	t.Run("invalid order_by fails before query execution even when count would be zero", func(t *testing.T) {
		var users []TestUser
		_, err := DBListAndCount(ctx, db, &TestUser{}, &users, QueryParams{
			Filters: []ListFilter{
				{Field: "name", Op: ListFilterEquals, Value: "non_existent"},
			},
			OrderBy: []string{"age; DROP TABLE users"},
		})
		require.ErrorIs(t, err, ErrInvalidListOption)
	})
}

func TestNoDoubleWrapInsideRunDBOp(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	type NonExistent struct {
		ID uint `gorm:"primaryKey"`
	}

	err := RunDBOp(ctx, nil, nil, nil, OpWrite, "create item", func(dbCtx context.Context) error {
		return DBCreate(dbCtx, db, &NonExistent{}, &NonExistent{ID: 1})
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create item: database operation failed")
	assert.NotContains(t, err.Error(), "failed to create database record")
}
