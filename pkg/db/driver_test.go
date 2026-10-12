package db

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestDriverRegistry_Defaults(t *testing.T) {
	drivers := RegisteredDrivers()
	assert.Contains(t, drivers, "mysql")
	assert.Contains(t, drivers, "postgres")
	assert.Contains(t, drivers, "sqlite")
	assert.Contains(t, drivers, "sqlserver")
	assert.Contains(t, drivers, "opengauss")

	// Case insensitivity
	fn, ok := GetDriver("SQLITE")
	assert.True(t, ok)
	require.NotNil(t, fn)

	dialector := fn(":memory:")
	assert.NotNil(t, dialector)

	fn2, ok2 := GetDriver("  MySql ")
	assert.True(t, ok2)
	assert.NotNil(t, fn2)
}

func TestDriverRegistry_CustomDriver(t *testing.T) {
	customCalled := false
	RegisterDriver("custom_mock", func(dsn string) gorm.Dialector {
		customCalled = true
		return sqlite.Open(dsn)
	})

	fn, ok := GetDriver("custom_mock")
	assert.True(t, ok)
	dialector := fn(":memory:")
	assert.True(t, customCalled)
	assert.NotNil(t, dialector)

	drivers := RegisteredDrivers()
	assert.Contains(t, drivers, "custom_mock")
}

func TestDriverRegistry_Panics(t *testing.T) {
	assert.Panics(t, func() {
		RegisterDriver("", func(dsn string) gorm.Dialector { return nil })
	})
	assert.Panics(t, func() {
		RegisterDriver("valid", nil)
	})
}
