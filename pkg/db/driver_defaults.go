//go:build !db_no_default_drivers

package db

import (
	"github.com/glebarez/sqlite"
	"gorm.io/driver/gaussdb"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

func init() {
	RegisterDriver("mysql", func(dsn string) gorm.Dialector {
		return mysql.Open(dsn)
	})
	RegisterDriver("postgres", func(dsn string) gorm.Dialector {
		return postgres.Open(dsn)
	})
	RegisterDriver("sqlite", func(dsn string) gorm.Dialector {
		return sqlite.Open(dsn)
	})
	RegisterDriver("sqlserver", func(dsn string) gorm.Dialector {
		return sqlserver.Open(dsn)
	})
	RegisterDriver("opengauss", func(dsn string) gorm.Dialector {
		return gaussdb.New(gaussdb.Config{
			DSN:                  dsn,
			PreferSimpleProtocol: true,
		})
	})
}
