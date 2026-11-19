package job

import (
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"

	"grain/pkg/db"
)

// Data holds the long-lived storage clients shared by repos.
type Data struct {
	gormdb    *gorm.DB
	dbTimeout db.DBTimeout
	dbSlow    db.DBSlowThreshold
	crontab   *cron.Cron
}

func NewData(
	gormdb *gorm.DB,
	dbTimeout db.DBTimeout,
	dbSlow db.DBSlowThreshold,
	crontab *cron.Cron,
) *Data {
	return &Data{
		gormdb:    gormdb,
		dbTimeout: dbTimeout,
		dbSlow:    dbSlow,
		crontab:   crontab,
	}
}
