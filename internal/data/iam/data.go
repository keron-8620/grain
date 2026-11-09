package iam

import (
	"github.com/casbin/casbin/v3"
	"gorm.io/gorm"

	"grain/pkg/auth"
	"grain/pkg/db"
)

// Data holds the long-lived storage clients shared by repos.
type Data struct {
	gormdb    *gorm.DB
	userCache UserCache
	enforcer  *casbin.SyncedEnforcer
	dbTimeout db.DBTimeout
	dbSlow    db.DBSlowThreshold
	jwtConf   auth.JWTConfig
}

func NewData(
	gormdb *gorm.DB,
	userCache UserCache,
	enforcer *casbin.SyncedEnforcer,
	dbTimeout db.DBTimeout,
	dbSlow db.DBSlowThreshold,
	jwtConf auth.JWTConfig,
) *Data {
	return &Data{
		gormdb:    gormdb,
		userCache: userCache,
		enforcer:  enforcer,
		dbTimeout: dbTimeout,
		dbSlow:    dbSlow,
		jwtConf:   jwtConf,
	}

}

// SetUserCache sets the user cache in Data.
func (d *Data) SetUserCache(cache UserCache) {
	if d != nil {
		d.userCache = cache
	}
}

// UserCache returns the user cache configured in Data.
func (d *Data) UserCache() UserCache {
	if d == nil {
		return nil
	}
	return d.userCache
}
