package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"grain/pkg/auth"
	"grain/pkg/db"
)

func TestData_Lifecycle(t *testing.T) {
	t.Run("NewData and UserCache accessors", func(t *testing.T) {
		uc := NewMemoryUserCache(0)
		d := NewData(
			&gorm.DB{},
			uc,
			nil,
			db.DBTimeout{},
			db.DBSlowThreshold{},
			auth.JWTConfig{},
		)

		assert.NotNil(t, d)
		assert.Equal(t, uc, d.UserCache())

		newUc := NewMemoryUserCache(0)
		d.SetUserCache(newUc)
		assert.Equal(t, newUc, d.UserCache())
	})

	t.Run("nil Data safe methods", func(t *testing.T) {
		var nilData *Data
		assert.Nil(t, nilData.UserCache())
		// should not panic
		nilData.SetUserCache(NewMemoryUserCache(0))
	})
}
