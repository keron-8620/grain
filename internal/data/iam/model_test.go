package iam

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/db"
)

func TestMetaSchemas(t *testing.T) {
	t.Run("NewMetaSchemas valid and invalid", func(t *testing.T) {
		m, err := NewMetaSchemas(`{"title":"Dashboard","icon":"home"}`)
		require.NoError(t, err)
		assert.Equal(t, "Dashboard", m.Title)
		assert.Equal(t, "home", m.Icon)

		_, err = NewMetaSchemas("")
		require.Error(t, err)

		_, err = NewMetaSchemas("{invalid-json")
		require.Error(t, err)
	})

	t.Run("Value and Scan", func(t *testing.T) {
		m := MetaSchemas{Title: "Users", Icon: "user"}
		val, err := m.Value()
		require.NoError(t, err)

		var m2 MetaSchemas
		err = m2.Scan(val)
		require.NoError(t, err)
		assert.Equal(t, m.Title, m2.Title)
		assert.Equal(t, m.Icon, m2.Icon)

		// Scan string
		var m3 MetaSchemas
		err = m3.Scan(string(val.([]byte)))
		require.NoError(t, err)
		assert.Equal(t, m.Title, m3.Title)

		// Scan nil
		err = m3.Scan(nil)
		require.NoError(t, err)
		assert.Empty(t, m3.Title)

		// Scan unsupported type
		err = m3.Scan(12345)
		require.Error(t, err)
	})

	t.Run("Json and LogValue", func(t *testing.T) {
		m := MetaSchemas{Title: "Roles", Icon: "lock"}
		assert.Contains(t, m.Json(), "Roles")

		lv := m.LogValue()
		assert.Equal(t, slog.KindGroup, lv.Kind())

		var nilM *MetaSchemas
		assert.Equal(t, "<nil>", nilM.LogValue().String())
	})
}

func TestPersistentModels_LogValueAndHelpers(t *testing.T) {
	t.Run("apiPO", func(t *testing.T) {
		po := &apiPO{
			StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 1}},
			URL:           "/test",
			Method:        "GET",
			Label:         "Test",
		}
		assert.Equal(t, "iam_api", po.TableName())
		assert.Equal(t, slog.KindGroup, po.LogValue().Kind())

		var nilPO *apiPO
		assert.Equal(t, "<nil>", nilPO.LogValue().String())

		upmap := po.ToUpdateMap()
		assert.Equal(t, "/test", upmap["url"])

		ids := listApiPOToUint64s([]apiPO{*po, {StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 2}}}})
		assert.Equal(t, []uint64{1, 2}, ids)
		assert.Empty(t, listApiPOToUint64s(nil))
	})

	t.Run("userPO", func(t *testing.T) {
		po := &userPO{
			StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 1}},
			Username:      "alice",
			IsActive:      true,
			RoleID:        2,
			Password:      "secret",
		}
		assert.Equal(t, "iam_user", po.TableName())
		assert.Equal(t, slog.KindGroup, po.LogValue().Kind())

		var nilPO *userPO
		assert.Equal(t, "<nil>", nilPO.LogValue().String())

		upmap := po.ToUpdateMap()
		assert.Equal(t, "alice", upmap["username"])
		assert.Equal(t, "secret", upmap["password"])
	})

	t.Run("rolePO", func(t *testing.T) {
		po := &rolePO{
			StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 1}},
			Name:          "admin",
			Descr:         "admin role",
			Apis:          []apiPO{{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 10}}}},
			Menus:         []menuPO{{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 20}}}},
			Buttons:       []buttonPO{{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 30}}}},
		}
		assert.Equal(t, "iam_role", po.TableName())
		assert.Equal(t, slog.KindGroup, po.LogValue().Kind())

		var nilPO *rolePO
		assert.Equal(t, "<nil>", nilPO.LogValue().String())

		upmap := po.ToUpdateMap()
		assert.Equal(t, "admin", upmap["name"])
	})

	t.Run("menuPO", func(t *testing.T) {
		parentID := uint64(5)
		po := &menuPO{
			StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 1}},
			Name:          "menu1",
			Path:          "/m1",
			Component:     "c1",
			ParentID:      &parentID,
			Apis:          []apiPO{{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 10}}}},
		}
		assert.Equal(t, "iam_menu", po.TableName())
		assert.Equal(t, slog.KindGroup, po.LogValue().Kind())

		var nilPO *menuPO
		assert.Equal(t, "<nil>", nilPO.LogValue().String())

		upmap := po.ToUpdateMap()
		assert.Equal(t, "menu1", upmap["name"])
	})

	t.Run("buttonPO", func(t *testing.T) {
		po := &buttonPO{
			StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 1}},
			Name:          "btn1",
			MenuID:        5,
			Apis:          []apiPO{{StandardModel: db.StandardModel{BaseModel: db.BaseModel{ID: 10}}}},
		}
		assert.Equal(t, "iam_button", po.TableName())
		assert.Equal(t, slog.KindGroup, po.LogValue().Kind())

		var nilPO *buttonPO
		assert.Equal(t, "<nil>", nilPO.LogValue().String())

		upmap := po.ToUpdateMap()
		assert.Equal(t, "btn1", upmap["name"])
	})

	t.Run("loginRecordPO, OutboxPO, RevisionPO", func(t *testing.T) {
		rec := &loginRecordPO{
			Username:  "alice",
			LoginAt:   time.Now(),
			IPAddress: "127.0.0.1",
			UserAgent: "Mozilla",
			Status:    true,
		}
		assert.Equal(t, "iam_login_record", rec.TableName())
		assert.Equal(t, slog.KindGroup, rec.LogValue().Kind())

		var nilRec *loginRecordPO
		assert.Equal(t, "<nil>", nilRec.LogValue().String())

		assert.Equal(t, "iam_token_revocation_outbox", TokenRevocationOutboxPO{}.TableName())
		assert.Equal(t, "iam_policy_revision", PolicyRevisionPO{}.TableName())

		assert.Empty(t, fmtTime(time.Time{}))
		assert.NotEmpty(t, fmtTime(time.Now()))
	})
}
