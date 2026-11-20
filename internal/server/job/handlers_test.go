package job

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bizjob "grain/internal/biz/job"
	"grain/pkg/auth"
)

func serveJobJSON(t *testing.T, engine *gin.Engine, method, path string, body any) apiEnvelope {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var env apiEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "body: %s", w.Body.String())
	return env
}

// TestScheduleHandlers exercises the schedule HTTP layer without the JWT
// middleware (authentication/authorization is covered by TestJobEndToEnd).
func TestScheduleHandlers(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := t.Context()

	script, err := srv.Scripts.Create(ctx, &bizjob.Script{
		Name:     "sched",
		Project:  "test",
		Label:    "demo",
		Language: "shell",
		Status:   true,
		Username: "tester",
	}, []byte("#!/bin/sh\necho scheduled\n"))
	require.NoError(t, err)

	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		ctx := auth.SetJwtClaims(c.Request.Context(), &auth.JwtClaims{
			UserInfo: auth.UserInfo{UserID: 1, Username: "tester"},
		})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	group := engine.Group("/api/v1")
	group.POST("/schedules", srv.Service.CreateSchedule)
	group.GET("/schedules", srv.Service.ListSchedules)
	group.GET("/schedules/:id", srv.Service.GetSchedule)
	group.PUT("/schedules/:id", srv.Service.UpdateSchedule)
	group.DELETE("/schedules/:id", srv.Service.DeleteSchedule)
	group.POST("/schedules/:id/enable", srv.Service.EnableSchedule)
	group.POST("/schedules/:id/disable", srv.Service.DisableSchedule)

	created := serveJobJSON(t, engine, http.MethodPost, "/api/v1/schedules", map[string]any{
		"name":          "nightly",
		"specification": "0 2 * * *",
		"script_id":     script.ID,
		"is_enabled":    false,
	})
	require.Equal(t, 0, created.Code, "create failed: %+v", created)
	var schedule struct {
		ID       uint64 `json:"id"`
		Username string `json:"username"`
	}
	require.NoError(t, json.Unmarshal(created.Data, &schedule))
	require.NotZero(t, schedule.ID)
	assert.Equal(t, "tester", schedule.Username)

	list := serveJobJSON(t, engine, http.MethodGet, "/api/v1/schedules?page=1&page_size=10", nil)
	require.Equal(t, 0, list.Code)

	enabled := serveJobJSON(t, engine, http.MethodPost, "/api/v1/schedules/1/enable", nil)
	require.Equal(t, 0, enabled.Code, "enable failed: %+v", enabled)

	disabled := serveJobJSON(t, engine, http.MethodPost, "/api/v1/schedules/1/disable", nil)
	require.Equal(t, 0, disabled.Code)

	updated := serveJobJSON(t, engine, http.MethodPut, "/api/v1/schedules/1", map[string]any{
		"name":          "nightly-v2",
		"specification": "30 3 * * *",
		"script_id":     script.ID,
		"is_enabled":    false,
	})
	require.Equal(t, 0, updated.Code, "update failed: %+v", updated)

	got := serveJobJSON(t, engine, http.MethodGet, "/api/v1/schedules/1", nil)
	require.Equal(t, 0, got.Code)
	var detail struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal(got.Data, &detail))
	assert.Equal(t, "nightly-v2", detail.Name)

	deleted := serveJobJSON(t, engine, http.MethodDelete, "/api/v1/schedules/1", nil)
	require.Equal(t, 0, deleted.Code)

	// Invalid cron expressions must be rejected by the use case.
	bad := serveJobJSON(t, engine, http.MethodPost, "/api/v1/schedules", map[string]any{
		"name":          "bad",
		"specification": "not-a-cron",
		"script_id":     script.ID,
	})
	assert.NotEqual(t, 0, bad.Code)
}
