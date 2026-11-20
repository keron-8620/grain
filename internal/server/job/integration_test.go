package job

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	biziam "grain/internal/biz/iam"
	"grain/internal/conf"
	dataiam "grain/internal/data/iam"
	datajob "grain/internal/data/job"
	iamserver "grain/internal/server/iam"
	serviceiam "grain/internal/service/iam"
	"grain/pkg/cryptoutil"
	"grain/pkg/db"
)

type apiEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func doJSON(t *testing.T, engine *gin.Engine, method, path, token string, body any) apiEnvelope {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var env apiEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "response body: %s", w.Body.String())
	return env
}

// TestJobEndToEnd wires IAM + job exactly like main.NewRouter and exercises the
// full path: login -> RBAC -> create script -> execute -> read record/log.
func TestJobEndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalStorage := conf.StorageDir
	storage := t.TempDir()
	conf.StorageDir = storage
	t.Cleanup(func() { conf.StorageDir = originalStorage })

	gormDB := setupJobTestDB(t)
	require.NoError(t, dataiam.AutoMigrate(gormDB))

	cm, err := model.NewModelFromString(conf.DefaultRBACModel)
	require.NoError(t, err)
	enforcer, err := casbin.NewSyncedEnforcer(cm)
	require.NoError(t, err)

	priv, pub, err := cryptoutil.GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	bc := &conf.Bootstrap{
		Server: &conf.ServerConfig{Host: "127.0.0.1", Port: 8080},
		IAM: &conf.IAMConfig{
			Token: conf.TokenConfig{
				AccessDuration:  time.Hour,
				RefreshDuration: 24 * time.Hour,
			},
			Login:    conf.LoginSecurityConfig{MaxFailedAttempts: 5, LockDuration: time.Minute},
			Password: conf.PasswordConfig{StrengthLevel: 1},
		},
	}

	engine := gin.New()
	ctx := context.Background()

	iamSrv, err := iamserver.InitServer(ctx, engine, bc, nil, gormDB, enforcer, iamserver.WithSigningKey(priv, pub))
	require.NoError(t, err)

	root := t.TempDir()
	store, err := datajob.NewLocalScriptStore(root)
	require.NoError(t, err)

	jobSrv, err := Init(ctx, engine, Options{
		GormDB:        gormDB,
		Bootstrap:     bc,
		Authenticator: iamSrv.Authenticator,
		Enforcer:      enforcer,
		Crontab:       cron.New(),
		ScriptStore:   store,
		ScriptRoot:    root,
	})
	require.NoError(t, err)
	require.NotNil(t, jobSrv)

	// Pick up the job routes in the API catalog (mirrors main.NewRouter).
	_, err = iamSrv.SyncGinRoutes(ctx, engine.Routes())
	require.NoError(t, err)

	role, err := iamSrv.Biz.Role.Create(ctx, &biziam.Role{Name: "JobAdmin"})
	require.NoError(t, err)
	_, err = iamSrv.Biz.User.Create(ctx, &biziam.User{
		Username: "job_admin",
		RoleID:   role.ID,
		IsActive: true,
	}, "admin123456")
	require.NoError(t, err)

	apis, _, err := iamSrv.Biz.Api.List(ctx, db.ListOptions{Offset: 0, PageSize: 100})
	require.NoError(t, err)
	apiIDs := make([]uint64, 0, len(apis))
	for i := range apis {
		apiIDs = append(apiIDs, apis[i].ID)
	}
	require.NotEmpty(t, apiIDs)

	_, err = iamSrv.Biz.Role.Update(ctx, &biziam.Role{
		ID:     role.ID,
		Name:   role.Name,
		ApiIDs: apiIDs,
	})
	require.NoError(t, err)

	login := doJSON(t, engine, http.MethodPost, "/api/v1/auth/login", "", serviceiam.LoginReq{
		Username: "job_admin",
		Password: "admin123456",
	})
	require.Equal(t, 0, login.Code, "login failed: %+v", login)

	var loginData struct {
		Tokens struct {
			AccessToken string `json:"access_token"`
		} `json:"tokens"`
	}
	require.NoError(t, json.Unmarshal(login.Data, &loginData))
	token := loginData.Tokens.AccessToken
	require.NotEmpty(t, token)

	// Create a script through the HTTP API.
	created := doJSON(t, engine, http.MethodPost, "/api/v1/scripts", token, map[string]any{
		"name":     "integration",
		"project":  "test",
		"label":    "demo",
		"language": "shell",
		"content":  "#!/bin/sh\necho integration-ok\n",
	})
	require.Equal(t, 0, created.Code, "create script failed: %+v", created)
	var script struct {
		ID uint64 `json:"id"`
	}
	require.NoError(t, json.Unmarshal(created.Data, &script))
	require.NotZero(t, script.ID)

	// Execute it locally and wait for completion.
	executed := doJSON(t, engine, http.MethodPost, "/api/v1/script-records", token, map[string]any{
		"script_id": script.ID,
		"timeout":   30,
	})
	require.Equal(t, 0, executed.Code, "execute failed: %+v", executed)
	var record struct {
		ID     uint64 `json:"id"`
		Status int    `json:"status"`
	}
	require.NoError(t, json.Unmarshal(executed.Data, &record))
	require.NotZero(t, record.ID)

	deadline := time.Now().Add(10 * time.Second)
	for {
		got := doJSON(t, engine, http.MethodGet, fmt.Sprintf("/api/v1/script-records/%d", record.ID), token, nil)
		require.Equal(t, 0, got.Code)
		var current struct {
			Status   int    `json:"status"`
			ExitCode int    `json:"exit_code"`
			LogName  string `json:"log_name"`
		}
		require.NoError(t, json.Unmarshal(got.Data, &current))
		if current.Status == 2 {
			assert.Equal(t, 0, current.ExitCode)
			break
		}
		if current.Status >= 3 {
			t.Fatalf("execution failed with status %d", current.Status)
		}
		if time.Now().After(deadline) {
			t.Fatalf("execution did not finish in time, last status %d", current.Status)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The log download endpoint is a file response; hit it directly and check the body.
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/script-records/%d/log", record.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "integration-ok")

	// Unauthenticated access must be rejected, not 404.
	anon := doJSON(t, engine, http.MethodGet, "/api/v1/scripts", "", nil)
	assert.NotEqual(t, 0, anon.Code)
}
