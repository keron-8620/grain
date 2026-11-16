package iam

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
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	biziam "grain/internal/biz/iam"
	"grain/internal/conf"
	dataiam "grain/internal/data/iam"
	serviceiam "grain/internal/service/iam"
	"grain/pkg/cryptoutil"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

type testBatchAdapter struct {
	*stringadapter.Adapter
}

func (a *testBatchAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return nil
}

func (a *testBatchAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return nil
}

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

	gc := db.NewGormConfig(nil)
	gormDB, err := db.NewGormDB(c, gc)
	require.NoError(t, err)

	err = dataiam.AutoMigrate(gormDB)
	require.NoError(t, err)

	return gormDB
}

func setupTestEnforcer(t *testing.T) *casbin.SyncedEnforcer {
	t.Helper()

	cm, err := model.NewModelFromString(conf.DefaultRBACModel)
	require.NoError(t, err)

	adapter := &testBatchAdapter{Adapter: stringadapter.NewAdapter("p, _init_, /_init_, GET")}
	enf, err := casbin.NewSyncedEnforcer(cm, adapter)
	require.NoError(t, err)

	return enf
}

func TestServer_New_Validation(t *testing.T) {
	_, err := New(Options{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "gorm DB is required")

	gormDB := setupTestDB(t)
	_, err = New(Options{GormDB: gormDB})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "casbin enforcer is required")
}

func TestServer_New_RequiresStableSigningKey(t *testing.T) {
	gormDB := setupTestDB(t)
	enf := setupTestEnforcer(t)

	_, err := New(Options{GormDB: gormDB, Enforcer: enf})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key")

	priv, pub, err := cryptoutil.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	srv, err := New(Options{GormDB: gormDB, Enforcer: enf, SigningKey: priv, VerifyKey: pub})
	require.NoError(t, err)
	require.NotNil(t, srv)
	assert.NotEmpty(t, srv.TokenManager.KeyID())
}

func TestServer_New_RejectsMismatchedPublicKey(t *testing.T) {
	gormDB := setupTestDB(t)
	enf := setupTestEnforcer(t)

	priv, _, err := cryptoutil.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	_, otherPub, err := cryptoutil.GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	_, err = New(Options{GormDB: gormDB, Enforcer: enf, SigningKey: priv, VerifyKey: otherPub})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestServer_InitServer_And_E2E(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gormDB := setupTestDB(t)
	enf := setupTestEnforcer(t)

	priv, pub, err := cryptoutil.GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	engine := gin.New()
	ctx := context.Background()

	bc := &conf.Bootstrap{
		Server: &conf.ServerConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
		Security: &conf.SecurityConfig{
			Token: conf.TokenConfig{
				AccessDuration:  time.Hour,
				RefreshDuration: 24 * time.Hour,
			},
			Login:    conf.LoginSecurityConfig{MaxFailedAttempts: 2, LockDuration: time.Hour},
			Password: conf.PasswordConfig{StrengthLevel: 2},
		},
	}

	srv, err := InitServer(ctx, engine, bc, nil, gormDB, enf, WithSigningKey(priv, pub))
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, srv.Service)
	require.NotNil(t, srv.Biz)
	require.NotNil(t, srv.Authenticator)

	// 1. 创建管理员角色并赋予权限
	role, err := srv.Biz.Role.Create(ctx, &biziam.Role{
		Name: "SuperAdmin",
	})
	require.NoError(t, err)

	// 2. 创建用户（密码策略 level 2 要求字母+数字）
	_, err = srv.Biz.User.Create(ctx, &biziam.User{
		Username: "weak_user",
		RoleID:   role.ID,
		IsActive: true,
	}, "abcdefgh")
	require.Error(t, err)
	require.True(t, errorx.IsCode(err, errorx.CodePasswordStrengthFailed))

	user, err := srv.Biz.User.Create(ctx, &biziam.User{
		Username: "admin_user",
		RoleID:   role.ID,
		IsActive: true,
	}, "admin123456")
	require.NoError(t, err)
	require.NotNil(t, user)

	// 3. 登录获取 Token
	loginBody, _ := json.Marshal(serviceiam.LoginReq{
		Username: "admin_user",
		Password: "admin123456",
	})
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	engine.ServeHTTP(wLogin, reqLogin)
	assert.Equal(t, http.StatusOK, wLogin.Code)

	var loginResp struct {
		Code int                  `json:"code"`
		Data serviceiam.LoginResp `json:"data"`
	}
	err = json.Unmarshal(wLogin.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	accessToken := loginResp.Data.Tokens.AccessToken
	assert.NotEmpty(t, accessToken)

	// 4. 访问受保护的 /api/v1/auth/me 端点
	reqMe := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+accessToken)
	wMe := httptest.NewRecorder()
	engine.ServeHTTP(wMe, reqMe)
	assert.Equal(t, http.StatusOK, wMe.Code)

	// 5. 访问未授权的 RBAC 端点 (角色还没有关联任何 API，应返回 403 Forbidden)
	reqUsers := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	reqUsers.Header.Set("Authorization", "Bearer "+accessToken)
	wUsers := httptest.NewRecorder()
	engine.ServeHTTP(wUsers, reqUsers)
	assert.Equal(t, http.StatusForbidden, wUsers.Code)

	// 6. 给角色分配 /api/v1/users 的权限并重试
	apiList, err := srv.Biz.Api.GetByURLAndMethod(ctx, "/api/v1/users", "GET")
	require.NoError(t, err)

	_, err = srv.Biz.Role.Update(ctx, &biziam.Role{
		ID:     role.ID,
		Name:   role.Name,
		ApiIDs: []uint64{apiList.ID},
	})
	require.NoError(t, err)

	// 角色权限更新后，该角色下用户旧 Token 自动被吊销，重新登录获取最新 Token
	reqLogin2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(loginBody))
	reqLogin2.Header.Set("Content-Type", "application/json")
	wLogin2 := httptest.NewRecorder()
	engine.ServeHTTP(wLogin2, reqLogin2)
	assert.Equal(t, http.StatusOK, wLogin2.Code)

	var loginResp2 struct {
		Code int                  `json:"code"`
		Data serviceiam.LoginResp `json:"data"`
	}
	_ = json.Unmarshal(wLogin2.Body.Bytes(), &loginResp2)
	newToken := loginResp2.Data.Tokens.AccessToken

	// 再次请求该受保护端点，应获得 200 OK
	reqUsersAuth := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	reqUsersAuth.Header.Set("Authorization", "Bearer "+newToken)
	wUsersAuth := httptest.NewRecorder()
	engine.ServeHTTP(wUsersAuth, reqUsersAuth)
	assert.Equal(t, http.StatusOK, wUsersAuth.Code)

	// 7. 测试 public-key 端点
	reqPubKey := httptest.NewRequest(http.MethodGet, "/api/v1/public-key", nil)
	wPubKey := httptest.NewRecorder()
	engine.ServeHTTP(wPubKey, reqPubKey)
	assert.Equal(t, http.StatusOK, wPubKey.Code)

	// 8. 测试 .well-known/jwks.json 端点
	reqJWKS := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	wJWKS := httptest.NewRecorder()
	engine.ServeHTTP(wJWKS, reqJWKS)
	assert.Equal(t, http.StatusOK, wJWKS.Code)

	// 9. 登录失败锁定：阈值 2 次，达到后正确密码也被拒绝
	badBody, _ := json.Marshal(serviceiam.LoginReq{Username: "admin_user", Password: "wrong-password"})
	for i := 0; i < 2; i++ {
		reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(badBody))
		reqBad.Header.Set("Content-Type", "application/json")
		wBad := httptest.NewRecorder()
		engine.ServeHTTP(wBad, reqBad)
		if i == 0 {
			assert.Equal(t, http.StatusUnauthorized, wBad.Code)
		} else {
			assert.Equal(t, http.StatusForbidden, wBad.Code)
		}
	}

	reqLocked := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(loginBody))
	reqLocked.Header.Set("Content-Type", "application/json")
	wLocked := httptest.NewRecorder()
	engine.ServeHTTP(wLocked, reqLocked)
	assert.Equal(t, http.StatusForbidden, wLocked.Code, "correct password must be rejected while locked")
}
