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
	"grain/pkg/auth"
	"grain/pkg/db"
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

func setupTestService(t *testing.T) (*Service, *biziam.Biz, *gorm.DB, biziam.TokenManager) {
	t.Helper()
	gin.SetMode(gin.TestMode)

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

	cm, err := model.NewModelFromString(conf.DefaultRBACModel)
	require.NoError(t, err)
	adapter := &testBatchAdapter{Adapter: stringadapter.NewAdapter("p, _init_, /_init_, GET")}
	enf, err := casbin.NewSyncedEnforcer(cm, adapter)
	require.NoError(t, err)

	userCache := dataiam.NewMemoryUserCache(0)
	data := dataiam.NewData(
		gormDB,
		userCache,
		enf,
		db.DBTimeout{},
		db.DBSlowThreshold{},
		auth.JWTConfig{},
	)

	userRepo := dataiam.NewUserRepo(data, nil, time.Hour, userCache)
	roleRepo := dataiam.NewRoleRepo(data, nil)
	menuRepo := dataiam.NewMenuRepo(data, nil)
	buttonRepo := dataiam.NewButtonRepo(data, nil)
	apiRepo := dataiam.NewApiRepo(data, nil)

	tokenMgr, err := biziam.NewTokenManager(biziam.TokenConfig{
		AccessDuration:  time.Hour,
		RefreshDuration: 24 * time.Hour,
	})
	require.NoError(t, err)

	userUC := biziam.NewUserUseCase(userRepo, roleRepo, nil)
	roleUC := biziam.NewRoleUseCase(roleRepo, userRepo, nil)
	menuUC := biziam.NewMenuUseCase(menuRepo, nil, buttonRepo)
	buttonUC := biziam.NewButtonUseCase(buttonRepo, menuRepo, nil)
	apiUC := biziam.NewApiUseCase(apiRepo, nil)
	authUC := biziam.NewAuthUseCase(userRepo, roleRepo, tokenMgr, nil, 24*time.Hour)

	biz := biziam.NewBiz(userUC, roleUC, menuUC, buttonUC, apiUC, authUC)
	svc := NewService(biz, nil)

	return svc, biz, gormDB, tokenMgr
}

func performRequest(r http.Handler, method, path string, body any, setContext ...func(*http.Request)) *httptest.ResponseRecorder {
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	for _, fn := range setContext {
		if fn != nil {
			fn(req)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAuthService(t *testing.T) {
	svc, biz, _, tokenMgr := setupTestService(t)
	ctx := context.Background()

	// 创建基础角色与用户
	role, err := biz.Role.Create(ctx, &biziam.Role{Name: "TesterRole"})
	require.NoError(t, err)

	user, err := biz.User.Create(ctx, &biziam.User{
		Username: "authuser",
		RoleID:   role.ID,
		IsActive: true,
	}, "password123")
	require.NoError(t, err)

	r := gin.New()
	r.POST("/login", svc.Login)
	r.POST("/refresh", svc.RefreshToken)
	r.GET("/public-key", svc.GetPublicKey)
	r.GET("/.well-known/jwks.json", svc.GetJWKS)

	// 带 auth claims 上下文的路由
	withAuth := r.Group("")
	withAuth.Use(func(c *gin.Context) {
		claims := &auth.JwtClaims{
			UserInfo: auth.UserInfo{
				UserID:   user.ID,
				Username: user.Username,
				RoleID:   user.RoleID,
			},
		}
		c.Request = c.Request.WithContext(auth.SetJwtClaims(c.Request.Context(), claims))
		c.Next()
	})
	withAuth.POST("/logout", svc.Logout)
	withAuth.GET("/me", svc.GetProfile)

	t.Run("Login success", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/login", LoginReq{
			Username: "authuser",
			Password: "password123",
		})
		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Code int       `json:"code"`
			Msg  string    `json:"msg"`
			Data LoginResp `json:"data"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.Code)
		assert.Equal(t, "authuser", resp.Data.User.Username)
		assert.NotEmpty(t, resp.Data.Tokens.AccessToken)
		assert.NotEmpty(t, resp.Data.Tokens.RefreshToken)
	})

	t.Run("Login invalid param", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/login", map[string]any{"username": ""})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Login wrong password", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/login", LoginReq{
			Username: "authuser",
			Password: "wrongpassword",
		})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("RefreshToken success", func(t *testing.T) {
		tokens, _, err := tokenMgr.IssueTokenPair(ctx, user, 0)
		require.NoError(t, err)

		w := performRequest(r, http.MethodPost, "/refresh", RefreshTokenReq{
			RefreshToken: tokens.RefreshToken,
		})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RefreshToken invalid", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/refresh", RefreshTokenReq{
			RefreshToken: "not.a.valid.jwt",
		})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Logout and GetProfile", func(t *testing.T) {
		wMe := performRequest(r, http.MethodGet, "/me", nil)
		assert.Equal(t, http.StatusOK, wMe.Code)

		wLogout := performRequest(r, http.MethodPost, "/logout", nil)
		assert.Equal(t, http.StatusOK, wLogout.Code)
	})

	t.Run("GetPublicKey and GetJWKS", func(t *testing.T) {
		wKey := performRequest(r, http.MethodGet, "/public-key", nil)
		assert.Equal(t, http.StatusOK, wKey.Code)

		wJWKS := performRequest(r, http.MethodGet, "/.well-known/jwks.json", nil)
		assert.Equal(t, http.StatusOK, wJWKS.Code)
	})
}

func TestUserService(t *testing.T) {
	svc, biz, _, _ := setupTestService(t)
	ctx := context.Background()

	role, err := biz.Role.Create(ctx, &biziam.Role{Name: "UserTestRole"})
	require.NoError(t, err)

	r := gin.New()
	r.POST("/users", svc.CreateUser)
	r.GET("/users", svc.ListUsers)
	r.GET("/users/:id", svc.GetUser)
	r.PUT("/users/:id", svc.UpdateUser)
	r.DELETE("/users/:id", svc.DeleteUser)
	r.POST("/users/:id/change-password", svc.ChangePassword)
	r.POST("/users/:id/reset-password", svc.ResetPassword)

	var createdID uint64

	t.Run("CreateUser success", func(t *testing.T) {
		isActive := true
		w := performRequest(r, http.MethodPost, "/users", CreateUserReq{
			Username: "bob",
			Password: "password123",
			RoleID:   role.ID,
			IsActive: &isActive,
		})
		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Code int       `json:"code"`
			Data *biziam.User `json:"data"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.Code)
		assert.Equal(t, "bob", resp.Data.Username)
		createdID = resp.Data.ID
	})

	t.Run("CreateUser duplicate conflict", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/users", CreateUserReq{
			Username: "bob",
			Password: "password123",
			RoleID:   role.ID,
		})
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("GetUser", func(t *testing.T) {
		w := performRequest(r, http.MethodGet, fmt.Sprintf("/users/%d", createdID), nil)
		assert.Equal(t, http.StatusOK, w.Code)

		w404 := performRequest(r, http.MethodGet, "/users/99999", nil)
		assert.Equal(t, http.StatusNotFound, w404.Code)
	})

	t.Run("UpdateUser", func(t *testing.T) {
		w := performRequest(r, http.MethodPut, fmt.Sprintf("/users/%d", createdID), UpdateUserReq{
			Username: "bob_updated",
		})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ListUsers", func(t *testing.T) {
		w := performRequest(r, http.MethodGet, "/users?page=1&page_size=10&username=bob", nil)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Code int            `json:"code"`
			Data UserPageResult `json:"data"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, resp.Data.Total, int64(1))
	})

	t.Run("ChangePassword and ResetPassword", func(t *testing.T) {
		wChange := performRequest(r, http.MethodPost, fmt.Sprintf("/users/%d/change-password", createdID), ChangePasswordReq{
			OldPassword: "password123",
			NewPassword: "newpassword123",
		})
		assert.Equal(t, http.StatusOK, wChange.Code)

		wReset := performRequest(r, http.MethodPost, fmt.Sprintf("/users/%d/reset-password", createdID), ResetPasswordReq{
			NewPassword: "resetpassword123",
		})
		assert.Equal(t, http.StatusOK, wReset.Code)
	})

	t.Run("DeleteUser", func(t *testing.T) {
		w := performRequest(r, http.MethodDelete, fmt.Sprintf("/users/%d", createdID), nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRoleService(t *testing.T) {
	svc, _, _, _ := setupTestService(t)

	r := gin.New()
	r.POST("/roles", svc.CreateRole)
	r.GET("/roles", svc.ListRoles)
	r.GET("/roles/:id", svc.GetRole)
	r.PUT("/roles/:id", svc.UpdateRole)
	r.DELETE("/roles/:id", svc.DeleteRole)

	var roleID uint64

	t.Run("CreateRole", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/roles", CreateRoleReq{
			Name:  "TestDevRole",
			Descr: "Developer role",
		})
		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Code int          `json:"code"`
			Data *biziam.Role `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		roleID = resp.Data.ID
	})

	t.Run("GetRole and ListRoles", func(t *testing.T) {
		wGet := performRequest(r, http.MethodGet, fmt.Sprintf("/roles/%d", roleID), nil)
		assert.Equal(t, http.StatusOK, wGet.Code)

		wList := performRequest(r, http.MethodGet, "/roles?name=Dev", nil)
		assert.Equal(t, http.StatusOK, wList.Code)
	})

	t.Run("UpdateRole", func(t *testing.T) {
		w := performRequest(r, http.MethodPut, fmt.Sprintf("/roles/%d", roleID), UpdateRoleReq{
			Name:  "TestDevRoleUpdated",
			Descr: "Updated descr",
		})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DeleteRole", func(t *testing.T) {
		w := performRequest(r, http.MethodDelete, fmt.Sprintf("/roles/%d", roleID), nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestMenuAndButtonService(t *testing.T) {
	svc, _, _, _ := setupTestService(t)

	r := gin.New()
	r.POST("/menus", svc.CreateMenu)
	r.GET("/menus", svc.ListMenus)
	r.GET("/menus/tree", svc.GetMenuTree)
	r.GET("/menus/:id", svc.GetMenu)
	r.PUT("/menus/:id", svc.UpdateMenu)
	r.DELETE("/menus/:id", svc.DeleteMenu)

	r.POST("/buttons", svc.CreateButton)
	r.GET("/buttons", svc.ListButtons)
	r.GET("/buttons/:id", svc.GetButton)
	r.PUT("/buttons/:id", svc.UpdateButton)
	r.DELETE("/buttons/:id", svc.DeleteButton)

	var menuID uint64
	var buttonID uint64

	t.Run("CreateMenu and GetMenuTree", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/menus", CreateMenuReq{
			Name:      "SystemMenu",
			Path:      "/sys",
			Component: "SysLayout",
			Meta: MenuMetaReq{
				Title: "系统",
				Icon:  "setting",
			},
			Sort: 1,
		})
		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Code int          `json:"code"`
			Data *biziam.Menu `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		menuID = resp.Data.ID

		wTree := performRequest(r, http.MethodGet, "/menus/tree", nil)
		assert.Equal(t, http.StatusOK, wTree.Code)
	})

	t.Run("CreateButton and ListButtons", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/buttons", CreateButtonReq{
			Name:   "btn:sys:view",
			MenuID: menuID,
			Sort:   1,
		})
		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Code int            `json:"code"`
			Data *biziam.Button `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		buttonID = resp.Data.ID

		wList := performRequest(r, http.MethodGet, fmt.Sprintf("/buttons?menu_id=%d", menuID), nil)
		assert.Equal(t, http.StatusOK, wList.Code)
	})

	t.Run("DeleteButton and DeleteMenu", func(t *testing.T) {
		// 先尝试删除存在关联按钮的菜单（应该失败）
		wFail := performRequest(r, http.MethodDelete, fmt.Sprintf("/menus/%d", menuID), nil)
		assert.Equal(t, http.StatusBadRequest, wFail.Code)

		// 删除按钮
		wDelBtn := performRequest(r, http.MethodDelete, fmt.Sprintf("/buttons/%d", buttonID), nil)
		assert.Equal(t, http.StatusOK, wDelBtn.Code)

		// 成功删除菜单
		wDelMenu := performRequest(r, http.MethodDelete, fmt.Sprintf("/menus/%d", menuID), nil)
		assert.Equal(t, http.StatusOK, wDelMenu.Code)
	})
}

func TestApiService(t *testing.T) {
	svc, _, _, _ := setupTestService(t)

	r := gin.New()
	r.POST("/apis", svc.CreateApi)
	r.GET("/apis", svc.ListApis)
	r.GET("/apis/:id", svc.GetApi)
	r.PUT("/apis/:id", svc.UpdateApi)
	r.DELETE("/apis/:id", svc.DeleteApi)
	r.POST("/apis/sync", svc.SyncApis)

	var apiID uint64

	t.Run("CreateApi and GetApi", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/apis", CreateApiReq{
			URL:    "/api/v1/orders",
			Method: "GET",
			Label:  "订单列表",
			Descr:  "获取订单列表",
		})
		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Code int         `json:"code"`
			Data *biziam.Api `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		apiID = resp.Data.ID

		wGet := performRequest(r, http.MethodGet, fmt.Sprintf("/apis/%d", apiID), nil)
		assert.Equal(t, http.StatusOK, wGet.Code)
	})

	t.Run("SyncApis", func(t *testing.T) {
		w := performRequest(r, http.MethodPost, "/apis/sync", SyncApisReq{
			Routes: []SyncRouteItem{
				{URL: "/api/v1/products", Method: "GET", Label: "产品列表"},
				{URL: "/api/v1/products", Method: "POST", Label: "创建产品"},
			},
		})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("UpdateApi and DeleteApi", func(t *testing.T) {
		wUp := performRequest(r, http.MethodPut, fmt.Sprintf("/apis/%d", apiID), UpdateApiReq{
			URL:    "/api/v1/orders",
			Method: "POST",
			Label:  "更新订单",
		})
		assert.Equal(t, http.StatusOK, wUp.Code)

		wDel := performRequest(r, http.MethodDelete, fmt.Sprintf("/apis/%d", apiID), nil)
		assert.Equal(t, http.StatusOK, wDel.Code)
	})
}
