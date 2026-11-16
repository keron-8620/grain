package iam

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	biziam "grain/internal/biz/iam"
	"grain/internal/conf"
	dataiam "grain/internal/data/iam"
	"grain/internal/middleware"
	serviceiam "grain/internal/service/iam"
	"grain/pkg/auth"
	"grain/pkg/cryptoutil"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// Server 封装 IAM 服务的核心组件与运行实例
type Server struct {
	Data          *dataiam.Data
	Biz           *biziam.Biz
	Service       *serviceiam.Service
	Authenticator *auth.Authenticator
	Enforcer      *casbin.SyncedEnforcer
	TokenManager  biziam.TokenManager
	Logger        *slog.Logger
	Config        *conf.Bootstrap
}

// Options 用于初始化 IAM 服务的配置项
type Options struct {
	GormDB      *gorm.DB
	Enforcer    *casbin.SyncedEnforcer
	Bootstrap   *conf.Bootstrap
	Logger      *slog.Logger
	RedisClient redis.UniversalClient
	UserCache   dataiam.UserCache
	TokenStore  auth.TokenVersionStore
	SigningKey  crypto.PrivateKey
	VerifyKey   crypto.PublicKey
	KeyID       string
	Issuer      string
	Audience    string
}

// Option 函数式配置选项
type Option func(*Options)

// WithLogger 配置自定义日志记录器
func WithLogger(logger *slog.Logger) Option {
	return func(o *Options) {
		if logger != nil {
			o.Logger = logger
		}
	}
}

// WithRedisClient 配置 Redis 客户端用于分布式缓存
func WithRedisClient(client redis.UniversalClient) Option {
	return func(o *Options) {
		o.RedisClient = client
	}
}

// WithUserCache 配置自定义用户缓存实现
func WithUserCache(cache dataiam.UserCache) Option {
	return func(o *Options) {
		o.UserCache = cache
	}
}

// WithSigningKey 配置 JWT 签名私钥与公钥
func WithSigningKey(privKey crypto.PrivateKey, pubKey crypto.PublicKey, kid ...string) Option {
	return func(o *Options) {
		o.SigningKey = privKey
		o.VerifyKey = pubKey
		if len(kid) > 0 {
			o.KeyID = kid[0]
		}
	}
}

func WithIssuer(issuer string) Option {
	return func(o *Options) { o.Issuer = issuer }
}

func WithAudience(audience string) Option {
	return func(o *Options) { o.Audience = audience }
}

func signingMethodMatchesKey(method jwt.SigningMethod, priv crypto.PrivateKey, pub crypto.PublicKey) error {
	switch method.Alg() {
	case jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg(), jwt.SigningMethodPS256.Alg(), jwt.SigningMethodPS384.Alg(), jwt.SigningMethodPS512.Alg():
		if _, ok := priv.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("jwt method %s requires RSA signing key", method.Alg())
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("jwt method %s requires RSA verification key", method.Alg())
		}
	case jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg():
		if _, ok := priv.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("jwt method %s requires ECDSA signing key", method.Alg())
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("jwt method %s requires ECDSA verification key", method.Alg())
		}
	case jwt.SigningMethodEdDSA.Alg():
		if _, ok := priv.(ed25519.PrivateKey); !ok {
			return fmt.Errorf("jwt method %s requires Ed25519 signing key", method.Alg())
		}
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return fmt.Errorf("jwt method %s requires Ed25519 verification key", method.Alg())
		}
	default:
		return fmt.Errorf("unsupported JWT signing method %q", method.Alg())
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	ader, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bder, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return string(ader) == string(bder)
}

// repoTokenVersionStore 适配器：将 biz.UserRepo 桥接为 auth.TokenVersionStore
type repoTokenVersionStore struct {
	repo biziam.UserRepo
}

func (s *repoTokenVersionStore) GetTokenVersion(ctx context.Context, userID uint64) (uint64, error) {
	if s.repo == nil {
		return 0, auth.ErrTokenVersionNotFound
	}
	ver, err := s.repo.GetTokenVersion(ctx, userID)
	if err != nil {
		if errorx.IsRecordNotFound(err) {
			return 0, auth.ErrTokenVersionNotFound
		}
		return 0, err
	}
	return ver, nil
}

// New 初始化并构建完整的 IAM Server 实例
func New(opts Options) (*Server, error) {
	if opts.GormDB == nil {
		return nil, fmt.Errorf("iam server: gorm DB is required")
	}
	if opts.Enforcer == nil {
		return nil, fmt.Errorf("iam server: casbin enforcer is required")
	}

	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Bootstrap == nil {
		opts.Bootstrap = &conf.Bootstrap{}
	}
	if opts.Bootstrap.Security == nil {
		opts.Bootstrap.Security = &conf.SecurityConfig{}
	}
	if opts.Issuer == "" {
		opts.Issuer = opts.Bootstrap.Security.Token.Issuer
	}
	if opts.Issuer == "" {
		opts.Issuer = "iam.grain.com"
	}
	if opts.Audience == "" {
		opts.Audience = opts.Bootstrap.Security.Token.Audience
	}
	if opts.Audience == "" {
		opts.Audience = "grain-api"
	}

	if opts.SigningKey == nil {
		return nil, fmt.Errorf("iam server: stable JWT signing key is required; configure security.token.private_key")
	}
	derivedPublicKey, err := cryptoutil.ExtractPublicKey(opts.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("iam server: failed to extract public key: %w", err)
	}
	if opts.VerifyKey == nil {
		opts.VerifyKey = derivedPublicKey
	} else if !publicKeysEqual(derivedPublicKey, opts.VerifyKey) {
		return nil, fmt.Errorf("iam server: configured JWT public key does not match signing key")
	}
	if opts.KeyID == "" {
		kid, err := auth.KeyID(opts.VerifyKey)
		if err != nil {
			return nil, fmt.Errorf("iam server: failed to derive JWT key ID: %w", err)
		}
		opts.KeyID = kid
	}

	// 2. 初始化 UserCache
	if opts.UserCache == nil {
		if opts.RedisClient != nil {
			opts.UserCache = dataiam.NewRedisUserCache(opts.RedisClient)
		} else {
			opts.UserCache = dataiam.NewMemoryUserCache(time.Minute)
		}
	}

	// 3. 获取超时与有效期参数
	dbTimeout := db.DBTimeout{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ListTimeout:  30 * time.Second,
	}
	slow := 200 * time.Millisecond
	if opts.Bootstrap.Database != nil && opts.Bootstrap.Database.SlowThreshold > 0 {
		slow = opts.Bootstrap.Database.SlowThreshold
	}
	dbSlow := db.DBSlowThreshold{
		ReadSlow:  slow,
		WriteSlow: slow,
		ListSlow:  slow,
	}

	accessDuration := opts.Bootstrap.Security.Token.AccessDuration
	if accessDuration <= 0 {
		accessDuration = 2 * time.Hour
	}
	refreshDuration := opts.Bootstrap.Security.Token.RefreshDuration
	if refreshDuration <= 0 {
		refreshDuration = 7 * 24 * time.Hour
	}

	method, err := conf.SigningMethod(opts.Bootstrap.Security.Token.AccessMethod)
	if err != nil {
		return nil, err
	}
	if err := signingMethodMatchesKey(method, opts.SigningKey, opts.VerifyKey); err != nil {
		return nil, err
	}
	jwtConf := auth.NewJWTConfig(opts.Issuer, opts.Audience, opts.VerifyKey, method)
	data := dataiam.NewData(opts.GormDB, opts.UserCache, opts.Enforcer, dbTimeout, dbSlow, jwtConf)

	userRepo := dataiam.NewUserRepo(data, opts.Logger, refreshDuration, opts.UserCache)
	roleRepo := dataiam.NewRoleRepo(data, opts.Logger)
	menuRepo := dataiam.NewMenuRepo(data, opts.Logger)
	buttonRepo := dataiam.NewButtonRepo(data, opts.Logger)
	apiRepo := dataiam.NewApiRepo(data, opts.Logger)

	// 5. 初始化 TokenVersionStore 与 Authenticator
	tokenStore := opts.TokenStore
	if tokenStore == nil {
		tokenStore = &repoTokenVersionStore{repo: userRepo}
	}

	authenticator, err := auth.NewAuthenticator(jwtConf, tokenStore, opts.Logger)
	if err != nil {
		return nil, fmt.Errorf("iam server: failed to create authenticator: %w", err)
	}

	// 6. 初始化 TokenManager
	tokenMgr, err := biziam.NewTokenManager(biziam.TokenConfig{
		Issuer:          opts.Issuer,
		Audience:        opts.Audience,
		AccessDuration:  accessDuration,
		RefreshDuration: refreshDuration,
		SigningMethod:   method,
		SigningKey:      opts.SigningKey,
		VerifyKey:       opts.VerifyKey,
		KeyID:           opts.KeyID,
		Authenticator:   authenticator,
	})
	if err != nil {
		return nil, fmt.Errorf("iam server: failed to create token manager: %w", err)
	}

	// 7. 初始化业务层 UseCase 与 Biz 聚合
	passwordPolicy := biziam.PasswordPolicy{
		StrengthLevel: opts.Bootstrap.Security.Password.StrengthLevel,
	}
	if err := passwordPolicy.ValidateLevel(); err != nil {
		return nil, fmt.Errorf("iam server: %w", err)
	}
	userUC := biziam.NewUserUseCase(userRepo, roleRepo, opts.Logger, passwordPolicy)
	roleUC := biziam.NewRoleUseCase(roleRepo, userRepo, opts.Logger)
	menuUC := biziam.NewMenuUseCase(menuRepo, opts.Logger, buttonRepo)
	buttonUC := biziam.NewButtonUseCase(buttonRepo, menuRepo, opts.Logger)
	apiUC := biziam.NewApiUseCase(apiRepo, opts.Logger)
	authUC := biziam.NewAuthUseCaseWithConfig(userRepo, roleRepo, tokenMgr, opts.Logger, biziam.AuthUseCaseConfig{
		RefreshTTL:        refreshDuration,
		MaxFailedAttempts: opts.Bootstrap.Security.Login.MaxFailedAttempts,
		LockDuration:      opts.Bootstrap.Security.Login.LockDuration,
	})
	biz := biziam.NewBiz(userUC, roleUC, menuUC, buttonUC, apiUC, authUC)

	// 8. 初始化服务层 Service
	svc := serviceiam.NewService(biz, opts.Logger)

	return &Server{
		Data:          data,
		Biz:           biz,
		Service:       svc,
		Authenticator: authenticator,
		Enforcer:      opts.Enforcer,
		TokenManager:  tokenMgr,
		Logger:        opts.Logger,
		Config:        opts.Bootstrap,
	}, nil
}

// RegisterRoutes 在给定的 Gin 路由器上注册 IAM 的所有 HTTP API 路由
func (s *Server) RegisterRoutes(r gin.IRouter, prefix ...string) {
	basePrefix := "/api/v1"
	if len(prefix) > 0 && prefix[0] != "" {
		basePrefix = prefix[0]
	}

	// 1. 公开接口 (无需认证)
	public := r.Group(basePrefix)
	{
		public.POST("/auth/login", s.Service.Login)
		public.POST("/auth/refresh", s.Service.RefreshToken)
		public.GET("/public-key", s.Service.GetPublicKey)
	}
	// RFC 7517 标准 JWKS 端点 (直接挂在根路径)
	r.GET("/.well-known/jwks.json", s.Service.GetJWKS)

	// 2. 基础受保护接口 (需登录凭证，无需 RBAC 权限)
	authed := r.Group(basePrefix)
	authed.Use(middleware.JWTAuthMiddleware(s.Logger, s.Authenticator))
	{
		authed.POST("/auth/logout", s.Service.Logout)
		authed.GET("/auth/me", s.Service.GetProfile)
	}

	// 3. RBAC 权限保护接口 (需登录凭证 + Casbin 鉴权)
	rbac := r.Group(basePrefix)
	rbac.Use(middleware.JWTAuthMiddleware(s.Logger, s.Authenticator))
	rbac.Use(middleware.CasbinAuthMiddleware(s.Logger, s.Enforcer))
	{
		// 用户管理接口
		rbac.POST("/users", s.Service.CreateUser)
		rbac.GET("/users", s.Service.ListUsers)
		rbac.GET("/users/:id", s.Service.GetUser)
		rbac.PUT("/users/:id", s.Service.UpdateUser)
		rbac.DELETE("/users/:id", s.Service.DeleteUser)
		rbac.POST("/users/:id/change-password", s.Service.ChangePassword)
		rbac.POST("/users/:id/reset-password", s.Service.ResetPassword)

		// 角色管理接口
		rbac.POST("/roles", s.Service.CreateRole)
		rbac.GET("/roles", s.Service.ListRoles)
		rbac.GET("/roles/:id", s.Service.GetRole)
		rbac.PUT("/roles/:id", s.Service.UpdateRole)
		rbac.DELETE("/roles/:id", s.Service.DeleteRole)

		// 菜单管理接口
		rbac.POST("/menus", s.Service.CreateMenu)
		rbac.GET("/menus", s.Service.ListMenus)
		rbac.GET("/menus/tree", s.Service.GetMenuTree)
		rbac.GET("/menus/:id", s.Service.GetMenu)
		rbac.PUT("/menus/:id", s.Service.UpdateMenu)
		rbac.DELETE("/menus/:id", s.Service.DeleteMenu)

		// 按钮管理接口
		rbac.POST("/buttons", s.Service.CreateButton)
		rbac.GET("/buttons", s.Service.ListButtons)
		rbac.GET("/buttons/:id", s.Service.GetButton)
		rbac.PUT("/buttons/:id", s.Service.UpdateButton)
		rbac.DELETE("/buttons/:id", s.Service.DeleteButton)

		// API 资源接口
		rbac.POST("/apis", s.Service.CreateApi)
		rbac.GET("/apis", s.Service.ListApis)
		rbac.GET("/apis/:id", s.Service.GetApi)
		rbac.PUT("/apis/:id", s.Service.UpdateApi)
		rbac.DELETE("/apis/:id", s.Service.DeleteApi)
		rbac.POST("/apis/sync", s.Service.SyncApis)
	}
}

// SyncGinRoutes 从 Gin 路由引擎中提取已注册的路由并同步到 API 权限目录与 Casbin
func (s *Server) SyncGinRoutes(ctx context.Context, routes gin.RoutesInfo, prefixFilter ...string) (int, error) {
	prefix := "/api/v1"
	if len(prefixFilter) > 0 {
		prefix = prefixFilter[0]
	}

	var apiRoutes []biziam.ApiRoute
	for _, r := range routes {
		if prefix == "" || strings.HasPrefix(r.Path, prefix) {
			apiRoutes = append(apiRoutes, biziam.ApiRoute{
				URL:    r.Path,
				Method: r.Method,
				Label:  r.Path,
				Descr:  r.Handler,
			})
		}
	}

	if len(apiRoutes) == 0 {
		return 0, nil
	}

	return s.Biz.Api.SyncRoutes(ctx, apiRoutes)
}

// InitServer 初始化 IAM 服务、注册路由并同步 API 策略规则
func InitServer(
	ctx context.Context,
	engine *gin.Engine,
	bc *conf.Bootstrap,
	logger *slog.Logger,
	gormDB *gorm.DB,
	enforcer *casbin.SyncedEnforcer,
	opts ...Option,
) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	options := Options{
		GormDB:    gormDB,
		Enforcer:  enforcer,
		Bootstrap: bc,
		Logger:    logger,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	srv, err := New(options)
	if err != nil {
		return nil, err
	}

	if engine != nil {
		srv.RegisterRoutes(engine)
		if count, syncErr := srv.SyncGinRoutes(ctx, engine.Routes()); syncErr != nil {
			return nil, fmt.Errorf("sync gin routes: %w", syncErr)
		} else if count > 0 {
			logger.InfoContext(ctx, "synced gin routes into IAM catalog", slog.Int("synced_count", count))
		}
	}
	if err := srv.Data.ReconcileIAMPolicies(ctx); err != nil {
		return nil, err
	}

	return srv, nil
}
