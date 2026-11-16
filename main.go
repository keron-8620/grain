package main

import (
	"context"
	"crypto"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/joho/godotenv"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"grain/docs"
	"grain/internal/conf"
	dataiam "grain/internal/data/iam"
	"grain/internal/middleware"
	iamserver "grain/internal/server/iam"
	"grain/pkg/auth"
	"grain/pkg/cryptoutil"
	"grain/pkg/db"
	"grain/pkg/logx"
)

var (
	version   string
	commitID  string
	buildTime string
	goVersion string
	goOS      string
	goArch    string

	flagconf    string
	showVersion bool
	migrateOnly bool
	execSqlPath string
)

func init() {
	flag.StringVar(&flagconf, "conf", "config/config.yaml", "config file path, eg: -conf config/config.yaml")
	flag.BoolVar(&showVersion, "v", false, "print version information and exit")
	flag.BoolVar(&migrateOnly, "migrate", false, "apply IAM schema migrations and exit (production schema bootstrap)")
	flag.StringVar(&execSqlPath, "exec-sql", "", "execute an SQL file and exit")
}

// @title artweb API
// @version 1.0
// @description artweb 自动化运维平台 IAM 模块 API 接口文档
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description 请在请求头中传入 Bearer 格式的 JWT Token，例如: "Bearer {token}"
func main() {
	flag.Parse()

	if showVersion {
		fmt.Println("===== 版本信息 =====")
		fmt.Printf("版本号    : %s\n", version)
		fmt.Printf("提交ID    : %s\n", commitID)
		fmt.Printf("构建时间  : %s\n", buildTime)
		fmt.Printf("Go版本    : %s\n", goVersion)
		fmt.Printf("操作系统  : %s\n", goOS)
		fmt.Printf("系统架构  : %s\n", goArch)
		fmt.Println("====================")
		return
	}

	if err := run(); err != nil {
		log.Printf("FATAL: %v", err)
		os.Exit(1)
	}
}

func run() error {
	// .env 仅用于本地开发；生产环境可直接通过进程环境或 Secret 注入。
	if err := godotenv.Load(filepath.Join(conf.BaseDir, ".env")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("加载环境变量失败: %w", err)
	}

	bc, err := loadConf(flagconf)
	if err != nil {
		return err
	}

	logOpts := bc.Log
	if logOpts == nil {
		logOpts = &logx.Options{}
	}
	if strings.TrimSpace(logOpts.Filename) == "" {
		logOpts.Filename = filepath.Join(conf.LogDir, "server.log")
	}

	logger, logCloser, err := logx.New(logOpts)
	if err != nil {
		return fmt.Errorf("初始化系统日志失败: %w", err)
	}
	defer func() {
		if err := logCloser(); err != nil {
			log.Printf("关闭系统日志失败: %v", err)
		}
	}()

	// 注册全局默认日志器，保证未注入 logger 的模块及第三方库日志规范统一
	logx.SetDefault(logger)

	ctx := context.Background()

	gc := db.NewGormConfigWithSlog(db.SlogLoggerConfig{
		SlowThreshold:             bc.Database.SlowThreshold,
		ParameterizedQueries:      true,
		IgnoreRecordNotFoundError: true,
		BaseLogger:                logger,
	})
	gormDB, err := db.NewGormDBContext(ctx, bc.Database, gc)
	if err != nil {
		return fmt.Errorf("数据库初始化连接失败: %w", err)
	}
	defer func() {
		if err := db.CloseGormDB(gormDB); err != nil {
			logger.Warn("关闭数据库连接失败", slog.Any("error", err))
		}
	}()

	// 迁移模式：建表、可选执行 SQL，然后退出，不启动 HTTP 服务。
	if migrateOnly || execSqlPath != "" {
		if migrateOnly {
			if err := dataiam.AutoMigrate(gormDB); err != nil {
				return fmt.Errorf("数据库迁移失败: %w", err)
			}
			logger.Info("IAM 数据库迁移完成")
		}
		if execSqlPath != "" {
			if err := db.ExecSQLFile(ctx, gormDB, execSqlPath); err != nil {
				return fmt.Errorf("执行 SQL 文件失败: %w", err)
			}
			logger.Info("SQL 文件执行完成", slog.String("path", execSqlPath))
		}
		return nil
	}

	var redisClient redis.UniversalClient
	if bc.Redis != nil && bc.Redis.Enable {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     bc.Redis.Addr,
			Username: bc.Redis.Username,
			Password: bc.Redis.Password,
			DB:       bc.Redis.DB,
		})
		defer func() {
			if err := redisClient.Close(); err != nil {
				logger.Warn("关闭 Redis 客户端失败", slog.Any("error", err))
			}
		}()
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := redisClient.Ping(pingCtx).Err(); err != nil {
			return fmt.Errorf("redis 连接失败: %w", err)
		}
		logger.Info("Redis 已连接", slog.String("addr", bc.Redis.Addr))
	}

	cm, err := model.NewModelFromString(conf.DefaultRBACModel)
	if err != nil {
		return fmt.Errorf("创建 Casbin 模型失败: %w", err)
	}
	// No persistent adapter: IAM tables are the source of truth and
	// ReconcileIAMPolicies rebuilds the in-memory policy at startup.
	enforcer, err := casbin.NewSyncedEnforcer(cm)
	if err != nil {
		return fmt.Errorf("casbin 初始化失败: %w", err)
	}

	lumLogger, err := logx.NewLumLogger(bc.Log, filepath.Join(conf.LogDir, "cron.log"))
	if err != nil {
		return fmt.Errorf("初始化计划任务日志文件失败: %w", err)
	}
	defer func() {
		if err := lumLogger.Close(); err != nil {
			logger.Warn("关闭计划任务日志失败", slog.Any("error", err))
		}
	}()
	cronLogger := cron.VerbosePrintfLogger(log.New(lumLogger, "cron: ", log.LstdFlags))
	crontab := cron.New(
		cron.WithLogger(cronLogger),
		cron.WithLocation(time.Local),
		cron.WithChain(
			cron.Recover(cronLogger),
		),
	)

	gin.SetMode(gin.ReleaseMode)
	gin.DisableConsoleColor()

	privateKey, publicKey, keyID, err := loadJWTKeys(bc)
	if err != nil {
		return fmt.Errorf("jwt 密钥初始化失败: %w", err)
	}

	serverOptions := []iamserver.Option{
		iamserver.WithSigningKey(privateKey, publicKey, keyID),
		iamserver.WithIssuer(bc.Security.Token.Issuer),
		iamserver.WithAudience(bc.Security.Token.Audience),
	}
	if redisClient != nil {
		serverOptions = append(serverOptions, iamserver.WithRedisClient(redisClient))
	}

	r, err := NewRouter(ctx, bc, logger, gormDB, enforcer, crontab, serverOptions...)
	if err != nil {
		return fmt.Errorf("初始化路由失败: %w", err)
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", bc.Server.Host, bc.Server.Port),
		Handler:           r,
		ReadHeaderTimeout: bc.Server.Timeout.Request,
		ReadTimeout:       bc.Server.Timeout.Request,
		WriteTimeout:      bc.Server.Timeout.Request,
		IdleTimeout:       2 * bc.Server.Timeout.Request,
	}

	crtPath := filepath.Join(conf.ConfigDir, bc.Server.SSL.CrtPath)
	keyPath := filepath.Join(conf.ConfigDir, bc.Server.SSL.KeyPath)
	if bc.Server.SSL.Enable {
		if _, statErr := os.Stat(crtPath); statErr != nil {
			return fmt.Errorf("ssl 证书不可用 %s: %w", crtPath, statErr)
		}
		if _, statErr := os.Stat(keyPath); statErr != nil {
			return fmt.Errorf("ssl 私钥不可用 %s: %w", keyPath, statErr)
		}
	}

	serveErr := make(chan error, 1)
	go func() {
		if bc.Server.SSL.Enable {
			logger.Info("正在启动 HTTPS 服务器...",
				slog.String("addr", srv.Addr),
				slog.String("crt", crtPath),
				slog.String("key", keyPath),
			)
			serveErr <- srv.ListenAndServeTLS(crtPath, keyPath)
			return
		}
		logger.Info("正在启动 HTTP 服务器...", slog.String("addr", srv.Addr))
		serveErr <- srv.ListenAndServe()
	}()

	logger.Info(
		"服务器启动ing ...",
		slog.String("host", bc.Server.Host),
		slog.Int("port", bc.Server.Port),
		slog.Bool("ssl", bc.Server.SSL.Enable),
		slog.Bool("redis", redisClient != nil),
		slog.String("version", version),
		slog.String("commit", commitID),
		slog.String("build_time", buildTime),
	)

	// 监听系统中断信号（SIGINT, SIGTERM）来触发优雅关闭流程
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("服务器启动失败: %w", err)
		}
		return nil
	case <-quit:
	}

	logger.Info("正在关闭服务器...")

	timeoutCtx, cancel := context.WithTimeout(ctx, bc.Server.Timeout.Shutdown)
	defer cancel()

	if err := srv.Shutdown(timeoutCtx); err != nil {
		logger.ErrorContext(timeoutCtx, "服务器强制关闭", slog.Any("error", err))
	}

	logger.Info("服务器已退出")
	return nil
}

// newSystemConf 加载系统配置文件
func loadConf(configPath string) (*conf.Bootstrap, error) {
	if strings.TrimSpace(configPath) == "" {
		return nil, fmt.Errorf("配置文件路径不能为空")
	}
	if info, err := os.Stat(configPath); err != nil {
		return nil, fmt.Errorf("配置文件不可用 %s: %w", configPath, err)
	} else if info.IsDir() {
		return nil, fmt.Errorf("配置路径必须是文件而不是目录: %s", configPath)
	}

	data, err := os.ReadFile(configPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	bc := &conf.Bootstrap{}
	if err := yaml.Unmarshal(data, bc); err != nil {
		return nil, fmt.Errorf("配置文件解析失败: %w", err)
	}
	if err := bc.Validate(); err != nil {
		return nil, fmt.Errorf("配置文件校验失败: %w", err)
	}

	if strings.EqualFold(bc.Database.Type, "sqlite") && !filepath.IsAbs(bc.Database.Dsn) && bc.Database.Dsn != "" {
		bc.Database.Dsn = filepath.Join(filepath.Dir(configPath), bc.Database.Dsn)
	}
	resolveKeyPath := func(material string) string {
		trimmed := strings.TrimSpace(material)
		if trimmed == "" || strings.Contains(trimmed, "-----BEGIN") || filepath.IsAbs(trimmed) {
			return material
		}
		return filepath.Join(filepath.Dir(configPath), trimmed)
	}
	bc.Security.Token.PrivateKey = resolveKeyPath(bc.Security.Token.PrivateKey)
	bc.Security.Token.PublicKey = resolveKeyPath(bc.Security.Token.PublicKey)
	bc.SetVersion(version)
	return bc, nil
}

func NewRouter(
	ctx context.Context,
	bc *conf.Bootstrap,
	logger *slog.Logger,
	gormDB *gorm.DB,
	enforcer *casbin.SyncedEnforcer,
	crontab *cron.Cron,
	serverOptions ...iamserver.Option,
) (*gin.Engine, error) {
	r := gin.New()
	if err := r.SetTrustedProxies(bc.Server.TrustedProxies); err != nil {
		logger.Warn("配置受信任代理失败，将不信任代理转发头")
		_ = r.SetTrustedProxies(nil)
	}

	// 配置静态文件处理
	htmlPath := filepath.Join(conf.HTMLDir, "index.html")
	r.GET("/", func(c *gin.Context) {
		c.File(htmlPath)
	})
	faviconPath := filepath.Join(conf.HTMLDir, "favicon.ico")
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.File(faviconPath)
	})
	coveragePath := filepath.Join(conf.HTMLDir, "coverage.html")
	r.GET("/coverage.html", func(c *gin.Context) {
		c.File(coveragePath)
	})
	staticPath := filepath.Join(conf.HTMLDir, "static")
	r.Static("/static", staticPath)

	// 存活检查只反映 HTTP 进程状态。
	r.GET("/livez", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": http.StatusOK, "msg": "ok", "data": nil})
	})
	// 就绪检查验证数据库连接，供负载均衡和编排系统摘流。
	r.GET("/readyz", func(c *gin.Context) {
		sqlDB, err := gormDB.DB()
		if err != nil || sqlDB.PingContext(c.Request.Context()) != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"code": http.StatusServiceUnavailable, "msg": "database unavailable", "data": nil})
			return
		}
		c.JSON(http.StatusOK, gin.H{"code": http.StatusOK, "msg": "ok", "data": nil})
	})
	// 保留旧健康检查路径以兼容已有部署。
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": http.StatusOK, "msg": time.Now().Format(time.DateTime), "data": nil})
	})

	// 版本信息接口
	r.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code": http.StatusOK,
			"msg":  version,
			"data": nil,
		})
	})

	// 终端页面
	r.GET("/terminal", func(c *gin.Context) {
		c.File(filepath.Join(conf.HTMLDir, "terminal.html"))
	})

	// 配置 Swagger 文档
	if bc.Server.Swagger {
		docs.SwaggerInfo.Title = "artweb"
		docs.SwaggerInfo.Description = "artweb自动化运维平台"
		docs.SwaggerInfo.Version = version
		docs.SwaggerInfo.Host = fmt.Sprintf("%s:%d", bc.Server.Host, bc.Server.Port)
		docs.SwaggerInfo.Schemes = []string{"http", "https"}
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	diagnostics := r.Group("")
	diagnostics.Use(diagnosticsAuth(os.Getenv("DIAGNOSTICS_TOKEN")))
	if bc.Server.EnableMetrics {
		diagnostics.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}
	if bc.Server.EnablePprof {
		diagnostics.GET("/debug/pprof/", gin.WrapF(pprof.Index))
		diagnostics.GET("/debug/pprof/cmdline", gin.WrapF(pprof.Cmdline))
		diagnostics.GET("/debug/pprof/profile", gin.WrapF(pprof.Profile))
		diagnostics.GET("/debug/pprof/symbol", gin.WrapF(pprof.Symbol))
		diagnostics.POST("/debug/pprof/symbol", gin.WrapF(pprof.Symbol))
		diagnostics.GET("/debug/pprof/trace", gin.WrapF(pprof.Trace))
	}

	// 注册统一异常处理中间件
	r.Use(middleware.ErrorMiddleware(logger))

	// 注册链路追踪处理中间件
	r.Use(middleware.TracingMiddleware(logger))

	// 注册跨域请求处理中间件
	r.Use(middleware.CorsMiddleware(bc.CORS))

	// host请求头防护中间件
	if bc.Security.HostGuard.Enable {
		r.Use(middleware.HostGuard(logger, bc.Security.HostGuard.TrustedHosts...))
	}

	// 注册时间戳处理中间件,用于防御重放攻击
	if bc.Security.Timestamp.CheckTimestamp {
		// 从配置中获取时间戳容差参数，如果没有配置则使用默认值
		tolerance := bc.Security.Timestamp.Tolerance
		if tolerance <= 0 {
			tolerance = 300 * time.Second // 默认5分钟
		}

		futureTolerance := bc.Security.Timestamp.FutureTolerance
		if futureTolerance <= 0 {
			futureTolerance = 60 * time.Second // 默认1分钟
		}

		toleranceMs := int64(tolerance / time.Millisecond)
		futureToleranceMs := int64(futureTolerance / time.Millisecond)

		// 默认过期时间(ms)
		defaultExpiration := time.Duration(max(toleranceMs, futureToleranceMs)) * time.Millisecond

		// 设置缓存过期时间为容忍度+未来容忍度，确保过期的nonce自动清除
		nonceCache := cache.New(defaultExpiration, 1*time.Minute)
		r.Use(middleware.TimestampMiddleware(
			logger,
			nonceCache,
			toleranceMs,
			futureToleranceMs,
			defaultExpiration,
		))
	}

	// IP限流中间件
	r.Use(middleware.IPBasedRateLimiterMiddleware(logger, rate.Limit(bc.Server.Rate.RPS), bc.Server.Rate.Burst))

	// 注册超时处理中间件
	r.Use(middleware.TimeoutMiddleware(logger, bc.Server.Timeout.Request))

	// 初始化加载业务模块
	if _, err := iamserver.InitServer(ctx, r, bc, logger, gormDB, enforcer, serverOptions...); err != nil {
		return nil, fmt.Errorf("初始化 IAM 模块失败: %w", err)
	}

	return r, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	ap, err := cryptoutil.MarshalPublicKeyPKIXPEM(a)
	if err != nil {
		return false
	}
	bp, err := cryptoutil.MarshalPublicKeyPKIXPEM(b)
	if err != nil {
		return false
	}
	return string(ap) == string(bp)
}
func loadJWTKeys(bc *conf.Bootstrap) (crypto.PrivateKey, crypto.PublicKey, string, error) {
	if bc == nil || bc.Security == nil {
		return nil, nil, "", fmt.Errorf("security configuration is required")
	}
	material := strings.TrimSpace(bc.Security.Token.PrivateKey)
	if material == "" {
		return nil, nil, "", fmt.Errorf("security.token.private_key is required")
	}
	privateKey, err := cryptoutil.LoadPrivateKey(material)
	if err != nil {
		return nil, nil, "", fmt.Errorf("load JWT private key: %w", err)
	}
	publicKey, err := cryptoutil.ExtractPublicKey(privateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("derive JWT public key: %w", err)
	}
	if configured := strings.TrimSpace(bc.Security.Token.PublicKey); configured != "" {
		configuredKey, err := cryptoutil.LoadPublicKey(configured)
		if err != nil {
			return nil, nil, "", fmt.Errorf("load JWT public key: %w", err)
		}
		if !publicKeysEqual(publicKey, configuredKey) {
			return nil, nil, "", fmt.Errorf("configured JWT public key does not match private key")
		}
		publicKey = configuredKey
	}
	kid := bc.Security.Token.KeyID
	if strings.TrimSpace(kid) == "" {
		kid, err = auth.KeyID(publicKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("derive JWT key ID: %w", err)
		}
	}
	return privateKey, publicKey, kid, nil
}

func diagnosticsAuth(expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		provided := strings.TrimSpace(c.GetHeader("Authorization"))
		provided = strings.TrimSpace(strings.TrimPrefix(provided, "Bearer "))
		if expected == "" || len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			c.Header("WWW-Authenticate", `Bearer realm="diagnostics"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code": http.StatusUnauthorized,
				"msg":  "diagnostics authentication required",
				"data": nil,
			})
			return
		}
		c.Next()
	}
}
