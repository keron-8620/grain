package main

import (
	"context"
	"crypto/subtle"
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
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/joho/godotenv"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"grain/docs"
	"grain/internal/conf"
	"grain/internal/middleware"
	iamserver "grain/internal/server/iam"
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
	flag.StringVar(&flagconf, "conf", "configs", "config path, eg: -conf configs")
	flag.BoolVar(&showVersion, "v", false, "print version information and exit")
	flag.BoolVar(&migrateOnly, "migrate", false, "apply versioned database migrations and exit (production schema bootstrap)")
	flag.StringVar(&execSqlPath, "exec-sql", "", "执行SQL文件路径")
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

	// .env 仅用于本地开发；生产环境可直接通过进程环境或 Secret 注入。
	if err := godotenv.Load(filepath.Join(conf.BaseDir, ".env")); err != nil && !os.IsNotExist(err) {
		log.Fatalf("加载环境变量失败: %v", err)
	}

	bc, confErr := loadConf(flagconf)
	if confErr != nil {
		log.Fatal(confErr.Error())
	}

	logOpts := bc.Log
	if logOpts == nil {
		logOpts = &logx.Options{}
	}
	if strings.TrimSpace(logOpts.Filename) == "" {
		logOpts.Filename = filepath.Join(conf.LogDir, "server.log")
	}

	logger, logCloser, logErr := logx.New(logOpts)
	if logErr != nil {
		log.Fatalf("初始化系统日志失败: %v", logErr)
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
	gormDB, gormErr := db.NewGormDBContext(ctx, bc.Database, gc)
	if gormErr != nil {
		logger.Error("数据库初始化连接失败", slog.Any("error", gormErr))
		return
	}
	defer db.CloseGormDB(gormDB)

	cm, rbacModelErr := model.NewModelFromString(conf.DefaultRBACModel)
	if rbacModelErr != nil {
		logger.Error("创建Casbin模型失败", slog.Any("error", rbacModelErr))
		return
	}
	adapter := stringadapter.NewAdapter("p, admin, /api/v1/*, GET")
	enforcer, enfErr := casbin.NewSyncedEnforcer(cm, adapter)
	if enfErr != nil {
		logger.Error("casbin初始化失败", slog.Any("error", enfErr))
		return
	}

	lumLogger, lumErr := logx.NewLumLogger(bc.Log, filepath.Join(conf.LogDir, "cron.log"))
	if lumErr != nil {
		logger.Error("初始化计划任务日志文件失败", slog.Any("error", lumErr))
	}
	defer lumLogger.Close()
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

	// 创建 Gin 路由引擎
	r := NewRouter(ctx, bc, logger, gormDB, enforcer, crontab)

	// 构建 HTTP 服务器结构体
	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", bc.Server.Host, bc.Server.Port),
		Handler:           r,
		ReadHeaderTimeout: bc.Server.Timeout.Request,
		ReadTimeout:       bc.Server.Timeout.Request,
		WriteTimeout:      bc.Server.Timeout.Request,
		IdleTimeout:       2 * bc.Server.Timeout.Request,
	}

	// 启动一个 goroutine 来异步启动 HTTP/HTTPS 服务
	go func() {
		var err error
		// 判断是否启用 SSL/TLS 加密传输
		if bc.Server.SSL.Enable {
			// 构造证书和私钥的完整路径
			crtPath := filepath.Join(conf.ConfigDir, bc.Server.SSL.CrtPath)
			keyPath := filepath.Join(conf.ConfigDir, bc.Server.SSL.KeyPath)

			// 校验证书文件是否存在
			if _, statErr := os.Stat(crtPath); os.IsNotExist(statErr) {
				logger.Error("SSL CRT 文件不存在", slog.String("path", crtPath))
				panic(statErr)
			}
			// 校验私钥文件是否存在
			if _, statErr := os.Stat(keyPath); os.IsNotExist(statErr) {
				logger.Error("SSL KEY 文件不存在", slog.String("path", keyPath))
				panic(statErr)
			}

			// 输出 HTTPS 启动信息并开始监听
			logger.Info(
				"正在启动 HTTPS 服务器...",
				slog.String("addr", srv.Addr),
				slog.String("crt", crtPath),
				slog.String("key", keyPath),
			)
			err = srv.ListenAndServeTLS(crtPath, keyPath)
		} else {
			// 输出 HTTP 启动信息并开始监听
			logger.Info("正在启动 HTTP 服务器...", slog.String("addr", srv.Addr))
			err = srv.ListenAndServe()
		}

		// 处理服务器启动过程中的致命错误
		if err != nil && err != http.ErrServerClosed {
			logger.Error("服务器启动失败", slog.Any("error", err))
			panic(err)
		}
	}()

	// 打印服务器启动信息
	logger.Info(
		"服务器启动ing ...",
		slog.String("host", bc.Server.Host),
		slog.Int("port", bc.Server.Port),
		slog.Bool("ssl", bc.Server.SSL.Enable),
		slog.String("version", version),
		slog.String("commit", commitID),
		slog.String("build_time", buildTime),
	)

	// 监听系统中断信号（SIGINT, SIGTERM）来触发优雅关闭流程
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // 阻塞等待信号到来

	// 收到关闭信号后打印提示信息
	logger.Info("正在关闭服务器...")

	// 创建带超时控制的上下文对象用于通知服务器关闭
	timeoutCtx, cancel := context.WithTimeout(ctx, bc.Server.Timeout.Shutdown)
	defer cancel()

	// 执行服务器优雅关闭逻辑
	if err := srv.Shutdown(timeoutCtx); err != nil {
		logger.ErrorContext(timeoutCtx, "服务器强制关闭", slog.Any("error", err))
	}

	// 最终确认服务器已经退出
	logger.Info("服务器已退出")

}

// newSystemConf 加载系统配置文件
func loadConf(configPath string) (*conf.Bootstrap, error) {
	if configPath == "" {
		log.Fatal("配置文件路径不能为空")
	}

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("FATAL: 配置文件不存在,请检查: %s", configPath)
		}
		return nil, fmt.Errorf("FATAL: 获取配置文件%s状态失败: %v", configPath, err)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath) // #nosec G304
	if err != nil {
		log.Fatalf("FATAL: 读取配置文件失败: %v", err)
	}

	bc := &conf.Bootstrap{}

	// 解析YAML配置
	if err := yaml.Unmarshal(data, bc); err != nil {
		return nil, fmt.Errorf("FATAL: 配置文件解析失败: %v", err)
	}
	if err := bc.Validate(); err != nil {
		return nil, fmt.Errorf("FATAL: 配置文件校验失败: %v", err)
	}

	if bc.Database.Type == "sqlite" && !filepath.IsAbs(bc.Database.Dsn) {
		bc.Database.Dsn = filepath.Join(conf.BaseDir, bc.Database.Dsn)
	}

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
) *gin.Engine {
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
	if _, err := iamserver.InitServer(ctx, r, bc, logger, gormDB, enforcer); err != nil {
		logger.ErrorContext(ctx, "初始化 IAM 模块失败", slog.Any("error", err))
	}

	return r
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
