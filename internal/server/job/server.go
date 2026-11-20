package job

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"

	bizjob "grain/internal/biz/job"
	"grain/internal/conf"
	datajob "grain/internal/data/job"
	"grain/internal/middleware"
	servicejob "grain/internal/service/job"
	"grain/pkg/auth"
	"grain/pkg/db"
)

// Options assembles the dependencies of the job module.
type Options struct {
	GormDB        *gorm.DB
	Bootstrap     *conf.Bootstrap
	Logger        *slog.Logger
	Authenticator *auth.Authenticator
	Enforcer      *casbin.SyncedEnforcer
	Crontab       *cron.Cron

	// ScriptStore and ScriptRoot override the configured storage backend.
	// They exist for tests and embedding; production wiring leaves them nil.
	ScriptStore bizjob.ScriptStore
	ScriptRoot  string
}

// Server owns the job data/biz/service stack.
type Server struct {
	Data      *datajob.Data
	Scripts   *bizjob.ScriptUseCase
	Schedules *bizjob.ScheduleUseCase
	Records   *bizjob.ScriptRecordUseCache
	Service   *servicejob.Service

	logger          *slog.Logger
	authenticator   *auth.Authenticator
	enforcer        *casbin.SyncedEnforcer
	crontab         *cron.Cron
	shutdownTimeout time.Duration
	recoverOnce     sync.Once
}

// New builds the job module.
func New(opts Options) (*Server, error) {
	if opts.GormDB == nil {
		return nil, fmt.Errorf("job server: gorm DB is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	bc := opts.Bootstrap
	if bc == nil {
		bc = &conf.Bootstrap{}
	}
	if bc.Database == nil {
		bc.Database = &db.DBConf{}
	}

	data := datajob.NewData(opts.GormDB, dbTimeout(bc), dbSlowThreshold(bc), opts.Crontab)
	scriptRepo := datajob.NewScriptRepo(data, logger)
	scheduleRepo := datajob.NewScheduleRepo(data, logger)
	recordRepo := datajob.NewScriptRecordRepo(data, logger)

	store, root := opts.ScriptStore, opts.ScriptRoot
	if store == nil {
		var err error
		store, root, err = buildScriptStore(bc)
		if err != nil {
			return nil, err
		}
	}
	if root == "" {
		root = bizjob.DefaultScriptRootDir()
	}

	maxConcurrent := 0
	if bc.Job != nil {
		maxConcurrent = bc.Job.MaxConcurrentScripts
	}

	records := bizjob.NewScriptRecordUseCache(scriptRepo, recordRepo, logger, maxConcurrent)
	records.SetScriptRoot(root)
	if bc.CMDB != nil {
		records.SetSSHKeyPassphrase(bc.CMDB.SSHPrivateKeyPassphrase)
	}
	scripts := bizjob.NewScriptUseCase(scriptRepo, store, logger)
	schedules := bizjob.NewScheduleUseCase(scheduleRepo, scriptRepo, records, logger, opts.Crontab)
	svc := servicejob.NewService(scripts, schedules, records, logger)

	shutdownTimeout := 30 * time.Second
	if bc.Server != nil && bc.Server.Timeout.Shutdown > 0 {
		shutdownTimeout = bc.Server.Timeout.Shutdown + 5*time.Second
	}

	return &Server{
		Data:            data,
		Scripts:         scripts,
		Schedules:       schedules,
		Records:         records,
		Service:         svc,
		logger:          logger,
		authenticator:   opts.Authenticator,
		enforcer:        opts.Enforcer,
		crontab:         opts.Crontab,
		shutdownTimeout: shutdownTimeout,
	}, nil
}

// RegisterRoutes registers the job HTTP API on r. Every endpoint requires a
// valid JWT and a matching Casbin permission.
func (s *Server) RegisterRoutes(r gin.IRouter, prefix ...string) {
	base := "/api/v1"
	if len(prefix) > 0 && prefix[0] != "" {
		base = prefix[0]
	}

	group := r.Group(base)
	group.Use(middleware.JWTAuthMiddleware(s.logger, s.authenticator))
	group.Use(middleware.CasbinAuthMiddleware(s.logger, s.enforcer))

	// 脚本
	group.POST("/scripts", s.Service.CreateScript)
	group.GET("/scripts", s.Service.ListScripts)
	group.GET("/scripts/:id", s.Service.GetScript)
	group.PUT("/scripts/:id", s.Service.UpdateScript)
	group.DELETE("/scripts/:id", s.Service.DeleteScript)
	group.GET("/scripts/:id/content", s.Service.GetScriptContent)

	// 计划任务
	group.POST("/schedules", s.Service.CreateSchedule)
	group.GET("/schedules", s.Service.ListSchedules)
	group.GET("/schedules/:id", s.Service.GetSchedule)
	group.PUT("/schedules/:id", s.Service.UpdateSchedule)
	group.DELETE("/schedules/:id", s.Service.DeleteSchedule)
	group.POST("/schedules/:id/enable", s.Service.EnableSchedule)
	group.POST("/schedules/:id/disable", s.Service.DisableSchedule)
	group.POST("/schedules/:id/run", s.Service.RunSchedule)

	// 执行记录
	group.POST("/script-records", s.Service.CreateScriptRecord)
	group.GET("/script-records", s.Service.ListScriptRecords)
	group.GET("/script-records/:id", s.Service.GetScriptRecord)
	group.POST("/script-records/:id/cancel", s.Service.CancelScriptRecord)
	group.GET("/script-records/:id/log", s.Service.DownloadScriptRecordLog)
}

// Start recovers interrupted records from a previous process, then loads
// enabled schedules and starts the cron scheduler.
func (s *Server) Start(ctx context.Context) error {
	if s.Records != nil {
		s.recoverOnce.Do(func() {
			if _, err := s.Records.Recover(ctx); err != nil {
				s.logger.ErrorContext(ctx, "恢复上次进程遗留的执行记录失败", slog.Any("error", err))
			}
		})
	}
	if s.Schedules == nil {
		return nil
	}
	return s.Schedules.Start(ctx)
}

// Stop removes cron entries, cancels running executions and waits (bounded)
// for them to persist their final state.
func (s *Server) Stop() {
	if s.Schedules != nil {
		s.Schedules.Stop()
	}
	if s.Records != nil {
		ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
		defer cancel()
		s.Records.Stop(ctx)
	}
}

// Init builds the job module and registers its routes.
func Init(ctx context.Context, r gin.IRouter, opts Options) (*Server, error) {
	srv, err := New(opts)
	if err != nil {
		return nil, err
	}
	if r != nil {
		srv.RegisterRoutes(r)
	}
	return srv, nil
}

// buildScriptStore selects the configured backing store and returns its working
// directory, which is also used as the local execution root.
func buildScriptStore(bc *conf.Bootstrap) (bizjob.ScriptStore, string, error) {
	if bc.Job == nil || bc.Job.ScriptRepo == nil || !bc.Job.ScriptRepo.Enable {
		root := bizjob.DefaultScriptRootDir()
		store, err := datajob.NewLocalScriptStore(root)
		if err != nil {
			return nil, "", fmt.Errorf("job server: initialize local script store: %w", err)
		}
		return store, root, nil
	}

	cfg := bc.Job.ScriptRepo
	dir := resolvePath(cfg.Dir)
	if strings.TrimSpace(dir) == "" {
		return nil, "", fmt.Errorf("job server: job.script_repo.dir is required")
	}
	store, err := datajob.NewGitStore(datajob.GitConfig{
		URL:              cfg.URL,
		Branch:           cfg.Branch,
		Dir:              dir,
		AuthorName:       cfg.AuthorName,
		AuthorEmail:      cfg.AuthorEmail,
		AuthType:         datajob.AuthType(strings.ToLower(strings.TrimSpace(cfg.AuthType))),
		Username:         cfg.Username,
		Password:         cfg.Password,
		SSHKeyPath:       resolvePath(cfg.SSHKeyPath),
		SSHKeyPassphrase: cfg.SSHKeyPassphrase,
		KnownHosts:       resolvePath(cfg.KnownHosts),
		SSHHostKey:       strings.TrimSpace(cfg.SSHHostKey),
		Timeout:          cfg.Timeout,
		InsecureSkipTLS:  cfg.InsecureSkipTLS,
	})
	if err != nil {
		return nil, "", fmt.Errorf("job server: initialize git script store: %w", err)
	}
	return store, dir, nil
}

// resolvePath resolves relative paths against the process base directory.
func resolvePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || filepath.IsAbs(p) || strings.Contains(p, "-----BEGIN") {
		return p
	}
	return filepath.Join(conf.BaseDir, p)
}

func dbTimeout(bc *conf.Bootstrap) db.DBTimeout {
	return db.DBTimeout{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ListTimeout:  30 * time.Second,
	}
}

func dbSlowThreshold(bc *conf.Bootstrap) db.DBSlowThreshold {
	slow := 200 * time.Millisecond
	if bc.Database != nil && bc.Database.SlowThreshold > 0 {
		slow = bc.Database.SlowThreshold
	}
	return db.DBSlowThreshold{ReadSlow: slow, WriteSlow: slow, ListSlow: slow}
}
