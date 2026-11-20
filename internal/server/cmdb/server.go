package cmdb

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	bizcmdb "grain/internal/biz/cmdb"
	"grain/internal/conf"
	datacmdb "grain/internal/data/cmdb"
	"grain/internal/middleware"
	servicecmdb "grain/internal/service/cmdb"
	"grain/pkg/auth"
	"grain/pkg/db"
)

// Options assembles the dependencies of the CMDB module.
type Options struct {
	GormDB        *gorm.DB
	Bootstrap     *conf.Bootstrap
	Logger        *slog.Logger
	Authenticator *auth.Authenticator
	Enforcer      *casbin.SyncedEnforcer
}

// Server owns the CMDB data/biz/service stack.
type Server struct {
	Data    *datacmdb.Data
	Hosts   *bizcmdb.HostUseCase
	Service *servicecmdb.Service

	logger        *slog.Logger
	authenticator *auth.Authenticator
	enforcer      *casbin.SyncedEnforcer
}

// New builds the CMDB module.
func New(opts Options) (*Server, error) {
	if opts.GormDB == nil {
		return nil, fmt.Errorf("cmdb server: gorm DB is required")
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

	onboarding, err := buildOnboarding(bc.CMDB, logger)
	if err != nil {
		return nil, err
	}

	data := datacmdb.NewData(opts.GormDB, dbTimeout(bc), dbSlowThreshold(bc), nil)
	repo := datacmdb.NewHostRepo(data, logger)
	hosts := bizcmdb.NewHostUseCase(
		repo,
		logger,
		onboarding.timeout,
		onboarding.authMethod,
		onboarding.publicKeys,
		bizcmdb.WithSSHPrivateKeyPath(onboarding.privateKeyPath),
		bizcmdb.WithWinRMConfig(onboarding.winrm),
	)
	svc := servicecmdb.NewService(hosts, logger)

	return &Server{
		Data:          data,
		Hosts:         hosts,
		Service:       svc,
		logger:        logger,
		authenticator: opts.Authenticator,
		enforcer:      opts.Enforcer,
	}, nil
}

// RegisterRoutes registers the CMDB HTTP API on r. Every endpoint requires a
// valid JWT and a matching Casbin permission.
func (s *Server) RegisterRoutes(r gin.IRouter, prefix ...string) {
	base := "/api/v1"
	if len(prefix) > 0 && prefix[0] != "" {
		base = prefix[0]
	}

	group := r.Group(base)
	group.Use(middleware.JWTAuthMiddleware(s.logger, s.authenticator))
	group.Use(middleware.CasbinAuthMiddleware(s.logger, s.enforcer))

	group.POST("/hosts", s.Service.CreateHost)
	group.GET("/hosts", s.Service.ListHosts)
	group.GET("/hosts/:id", s.Service.GetHost)
	group.PUT("/hosts/:id", s.Service.UpdateHost)
	group.POST("/hosts/:id/refresh-key", s.Service.RefreshHostKey)
	group.DELETE("/hosts/:id", s.Service.DeleteHost)
}

// Init builds the CMDB module and registers its routes.
func Init(ctx context.Context, r gin.IRouter, opts Options) (*Server, error) {
	srv, err := New(opts)
	if err != nil {
		return nil, err
	}
	if r != nil {
		srv.RegisterRoutes(r)
	}
	// Rewrite all host vars from the database/current config. This drops legacy
	// secrets (ansible_password, inline PEMs) and refreshes key/cert paths.
	if _, err := srv.Hosts.ResyncHostVars(ctx); err != nil {
		srv.logger.Warn("resync ansible host vars failed", slog.Any("error", err))
	}
	return srv, nil
}

type onboardingConfig struct {
	authMethod     ssh.AuthMethod
	publicKeys     []string
	privateKeyPath string
	winrm          bizcmdb.WinRMConfig
	timeout        time.Duration
}

// buildOnboarding translates the cmdb config section into the host use case
// dependencies. Missing credentials are allowed: onboarding is then skipped and
// hosts are persisted without passwordless-key deployment.
func buildOnboarding(cfg *conf.CMDBConfig, logger *slog.Logger) (onboardingConfig, error) {
	if logger == nil {
		logger = slog.Default()
	}
	out := onboardingConfig{timeout: 15 * time.Second}
	if cfg == nil {
		return out, nil
	}
	if cfg.SSHTimeout > 0 {
		out.timeout = cfg.SSHTimeout
	}

	if key := strings.TrimSpace(cfg.SSHPrivateKey); key != "" {
		signer, err := loadSSHSigner(key, cfg.SSHPrivateKeyPassphrase)
		if err != nil {
			return out, fmt.Errorf("cmdb server: load ssh private key: %w", err)
		}
		out.authMethod = ssh.PublicKeys(signer)
		out.publicKeys = append(out.publicKeys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
		keyPath, pathErr := materializeSSHKey(key)
		if pathErr != nil {
			return out, fmt.Errorf("cmdb server: persist ssh private key: %w", pathErr)
		}
		out.privateKeyPath = keyPath
	} else if password := cfg.SSHPassword; password != "" {
		out.authMethod = ssh.Password(password)
	} else {
		logger.Warn("cmdb: no ssh onboarding credential configured; ssh onboarding and host key capture will be skipped")
	}

	for _, key := range cfg.PublicKeys {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			out.publicKeys = append(out.publicKeys, trimmed)
		}
	}

	caCert, err := readMaterial(cfg.WinRM.CACert)
	if err != nil {
		return out, fmt.Errorf("cmdb server: read winrm ca cert: %w", err)
	}

	out.winrm = bizcmdb.WinRMConfig{
		UseTLS:   cfg.WinRM.UseTLS,
		Insecure: cfg.WinRM.Insecure,
		CACert:   caCert,
	}
	// The host use case reads the client certificate pair from disk, so these
	// must be file paths (inline PEM is not supported here).
	if cert := strings.TrimSpace(cfg.WinRM.ClientCert); cert != "" {
		if strings.Contains(cert, "-----BEGIN") {
			return out, fmt.Errorf("cmdb server: cmdb.winrm.client_cert must be a file path")
		}
		out.winrm.ClientCertPath = resolvePath(cert)
		out.winrm.ClientKeyPath = resolvePath(cfg.WinRM.ClientKey)
	}
	return out, nil
}

// materializeSSHKey returns a filesystem path for the execution key. Inline PEM
// is written once to storage/keys (0600) because host_vars only carries paths.
func materializeSSHKey(material string) (string, error) {
	material = strings.TrimSpace(material)
	if !strings.Contains(material, "-----BEGIN") {
		return resolvePath(material), nil
	}
	dir := filepath.Join(conf.StorageDir, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "cmdb_ssh_key")
	if err := os.WriteFile(path, []byte(material+"\n"), 0o600); err != nil { // #nosec G306 -- private key file
		return "", err
	}
	return path, nil
}

func loadSSHSigner(material, passphrase string) (ssh.Signer, error) {
	data, err := readMaterial(material)
	if err != nil {
		return nil, err
	}
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(data)
}

// readMaterial accepts inline PEM text or a filesystem path (resolved against
// the process base directory when relative).
func readMaterial(material string) ([]byte, error) {
	material = strings.TrimSpace(material)
	if material == "" {
		return nil, nil
	}
	if strings.Contains(material, "-----BEGIN") {
		return []byte(material), nil
	}
	path := resolvePath(material)
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted configuration
	if err != nil {
		return nil, err
	}
	return data, nil
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
