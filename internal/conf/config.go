package conf

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"grain/pkg/db"
	"grain/pkg/logx"
)

// SigningMethod resolves a configured JWT algorithm name. An empty value
// defaults to RS256 for backward compatibility.
func SigningMethod(name string) (jwt.SigningMethod, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "RS256") {
		return jwt.SigningMethodRS256, nil
	}
	method := jwt.GetSigningMethod(strings.ToUpper(name))
	if method == nil {
		return nil, fmt.Errorf("unsupported JWT signing method %q", name)
	}
	switch method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA, *jwt.SigningMethodEd25519:
		return method, nil
	default:
		// Reject HMAC and "none": the service is configured with an
		// asymmetric key pair, and symmetric secrets must not be accepted here.
		return nil, fmt.Errorf("unsupported JWT signing method %q: asymmetric algorithm required", name)
	}
}

type Bootstrap struct {
	Server   *ServerConfig   `yaml:"server"`
	Database *db.DBConf      `yaml:"database"`
	Redis    *RedisConfig    `yaml:"redis"`
	Log      *logx.Options   `yaml:"log"`
	Security *SecurityConfig `yaml:"security"`
	IAM      *IAMConfig      `yaml:"iam"`
	Job      *JobConfig      `yaml:"job"`
	CMDB     *CMDBConfig     `yaml:"cmdb"`
	version  string
}

// JobConfig 定时任务模块配置
type JobConfig struct {
	// MaxConcurrentScripts caps simultaneously running script executions.
	// 0 uses the built-in default (10).
	MaxConcurrentScripts int               `yaml:"max_concurrent_scripts"`
	ScriptRepo           *ScriptRepoConfig `yaml:"script_repo"`
}

// CMDBConfig 主机管理模块配置。
// SSH 凭据仅用于新主机接入（部署免密公钥），不会写入主机记录。
type CMDBConfig struct {
	SSHTimeout              time.Duration   `yaml:"ssh_timeout"`
	SSHPrivateKey           string          `yaml:"ssh_private_key"` // PEM text or path
	SSHPrivateKeyPassphrase string          `yaml:"ssh_private_key_passphrase"`
	SSHPassword             string          `yaml:"ssh_password"`
	PublicKeys              []string        `yaml:"public_keys"` // authorized_keys lines or base64 blobs
	WinRM                   CMDBWinRMConfig `yaml:"winrm"`
}

// CMDBWinRMConfig configures WinRM onboarding (certificate verification).
type CMDBWinRMConfig struct {
	UseTLS     bool   `yaml:"use_tls"`
	Insecure   bool   `yaml:"insecure_skip_verify"`
	CACert     string `yaml:"ca_cert"`     // PEM text or path
	ClientCert string `yaml:"client_cert"` // PEM text or path
	ClientKey  string `yaml:"client_key"`  // PEM text or path
}

// ScriptRepoConfig 脚本内容所在的 Git 仓库配置。
// 脚本正文不写入数据库，统一提交到该仓库；数据库只保存元数据。
type ScriptRepoConfig struct {
	Enable           bool          `yaml:"enable"`
	URL              string        `yaml:"url"`
	Branch           string        `yaml:"branch"`
	Dir              string        `yaml:"dir"`
	Timeout          time.Duration `yaml:"timeout"`
	AuthorName       string        `yaml:"author_name"`
	AuthorEmail      string        `yaml:"author_email"`
	AuthType         string        `yaml:"auth_type"` // none / http / ssh
	Username         string        `yaml:"username"`
	Password         string        `yaml:"password"`
	SSHKeyPath       string        `yaml:"ssh_key_path"`
	SSHKeyPassphrase string        `yaml:"ssh_key_passphrase"`
	KnownHosts       string        `yaml:"known_hosts"`  // known_hosts file for SSH remotes
	SSHHostKey       string        `yaml:"ssh_host_key"` // pinned SSH host key (authorized_keys line)
	InsecureSkipTLS  bool          `yaml:"insecure_skip_tls"`
}

// RedisConfig configures shared session and revocation state.
type RedisConfig struct {
	Enable   bool   `yaml:"enable"`
	Addr     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

func (b *Bootstrap) SetVersion(v string) {
	b.version = v
}

func (b *Bootstrap) GetVersion() string {
	return b.version
}

// Server modes. Production mode turns the security baseline items that used to
// be documentation-only into startup errors.
const (
	ServerModeDev  = "dev"
	ServerModeProd = "prod"
)

func (b *Bootstrap) Validate() error {
	if b == nil {
		return fmt.Errorf("bootstrap configuration cannot be nil")
	}
	if b.Server == nil {
		return fmt.Errorf("server configuration is required")
	}

	mode := strings.ToLower(strings.TrimSpace(b.Server.Mode))
	switch mode {
	case "":
		b.Server.Mode = ServerModeDev
	case ServerModeDev, ServerModeProd:
		b.Server.Mode = mode
	default:
		return fmt.Errorf("server.mode must be %q or %q, got %q", ServerModeDev, ServerModeProd, b.Server.Mode)
	}

	if b.Database == nil {
		return fmt.Errorf("database configuration is required")
	}
	if strings.TrimSpace(b.Database.Type) == "" {
		return fmt.Errorf("database.type is required")
	}
	if strings.TrimSpace(b.Database.Dsn) == "" && strings.ToLower(strings.TrimSpace(b.Database.Type)) != "sqlite" {
		return fmt.Errorf("database.dsn is required")
	}
	if _, ok := db.GetDriver(b.Database.Type); !ok {
		return fmt.Errorf("unsupported database type %q", b.Database.Type)
	}
	if b.Server.Port < 1 || b.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}
	if b.Server.SSL.Enable {
		if strings.TrimSpace(b.Server.SSL.KeyPath) == "" || strings.TrimSpace(b.Server.SSL.CrtPath) == "" {
			return fmt.Errorf("server.ssl.key_path and server.ssl.crt_path are required when SSL is enabled")
		}
	}
	if b.Server.Rate.RPS < 0 || b.Server.Rate.Burst < 0 {
		return fmt.Errorf("server.rate.rps and server.rate.burst cannot be negative")
	}
	if b.Server.Timeout.Request < 0 || b.Server.Timeout.Shutdown < 0 {
		return fmt.Errorf("server.timeout values cannot be negative")
	}
	if b.Redis != nil && b.Redis.Enable && strings.TrimSpace(b.Redis.Addr) == "" {
		return fmt.Errorf("redis.addr is required when redis.enable is true")
	}
	if b.Job != nil && b.Job.ScriptRepo != nil && b.Job.ScriptRepo.Enable {
		sr := b.Job.ScriptRepo
		if strings.TrimSpace(sr.URL) == "" {
			return fmt.Errorf("job.script_repo.url is required when job.script_repo.enable is true")
		}
		if strings.TrimSpace(sr.Dir) == "" {
			return fmt.Errorf("job.script_repo.dir is required when job.script_repo.enable is true")
		}
		switch strings.ToLower(strings.TrimSpace(sr.AuthType)) {
		case "", "none", "http", "ssh":
		default:
			return fmt.Errorf("job.script_repo.auth_type must be one of none, http, ssh")
		}
		if sr.Timeout < 0 {
			return fmt.Errorf("job.script_repo.timeout cannot be negative")
		}
	}
	if b.Job != nil && b.Job.MaxConcurrentScripts < 0 {
		return fmt.Errorf("job.max_concurrent_scripts cannot be negative")
	}
	if b.CMDB != nil {
		if b.CMDB.SSHTimeout < 0 {
			return fmt.Errorf("cmdb.ssh_timeout cannot be negative")
		}
		hasCert := strings.TrimSpace(b.CMDB.WinRM.ClientCert) != ""
		hasKey := strings.TrimSpace(b.CMDB.WinRM.ClientKey) != ""
		if hasCert != hasKey {
			return fmt.Errorf("cmdb.winrm.client_cert and cmdb.winrm.client_key must be configured together")
		}
		// Remote execution is passwordless: onboarding needs the private key so
		// the same identity can later run scripts. ssh_password is only a
		// first-contact fallback for installing the key and is never persisted.
		if strings.TrimSpace(b.CMDB.SSHPrivateKey) == "" &&
			(strings.TrimSpace(b.CMDB.SSHPassword) != "" || len(b.CMDB.PublicKeys) > 0) {
			return fmt.Errorf("cmdb.ssh_private_key is required for passwordless SSH execution")
		}
	}
	if b.Security == nil {
		b.Security = &SecurityConfig{}
	}
	if b.Security.CORS == nil {
		b.Security.CORS = &AllowConfig{}
	}
	if b.IAM == nil {
		b.IAM = &IAMConfig{}
	}
	accessMethod, err := SigningMethod(b.IAM.Token.AccessMethod)
	if err != nil {
		return err
	}
	if strings.TrimSpace(b.IAM.Token.RefreshMethod) != "" {
		refreshMethod, err := SigningMethod(b.IAM.Token.RefreshMethod)
		if err != nil {
			return err
		}
		if refreshMethod.Alg() != accessMethod.Alg() {
			return fmt.Errorf("security.token.refresh_method must match access_method %q", accessMethod.Alg())
		}
	}
	if strings.TrimSpace(b.IAM.Token.PrivateKey) == "" {
		return fmt.Errorf("security.token.private_key is required")
	}
	if b.IAM.Login.MaxFailedAttempts < 0 {
		return fmt.Errorf("security.login.max_failed_attempts cannot be negative")
	}
	if b.IAM.Login.LockDuration < 0 {
		return fmt.Errorf("security.login.lock_duration cannot be negative")
	}
	if b.IAM.Login.MaxFailedAttempts > 0 && b.IAM.Login.LockDuration <= 0 {
		return fmt.Errorf("security.login.lock_duration is required when max_failed_attempts is enabled")
	}
	if b.IAM.Password.StrengthLevel < 0 || b.IAM.Password.StrengthLevel > 3 {
		return fmt.Errorf("security.password.strength_level must be between 0 and 3")
	}

	// CORS: a wildcard origin combined with credentials is never allowed, and
	// production must list the browser origins explicitly.
	if b.Security.CORS != nil {
		for _, origin := range b.Security.CORS.AllowOrigins {
			if strings.TrimSpace(origin) != "*" {
				continue
			}
			if b.Security.CORS.AllowCredentials {
				return fmt.Errorf("security.cors.allow_origins cannot contain \"*\" when allow_credentials is true")
			}
			if b.Server.Mode == ServerModeProd {
				return fmt.Errorf("security.cors.allow_origins cannot contain \"*\" when server.mode is prod; list the frontend origins explicitly")
			}
		}
	}

	if b.Server.Mode == ServerModeProd {
		if b.Server.Swagger {
			return fmt.Errorf("server.swagger must be false when server.mode is prod")
		}
		if !b.Server.SSL.Enable && !b.Server.BehindTLSProxy {
			return fmt.Errorf("server.mode=prod requires server.ssl.enable=true or server.behind_tls_proxy=true (terminate TLS at a trusted proxy)")
		}
		if !b.Security.HostGuard.Enable || len(b.Security.HostGuard.TrustedHosts) == 0 {
			return fmt.Errorf("server.mode=prod requires security.host_guard.enable=true with a non-empty trusted_hosts list")
		}
		if b.Server.Rate.RPS <= 0 {
			return fmt.Errorf("server.mode=prod requires server.rate.rps > 0")
		}
		if b.Server.Timeout.Request <= 0 {
			return fmt.Errorf("server.mode=prod requires server.timeout.request > 0")
		}
		host := strings.TrimSpace(b.Server.Host)
		if (host == "" || host == "0.0.0.0" || host == "::") && !b.Server.BehindTLSProxy {
			return fmt.Errorf("server.mode=prod must not bind to %q without server.behind_tls_proxy=true", host)
		}
		privateKey := strings.TrimSpace(b.IAM.Token.PrivateKey)
		if !strings.Contains(privateKey, "-----BEGIN") && !filepath.IsAbs(privateKey) {
			return fmt.Errorf("server.mode=prod requires security.token.private_key to be an absolute path (inject it from a secret store)")
		}
	}

	if b.Log == nil {
		b.Log = &logx.Options{}
	}
	return nil
}

// SSLConfig SSL配置
type SSLConfig struct {
	Enable   bool   `yaml:"enable"`
	KeyPath  string `yaml:"key_path"`
	CrtPath  string `yaml:"crt_path"`
	Password string `yaml:"password"`
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// 每秒请求数
	RPS float64 `yaml:"rps"`

	// 突发请求数
	Burst int `yaml:"burst"`
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	Request  time.Duration `yaml:"request"`  // 请求处理超时时间(秒)
	Shutdown time.Duration `yaml:"shutdown"` // 服务关闭超时时间(秒)
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// Mode selects the security baseline: "dev" (default) or "prod".
	// Production mode refuses to start on insecure defaults (swagger, wildcard
	// CORS, missing HostGuard, plaintext-only exposure, relative key paths).
	Mode string `yaml:"mode"`
	// BehindTLSProxy indicates that TLS is terminated by a trusted reverse proxy
	// in front of grain; production requires either this or server.ssl.enable.
	BehindTLSProxy bool            `yaml:"behind_tls_proxy"`
	SSL            SSLConfig       `yaml:"ssl"`
	Rate           RateLimitConfig `yaml:"rate"`
	Timeout        TimeoutConfig   `yaml:"timeout"`
	Swagger        bool            `yaml:"swagger"`
	EnableMetrics  bool            `yaml:"enable_metrics"`
	EnablePprof    bool            `yaml:"enable_pprof"`
	TrustedProxies []string        `yaml:"trusted_proxies"`
}

// AllowConfig CORS配置
type AllowConfig struct {
	AllowOrigins     []string `yaml:"allow_origins"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	AllowMethods     []string `yaml:"allow_methods"`
	AllowHeaders     []string `yaml:"allow_headers"`
	ExposeHeaders    []string `yaml:"expose_headers"`
}

type HostGuardConfig struct {
	Enable       bool     `yaml:"enable"`        // 是否启用host请求头防护
	TrustedHosts []string `yaml:"trusted_hosts"` // 受信任的host列表
}

// TimestampConfig 时间戳验证配置
type TimestampConfig struct {
	CheckTimestamp  bool          `yaml:"check_timestamp"`  // 是否检查时间戳
	Tolerance       time.Duration `yaml:"tolerance"`        // 时间容忍度(毫秒)
	FutureTolerance time.Duration `yaml:"future_tolerance"` // 未来时间容忍度(毫秒)
}

// TokenConfig Token配置
type TokenConfig struct {
	AccessDuration  time.Duration `yaml:"access_duration"`  // Token有效时间
	RefreshDuration time.Duration `yaml:"refresh_duration"` // 刷新令牌有效时间
	AccessMethod    string        `yaml:"access_method"`    // 访问令牌签名方法
	RefreshMethod   string        `yaml:"refresh_method"`   // 刷新令牌签名方法
	Issuer          string        `yaml:"issuer"`
	Audience        string        `yaml:"audience"`
	PrivateKey      string        `yaml:"private_key"` // PEM text or path
	PublicKey       string        `yaml:"public_key"`  // optional PEM text or path
	KeyID           string        `yaml:"key_id"`
}

// LoginSecurityConfig 登录安全配置
type LoginSecurityConfig struct {
	MaxFailedAttempts int           `yaml:"max_failed_attempts"` // 最大登录失败次数
	LockDuration      time.Duration `yaml:"lock_duration"`       // 锁定时长
}

// PasswordConfig 密码配置
type PasswordConfig struct {
	StrengthLevel int `yaml:"strength_level"` // 密码强度等级
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	CORS      *AllowConfig    `yaml:"cors"`       // cors 配置
	HostGuard HostGuardConfig `yaml:"host_guard"` // host请求头配置
	Timestamp TimestampConfig `yaml:"timestamp"`  // 时间戳验证配置

}

type IAMConfig struct {
	Token    TokenConfig         `yaml:"token"`    // Token配置
	Login    LoginSecurityConfig `yaml:"login"`    // 登录安全配置
	Password PasswordConfig      `yaml:"password"` // 密码配置
}
