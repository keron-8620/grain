package conf

import (
	"fmt"
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
	CORS     *AllowConfig    `yaml:"cors"`
	Log      *logx.Options   `yaml:"log"`
	Security *SecurityConfig `yaml:"security"`
	version  string
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

func (b *Bootstrap) Validate() error {
	if b == nil {
		return fmt.Errorf("bootstrap configuration cannot be nil")
	}
	if b.Server == nil {
		return fmt.Errorf("server configuration is required")
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
	if b.Security == nil {
		b.Security = &SecurityConfig{}
	}
	accessMethod, err := SigningMethod(b.Security.Token.AccessMethod)
	if err != nil {
		return err
	}
	if strings.TrimSpace(b.Security.Token.RefreshMethod) != "" {
		refreshMethod, err := SigningMethod(b.Security.Token.RefreshMethod)
		if err != nil {
			return err
		}
		if refreshMethod.Alg() != accessMethod.Alg() {
			return fmt.Errorf("security.token.refresh_method must match access_method %q", accessMethod.Alg())
		}
	}
	if strings.TrimSpace(b.Security.Token.PrivateKey) == "" {
		return fmt.Errorf("security.token.private_key is required")
	}
	if b.Security.Login.MaxFailedAttempts < 0 {
		return fmt.Errorf("security.login.max_failed_attempts cannot be negative")
	}
	if b.Security.Login.LockDuration < 0 {
		return fmt.Errorf("security.login.lock_duration cannot be negative")
	}
	if b.Security.Login.MaxFailedAttempts > 0 && b.Security.Login.LockDuration <= 0 {
		return fmt.Errorf("security.login.lock_duration is required when max_failed_attempts is enabled")
	}
	if b.Security.Password.StrengthLevel < 0 || b.Security.Password.StrengthLevel > 3 {
		return fmt.Errorf("security.password.strength_level must be between 0 and 3")
	}
	if b.CORS == nil {
		b.CORS = &AllowConfig{}
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
	Host           string          `yaml:"host"`
	Port           int             `yaml:"port"`
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
	HostGuard HostGuardConfig     `yaml:"host_guard"` // host请求头配置
	Timestamp TimestampConfig     `yaml:"timestamp"`  // 时间戳验证配置
	Token     TokenConfig         `yaml:"token"`      // Token配置
	Login     LoginSecurityConfig `yaml:"login"`      // 登录安全配置
	Password  PasswordConfig      `yaml:"password"`   // 密码配置
}
