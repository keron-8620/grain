package conf

import (
	"time"

	"grain/pkg/db"
	"grain/pkg/logx"
)

type Bootstrap struct {
	Server   *ServerConfig   `yaml:"server"`
	Database *db.DBConf      `yaml:"database"`
	CORS     *AllowConfig    `yaml:"cors"`
	Log      *logx.Options   `yaml:"log"`
	Security *SecurityConfig `yaml:"security"`
	version  string
}

func (b *Bootstrap) SetVersion(v string) {
	b.version = v
}

func (b *Bootstrap) GetVersion() string {
	return b.version
}

func (b *Bootstrap) Validate() error {
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
