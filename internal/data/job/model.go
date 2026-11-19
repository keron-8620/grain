package job

import (
	"log/slog"
	"slices"
	"time"

	"gorm.io/gorm"

	"grain/pkg/db"
)

// ==================== AutoMigrate ====================

// AutoMigrate runs the database migration for all persistent models
func AutoMigrate(gormdb *gorm.DB) error {
	return gormdb.AutoMigrate(
		&scriptPO{},
		&scriptRecordPO{},
		&schedulePO{},
	)
}

// ==================== script persistent model ====================

type scriptPO struct {
	db.SoftDeleteModel
	Name      string `gorm:"column:name;type:varchar(50);not null;index:idx_script_project_label_name;comment:名称" json:"name"`
	Descr     string `gorm:"column:descr;type:varchar(254);comment:描述" json:"descr"`
	ParamDesc string `gorm:"column:param_desc;type:varchar(254);comment:参数描述" json:"param_desc"`
	Project   string `gorm:"column:project;type:varchar(50);index:idx_script_project_label_name;comment:项目" json:"project"`
	Label     string `gorm:"column:label;type:varchar(50);index:idx_script_project_label_name;comment:标签" json:"label"`
	Language  string `gorm:"column:language;type:varchar(50);comment:脚本语言" json:"language"`
	Status    bool   `gorm:"column:status;type:boolean;comment:是否启用" json:"status"`
	Username  string `gorm:"column:username;type:varchar(50);comment:用户名" json:"username"`
}

func (m *scriptPO) TableName() string {
	return "job_script"
}

func (m *scriptPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("name", m.Name),
			slog.String("descr", m.Descr),
			slog.String("param_desc", m.ParamDesc),
			slog.String("project", m.Project),
			slog.String("label", m.Label),
			slog.String("language", m.Language),
			slog.Bool("status", m.Status),
			slog.String("username", m.Username),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *scriptPO) ToUpdateMap() map[string]any {
	return map[string]any{
		"name":       m.Name,
		"descr":      m.Descr,
		"param_desc": m.ParamDesc,
		"project":    m.Project,
		"label":      m.Label,
		"language":   m.Language,
		"status":     m.Status,
		"username":   m.Username,
		"updated_at": time.Now(),
	}
}

// ==================== script record persistent model ====================

type scriptRecordPO struct {
	db.StandardModel
	TriggerType  string    `gorm:"column:trigger_type;type:varchar(20);comment:触发类型(cron/api)" json:"trigger_type"`
	Status       int       `gorm:"column:status;type:tinyint;not null;default:0;comment:执行状态(0-待执行,1-执行中,2-成功,3-失败,4-超时,5-崩溃)" json:"status"`
	ExitCode     int       `gorm:"column:exit_code;comment:退出码" json:"exit_code"`
	EnvVars      string    `gorm:"column:env_vars;type:json;comment:环境变量(JSON对象)" json:"env_vars"`
	ScriptArgs   string    `gorm:"column:script_args;type:varchar(254);comment:命令行参数(JSON数组)" json:"script_args"`
	WorkDir      string    `gorm:"column:work_dir;type:varchar(255);comment:工作目录" json:"work_dir"`
	Timeout      int       `gorm:"column:timeout;type:int;not null;default:300;comment:超时时间(秒)" json:"timeout"`
	LogName      string    `gorm:"column:log_name;type:varchar(255);comment:日志文件路径" json:"log_name"`
	ErrorMessage string    `gorm:"column:error_message;type:text;comment:错误信息" json:"error_message"`
	Username     string    `gorm:"column:username;type:varchar(50);comment:用户名" json:"username"`
	ScriptID     uint64    `gorm:"column:script_id;not null;index;comment:脚本ID" json:"script_id"`
	Script       *scriptPO `gorm:"foreignKey:ScriptID;references:ID;constraint:OnDelete:CASCADE" json:"script,omitempty"`
}

func (m *scriptRecordPO) TableName() string {
	return "job_script_record"
}

func (m *scriptRecordPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("trigger_type", m.TriggerType),
			slog.Int("status", m.Status),
			slog.Int("exit_code", m.ExitCode),
			slog.String("env_vars", m.EnvVars),
			slog.String("script_args", m.ScriptArgs),
			slog.String("work_dir", m.WorkDir),
			slog.Int("timeout", m.Timeout),
			slog.String("log_name", m.LogName),
			slog.String("error_message", m.ErrorMessage),
			slog.String("username", m.Username),
			slog.Uint64("script_id", m.ScriptID),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *scriptRecordPO) ToUpdateMap() map[string]any {
	return map[string]any{
		"trigger_type":  m.TriggerType,
		"status":        m.Status,
		"exit_code":     m.ExitCode,
		"env_vars":      m.EnvVars,
		"script_args":   m.ScriptArgs,
		"work_dir":      m.WorkDir,
		"timeout":       m.Timeout,
		"log_name":      m.LogName,
		"error_message": m.ErrorMessage,
		"username":      m.Username,
		"script_id":     m.ScriptID,
		"updated_at":    time.Now(),
	}
}

// ==================== schedule persistent model ====================

type schedulePO struct {
	db.StandardModel
	Name          string    `gorm:"column:name;type:varchar(50);not null;uniqueIndex;comment:名称" json:"name"`
	Specification string    `gorm:"column:specification;type:text;comment:条件" json:"specification"`
	IsEnabled     bool      `gorm:"column:is_enabled;type:boolean;comment:是否启用" json:"is_enabled"`
	EnvVars       string    `gorm:"column:env_vars;type:json;comment:环境变量(JSON对象)" json:"env_vars"`
	ScriptArgs    string    `gorm:"column:script_args;type:varchar(254);comment:命令行参数" json:"script_args"`
	WorkDir       string    `gorm:"column:work_dir;type:varchar(255);comment:工作目录" json:"work_dir"`
	Timeout       int       `gorm:"column:timeout;type:int;not null;default:300;comment:超时时间(秒)" json:"timeout"`
	IsRetry       bool      `gorm:"column:is_retry;type:boolean;default:false;comment:是否启用重试" json:"is_retry"`
	RetryInterval int       `gorm:"column:retry_interval;type:int;default:60;comment:重试间隔(秒)" json:"retry_interval"`
	MaxRetries    int       `gorm:"column:max_retries;type:int;default:3;comment:最大重试次数" json:"max_retries"`
	Username      string    `gorm:"column:username;type:varchar(50);comment:用户名" json:"username"`
	ScriptID      uint64    `gorm:"column:script_id;not null;index;comment:脚本ID" json:"script_id"`
	Script        *scriptPO `gorm:"foreignKey:ScriptID;references:ID;constraint:OnDelete:RESTRICT" json:"script,omitempty"`
}

func (m *schedulePO) TableName() string {
	return "job_schedule"
}

func (m *schedulePO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("name", m.Name),
			slog.String("specification", m.Specification),
			slog.Bool("is_enabled", m.IsEnabled),
			slog.String("env_vars", m.EnvVars),
			slog.String("script_args", m.ScriptArgs),
			slog.String("work_dir", m.WorkDir),
			slog.Int("timeout", m.Timeout),
			slog.Bool("is_retry", m.IsRetry),
			slog.Int("retry_interval", m.RetryInterval),
			slog.Int("max_retries", m.MaxRetries),
			slog.String("username", m.Username),
			slog.Uint64("script_id", m.ScriptID),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *schedulePO) ToUpdateMap() map[string]any {
	return map[string]any{
		"name":           m.Name,
		"specification":  m.Specification,
		"is_enabled":     m.IsEnabled,
		"env_vars":       m.EnvVars,
		"script_args":    m.ScriptArgs,
		"work_dir":       m.WorkDir,
		"timeout":        m.Timeout,
		"is_retry":       m.IsRetry,
		"retry_interval": m.RetryInterval,
		"max_retries":    m.MaxRetries,
		"username":       m.Username,
		"script_id":      m.ScriptID,
		"updated_at":     time.Now(),
	}
}
