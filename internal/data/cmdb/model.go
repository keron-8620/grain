package cmdb

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
		&hostPO{},
	)
}

// ==================== host persistent model ====================

type hostPO struct {
	db.SoftDeleteModel
	Name     string `gorm:"column:name;type:varchar(50);not null;comment:名称" json:"name"`
	Label    string `gorm:"column:label;type:varchar(50);index:idx_host_label;comment:标签" json:"label"`
	HostIP   string `gorm:"column:host_ip;type:varchar(108);index:idx_host_ip_port_user;comment:IP地址" json:"host_ip"`
	HostPort uint16 `gorm:"column:host_port;type:smallint unsigned;index:idx_host_ip_port_user;comment:端口(ssh默认22, winrm默认5985/5986)" json:"host_port"`
	HostUser string `gorm:"column:host_user;type:varchar(50);index:idx_host_ip_port_user;comment:用户名" json:"host_user"`
	Protocol string `gorm:"column:protocol;type:varchar(20);not null;default:'ssh';index:idx_host_protocol;comment:连接协议(ssh/winrm)" json:"protocol"`
	PyPath   string `gorm:"column:py_path;type:varchar(254);comment:python路径" json:"py_path"`
	Remark   string `gorm:"column:remark;type:varchar(254);comment:备注" json:"remark"`
	OSType   string `gorm:"column:os_type;type:varchar(20);default:'linux';comment:操作系统类型" json:"os_type"`
	// SSHHostKey pins the SSH server host key captured during onboarding.
	SSHHostKey string `gorm:"column:ssh_host_key;type:varchar(1024);comment:SSH主机公钥(authorized_keys格式)" json:"ssh_host_key"`
}

func (hostPO) TableName() string {
	return "job_host"
}

func (m *hostPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("name", m.Name),
			slog.String("label", m.Label),
			slog.String("host_ip", m.HostIP),
			slog.Uint64("host_port", uint64(m.HostPort)),
			slog.String("host_user", m.HostUser),
			slog.String("protocol", m.Protocol),
			slog.String("py_path", m.PyPath),
			slog.String("remark", m.Remark),
			slog.String("os_type", m.OSType),
			// Do not log the full host key; the fingerprint is enough for audit.
			slog.Bool("has_ssh_host_key", m.SSHHostKey != ""),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *hostPO) ToUpdateMap() map[string]any {
	return map[string]any{
		"name":         m.Name,
		"label":        m.Label,
		"host_ip":      m.HostIP,
		"host_port":    m.HostPort,
		"host_user":    m.HostUser,
		"protocol":     m.Protocol,
		"py_path":      m.PyPath,
		"remark":       m.Remark,
		"os_type":      m.OSType,
		"ssh_host_key": m.SSHHostKey,
		"updated_at":   time.Now(),
	}
}
