package iam

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"gorm.io/gorm"

	"grain/pkg/db"
)

// ==================== AutoMigrate ====================

// AutoMigrate runs the database migration for all persistent models
func AutoMigrate(gormdb *gorm.DB) error {
	return gormdb.AutoMigrate(
		&apiPO{},
		&rolePO{},
		&userPO{},
		&menuPO{},
		&buttonPO{},
		&loginRecordPO{},
		&TokenRevocationOutboxPO{},
		&PolicyRevisionPO{},
	)
}

// ==================== API persistent model ====================

type apiPO struct {
	db.StandardModel
	URL    string `gorm:"column:url;type:varchar(150);not null;uniqueIndex:idx_api_url_method;comment:HTTP URL" json:"url"`
	Method string `gorm:"column:method;type:varchar(10);not null;uniqueIndex:idx_api_url_method;comment:request method" json:"method"`
	Label  string `gorm:"column:label;type:varchar(50);not null;index:label;comment:label" json:"label"`
	Descr  string `gorm:"column:descr;type:varchar(254);comment:description" json:"descr"`
}

func (apiPO) TableName() string {
	return "iam_api"
}

func (m *apiPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("url", m.URL),
			slog.String("method", m.Method),
			slog.String("label", m.Label),
			slog.String("descr", m.Descr),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *apiPO) ToUpdateMap() map[string]any {
	return map[string]any{
		"url":        m.URL,
		"method":     m.Method,
		"label":      m.Label,
		"descr":      m.Descr,
		"updated_at": time.Now(),
	}
}

// ==================== User persistent model ====================

type userPO struct {
	db.SoftDeleteModel
	Username string  `gorm:"column:username;type:varchar(50);not null;uniqueIndex;comment:username" json:"username"`
	Password string  `gorm:"column:password;type:varchar(150);not null;comment:password" json:"-"`
	IsActive bool    `gorm:"column:is_active;type:boolean;comment:is active" json:"is_active"`
	RoleID   uint64  `gorm:"column:role_id;not null;index:idx_user_role;comment:role ID" json:"role_id"`
	Role     *rolePO `gorm:"foreignKey:RoleID;references:ID;constraint:OnDelete:RESTRICT" json:"role,omitempty"`
	// TokenVersion is the authoritative database copy of the token version (session revocation counter).
	// The version key in Redis is a hot cache; when the cache is lost, this value is the source of truth to prevent revoked tokens from coming back to life.
	TokenVersion uint64 `gorm:"column:token_version;not null;default:0;comment:token version (session revocation counter)" json:"-"`
}

func (userPO) TableName() string {
	return "iam_user"
}

func (m *userPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("username", m.Username),
			slog.Bool("is_active", m.IsActive),
			slog.Uint64("role_id", m.RoleID),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *userPO) ToUpdateMap() map[string]any {
	upmap := map[string]any{
		"username":   m.Username,
		"is_active":  m.IsActive,
		"role_id":    m.RoleID,
		"updated_at": time.Now(),
	}
	if m.Password != "" {
		upmap["password"] = m.Password
	}
	return upmap
}

// ==================== Role persistent model ====================

type rolePO struct {
	db.StandardModel
	Name    string     `gorm:"column:name;type:varchar(50);not null;uniqueIndex;comment:name" json:"name"`
	Descr   string     `gorm:"column:descr;type:varchar(254);comment:description" json:"descr"`
	Apis    []apiPO    `gorm:"many2many:iam_role_api;joinForeignKey:role_id;joinReferences:api_id;constraint:OnDelete:CASCADE"`
	Menus   []menuPO   `gorm:"many2many:iam_role_menu;joinForeignKey:role_id;joinReferences:menu_id;constraint:OnDelete:CASCADE"`
	Buttons []buttonPO `gorm:"many2many:iam_role_button;joinForeignKey:role_id;joinReferences:button_id;constraint:OnDelete:CASCADE"`
}

func (rolePO) TableName() string {
	return "iam_role"
}

func (m *rolePO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	apis := make([]slog.Attr, 0, len(m.Apis))
	for i, v := range m.Apis {
		apis = append(apis, slog.Uint64(strconv.Itoa(i), uint64(v.ID)))
	}
	menus := make([]slog.Attr, 0, len(m.Menus))
	for i, v := range m.Menus {
		menus = append(menus, slog.Uint64(strconv.Itoa(i), uint64(v.ID)))
	}
	buttons := make([]slog.Attr, 0, len(m.Buttons))
	for i, v := range m.Buttons {
		buttons = append(buttons, slog.Uint64(strconv.Itoa(i), uint64(v.ID)))
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("name", m.Name),
			slog.String("descr", m.Descr),
			slog.GroupAttrs("apis", apis...),
			slog.GroupAttrs("menus", menus...),
			slog.GroupAttrs("buttons", buttons...),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *rolePO) ToUpdateMap() map[string]any {
	return map[string]any{
		"name":       m.Name,
		"descr":      m.Descr,
		"updated_at": time.Now(),
	}
}

// ==================== Menu persistent model ====================

type MetaSchemas struct {
	Title string `json:"title" example:"User Management"`
	Icon  string `json:"icon" example:"icon"`
}

func (m MetaSchemas) Value() (driver.Value, error) {
	return json.Marshal(m)
}

func (m *MetaSchemas) Scan(value any) error {
	if value == nil {
		*m = MetaSchemas{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("failed to parse MetaSchemas: unsupported type %T", value)
	}
	return json.Unmarshal(bytes, m)
}

func (m *MetaSchemas) Json() string {
	jd, _ := json.Marshal(m)
	return string(jd)
}

func (m *MetaSchemas) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	return slog.GroupValue(
		slog.String("title", m.Title),
		slog.String("icon", m.Icon),
	)
}

func NewMetaSchemas(ms string) (*MetaSchemas, error) {
	if ms == "" {
		return nil, fmt.Errorf("meta is empty")
	}
	var meta MetaSchemas
	err := json.Unmarshal([]byte(ms), &meta)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MetaSchemas: %w", err)
	}
	return &meta, nil
}

type menuPO struct {
	db.StandardModel
	Path      string      `gorm:"column:path;type:varchar(100);not null;uniqueIndex;comment:frontend route" json:"path"`
	Component string      `gorm:"column:component;type:varchar(200);not null;comment:frontend component" json:"component"`
	Name      string      `gorm:"column:name;type:varchar(50);not null;uniqueIndex;comment:name" json:"name"`
	Meta      MetaSchemas `gorm:"column:meta;serializer:json;comment:menu meta" json:"meta"`
	Sort      uint32      `gorm:"column:sort;type:integer;comment:sort" json:"sort"`
	IsActive  bool        `gorm:"column:is_active;type:boolean;comment:is active" json:"is_active"`
	Descr     string      `gorm:"column:descr;type:varchar(254);comment:description" json:"descr"`
	ParentID  *uint64     `gorm:"column:parent_id;index:idx_menu_parent;comment:parent menu ID" json:"parent_id"`
	Parent    *menuPO     `gorm:"foreignKey:ParentID;references:ID;constraint:OnDelete:CASCADE" json:"parent"`
	Apis      []apiPO     `gorm:"many2many:iam_menu_api;joinForeignKey:menu_id;joinReferences:api_id;constraint:OnDelete:CASCADE"`
}

func (menuPO) TableName() string {
	return "iam_menu"
}

func (m *menuPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	apis := make([]slog.Attr, 0, len(m.Apis))
	for i, v := range m.Apis {
		apis = append(apis, slog.Uint64(strconv.Itoa(i), uint64(v.ID)))
	}
	var parentID uint64
	if m.ParentID != nil {
		parentID = *m.ParentID
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("path", m.Path),
			slog.String("component", m.Component),
			slog.String("name", m.Name),
			slog.Any("meta", m.Meta),
			slog.Int64("sort", int64(m.Sort)),
			slog.Bool("is_active", m.IsActive),
			slog.String("descr", m.Descr),
			slog.Uint64("parent_id", parentID),
			slog.GroupAttrs("apis", apis...),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *menuPO) ToUpdateMap() map[string]any {
	return map[string]any{
		"path":       m.Path,
		"component":  m.Component,
		"name":       m.Name,
		"meta":       m.Meta,
		"sort":       m.Sort,
		"is_active":  m.IsActive,
		"descr":      m.Descr,
		"parent_id":  m.ParentID,
		"updated_at": time.Now(),
	}
}

// ==================== Button persistent model ====================

type buttonPO struct {
	db.StandardModel
	Name     string  `gorm:"column:name;type:varchar(50);not null;uniqueIndex;comment:name" json:"name"`
	Sort     uint32  `gorm:"column:sort;type:integer;comment:sort" json:"sort"`
	IsActive bool    `gorm:"column:is_active;type:boolean;comment:is active" json:"is_active"`
	Descr    string  `gorm:"column:descr;type:varchar(254);comment:description" json:"descr"`
	MenuID   uint64  `gorm:"column:menu_id;not null;index:idx_button_menu;comment:menu ID" json:"menu_id"`
	Menu     *menuPO `gorm:"foreignKey:MenuID;references:ID;constraint:OnDelete:CASCADE" json:"menu,omitempty"`
	Apis     []apiPO `gorm:"many2many:iam_button_api;joinForeignKey:button_id;joinReferences:api_id;constraint:OnDelete:CASCADE"`
}

func (buttonPO) TableName() string {
	return "iam_button"
}

func (m *buttonPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	apis := make([]slog.Attr, 0, len(m.Apis))
	for i, v := range m.Apis {
		apis = append(apis, slog.Uint64(strconv.Itoa(i), uint64(v.ID)))
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("name", m.Name),
			slog.Int64("sort", int64(m.Sort)),
			slog.Bool("is_active", m.IsActive),
			slog.String("descr", m.Descr),
			slog.Uint64("menu_id", m.MenuID),
			slog.GroupAttrs("apis", apis...),
		},
	)
	return slog.GroupValue(attrs...)
}

func (m *buttonPO) ToUpdateMap() map[string]any {
	return map[string]any{
		"name":       m.Name,
		"sort":       m.Sort,
		"is_active":  m.IsActive,
		"descr":      m.Descr,
		"menu_id":    m.MenuID,
		"updated_at": time.Now(),
	}
}

// ==================== LoginRecord persistent model ====================

type loginRecordPO struct {
	db.BaseModel
	Username  string    `gorm:"column:username;type:varchar(50);index:idx_login_username;comment:username" json:"username"`
	LoginAt   time.Time `gorm:"column:login_at;autoCreateTime;index:idx_login_at;comment:login time" json:"login_at"`
	IPAddress string    `gorm:"column:ip_address;type:varchar(108);index:idx_login_ip;comment:IP address" json:"ip_address"`
	UserAgent string    `gorm:"column:user_agent;type:varchar(254);comment:client info" json:"user_agent"`
	Status    bool      `gorm:"column:status;type:boolean;index:idx_login_status;comment:login success" json:"status"`
}

func (loginRecordPO) TableName() string {
	return "iam_login_record"
}

func (m *loginRecordPO) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("<nil>")
	}
	attrs := slices.Concat(
		m.LogAttr(),
		[]slog.Attr{
			slog.String("username", m.Username),
			slog.String("login_at", m.LoginAt.Format(time.DateTime)),
			slog.String("ip_address", m.IPAddress),
			slog.String("user_agent", m.UserAgent),
			slog.Bool("status", m.Status),
		},
	)
	return slog.GroupValue(attrs...)
}

// ==================== Token Revocation Outbox persistent model ====================

type TokenRevocationOutboxPO struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	UserID    uint64    `gorm:"column:user_id;not null;index:idx_outbox_user" json:"user_id"`
	Version   uint64    `gorm:"column:version;not null" json:"version"`
	Status    string    `gorm:"column:status;type:varchar(20);not null;default:'pending';index:idx_outbox_status" json:"status"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (TokenRevocationOutboxPO) TableName() string {
	return "iam_token_revocation_outbox"
}

// ==================== Policy Revision persistent model ====================

type PolicyRevisionPO struct {
	ID        uint64    `gorm:"column:id;primaryKey" json:"id"`
	Revision  uint64    `gorm:"column:revision;not null" json:"revision"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (PolicyRevisionPO) TableName() string {
	return "iam_policy_revision"
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.DateTime)
}
