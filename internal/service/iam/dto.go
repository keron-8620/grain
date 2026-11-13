package iam

import (
	biz "grain/internal/biz/iam"
	"grain/internal/service/common"
	"grain/pkg/auth"
)

// 引用公共包定义并导出类型别名，便于 Swagger 文档解析与本包直接使用
type (
	Response          = common.Response
	PageResult        = common.PageResult
	TokenPair         = biz.TokenPair
	User              = biz.User
	Role              = biz.Role
	Menu              = biz.Menu
	Button            = biz.Button
	Api               = biz.Api
	MenuTreeNode      = biz.MenuTreeNode
	PublicKeyResponse = auth.PublicKeyResponse
	JSONWebKeySet     = auth.JSONWebKeySet
)

// UserPageResult 用户分页响应结果
type UserPageResult struct {
	List  []*biz.User `json:"list"`              // 用户列表
	Total int64       `json:"total" example:"1"` // 总用户数
}

// RolePageResult 角色分页响应结果
type RolePageResult struct {
	List  []*biz.Role `json:"list"`              // 角色列表
	Total int64       `json:"total" example:"1"` // 总角色数
}

// MenuPageResult 菜单分页响应结果
type MenuPageResult struct {
	List  []*biz.Menu `json:"list"`              // 菜单列表
	Total int64       `json:"total" example:"1"` // 总菜单数
}

// ButtonPageResult 按钮分页响应结果
type ButtonPageResult struct {
	List  []*biz.Button `json:"list"`              // 按钮列表
	Total int64         `json:"total" example:"1"` // 总按钮数
}

// ApiPageResult 接口分页响应结果
type ApiPageResult struct {
	List  []*biz.Api `json:"list"`              // 接口列表
	Total int64      `json:"total" example:"1"` // 总接口数
}

// ==================== 认证相关 DTO ====================

// LoginReq 用户登录请求
type LoginReq struct {
	Username string `json:"username" binding:"required,min=2,max=64" example:"admin"` // 用户名
	Password string `json:"password" binding:"required,min=6,max=64" example:"123456"` // 密码
}

// LoginResp 用户登录响应
type LoginResp struct {
	User   *biz.User      `json:"user"`   // 登录用户信息
	Tokens *biz.TokenPair `json:"tokens"` // 访问令牌与刷新令牌
}

// RefreshTokenReq 刷新令牌请求
type RefreshTokenReq struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"eyJhbGciOi..."` // 刷新令牌
}

// LogoutReq 用户登出请求
type LogoutReq struct {
	RefreshToken string `json:"refresh_token,omitempty" example:"eyJhbGciOi..."` // 可选：待撤销的刷新令牌
}

// ==================== 用户相关 DTO ====================

// CreateUserReq 创建用户请求
type CreateUserReq struct {
	Username string `json:"username" binding:"required,min=2,max=64" example:"zhangsan"` // 用户名
	Password string `json:"password" binding:"required,min=6,max=64" example:"123456"`   // 密码 (至少6位)
	RoleID   uint64 `json:"role_id" binding:"required" example:"1"`                       // 关联角色ID
	IsActive *bool  `json:"is_active" example:"true"`                                    // 是否启用 (默认启用)
}

// UpdateUserReq 更新用户请求
type UpdateUserReq struct {
	Username string `json:"username,omitempty" example:"zhangsan"` // 用户名
	Password string `json:"password,omitempty" example:"123456"`   // 密码 (可选，重设密码)
	RoleID   uint64 `json:"role_id,omitempty" example:"1"`         // 关联角色ID
	IsActive *bool  `json:"is_active,omitempty" example:"true"`    // 是否启用
}

// ChangePasswordReq 修改当前用户密码请求
type ChangePasswordReq struct {
	OldPassword string `json:"old_password" binding:"required" example:"123456"`         // 旧密码
	NewPassword string `json:"new_password" binding:"required,min=6,max=64" example:"654321"` // 新密码 (至少6位)
}

// ResetPasswordReq 管理员重置用户密码请求
type ResetPasswordReq struct {
	NewPassword string `json:"new_password" binding:"required,min=6,max=64" example:"654321"` // 新密码 (至少6位)
}

// ListUserReq 用户列表查询参数
type ListUserReq struct {
	Page     int    `form:"page,default=1" example:"1"`         // 页码 (从1开始)
	PageSize int    `form:"page_size,default=20" example:"20"`  // 每页条数 (默认20, 最大100)
	Username string `form:"username" example:"admin"`           // 用户名模糊过滤
	RoleID   uint64 `form:"role_id" example:"1"`                // 角色ID过滤
	IsActive *bool  `form:"is_active" example:"true"`           // 状态过滤 (true/false)
	OrderBy  string `form:"order_by" example:"id desc"`         // 排序字段 (如 id desc, created_at asc)
}

// ==================== 角色相关 DTO ====================

// CreateRoleReq 创建角色请求
type CreateRoleReq struct {
	Name      string   `json:"name" binding:"required,min=2,max=64" example:"admin"` // 角色名称
	Descr     string   `json:"descr" example:"系统管理员角色"`                              // 角色描述
	ApiIDs    []uint64 `json:"api_ids" example:"1,2"`                                // 关联 API 接口 ID 列表
	MenuIDs   []uint64 `json:"menu_ids" example:"1,2"`                               // 关联菜单 ID 列表
	ButtonIDs []uint64 `json:"button_ids" example:"1,2"`                             // 关联按钮 ID 列表
}

// UpdateRoleReq 更新角色请求
type UpdateRoleReq struct {
	Name      string   `json:"name" binding:"required,min=2,max=64" example:"admin"` // 角色名称
	Descr     string   `json:"descr" example:"系统管理员角色"`                              // 角色描述
	ApiIDs    []uint64 `json:"api_ids" example:"1,2"`                                // 关联 API 接口 ID 列表
	MenuIDs   []uint64 `json:"menu_ids" example:"1,2"`                               // 关联菜单 ID 列表
	ButtonIDs []uint64 `json:"button_ids" example:"1,2"`                             // 关联按钮 ID 列表
}

// ListRoleReq 角色列表查询参数
type ListRoleReq struct {
	Page     int    `form:"page,default=1" example:"1"`        // 页码
	PageSize int    `form:"page_size,default=20" example:"20"` // 每页条数
	Name     string `form:"name" example:"admin"`              // 角色名称模糊过滤
	OrderBy  string `form:"order_by" example:"id desc"`        // 排序规则
}

// ==================== 菜单相关 DTO ====================

// MenuMetaReq 菜单元数据请求
type MenuMetaReq struct {
	Title string `json:"title" binding:"required" example:"系统管理"` // 菜单标题
	Icon  string `json:"icon" example:"setting"`                  // 图标标识
}

// CreateMenuReq 创建菜单请求
type CreateMenuReq struct {
	Name      string      `json:"name" binding:"required,min=2,max=64" example:"System"` // 菜单名称 (唯一标识)
	Path      string      `json:"path" binding:"required" example:"/system"`              // 前端路由路径
	Component string      `json:"component" example:"Layout"`                             // 前端组件路径
	Meta      MenuMetaReq `json:"meta" binding:"required"`                                // 菜单元数据 (标题/图标)
	Sort      uint32      `json:"sort" example:"1"`                                       // 排序号 (升序)
	IsActive  *bool       `json:"is_active" example:"true"`                               // 是否启用 (默认启用)
	Descr     string      `json:"descr" example:"系统基础配置管理"`                               // 描述说明
	ParentID  *uint64     `json:"parent_id" example:"0"`                                  // 父级菜单ID (0或空为顶级菜单)
	ApiIDs    []uint64    `json:"api_ids" example:"1,2"`                                  // 关联的接口ID列表
}

// UpdateMenuReq 更新菜单请求
type UpdateMenuReq struct {
	Name      string      `json:"name" binding:"required,min=2,max=64" example:"System"` // 菜单名称 (唯一标识)
	Path      string      `json:"path" binding:"required" example:"/system"`              // 前端路由路径
	Component string      `json:"component" example:"Layout"`                             // 前端组件路径
	Meta      MenuMetaReq `json:"meta" binding:"required"`                                // 菜单元数据
	Sort      uint32      `json:"sort" example:"1"`                                       // 排序号
	IsActive  *bool       `json:"is_active" example:"true"`                               // 是否启用
	Descr     string      `json:"descr" example:"系统基础配置管理"`                               // 描述说明
	ParentID  *uint64     `json:"parent_id" example:"0"`                                  // 父级菜单ID
	ApiIDs    []uint64    `json:"api_ids" example:"1,2"`                                  // 关联的接口ID列表
}

// ListMenuReq 菜单列表查询参数
type ListMenuReq struct {
	Page     int    `form:"page,default=1" example:"1"`         // 页码
	PageSize int    `form:"page_size,default=20" example:"20"`  // 每页条数
	Name     string `form:"name" example:"System"`              // 菜单名称过滤
	Path     string `form:"path" example:"/system"`             // 路由路径过滤
	IsActive *bool  `form:"is_active" example:"true"`           // 状态过滤
	OrderBy  string `form:"order_by" example:"sort asc"`        // 排序规则
}

// ==================== 按钮相关 DTO ====================

// CreateButtonReq 创建按钮权限请求
type CreateButtonReq struct {
	Name     string   `json:"name" binding:"required,min=2,max=64" example:"user:add"` // 按钮标识 (唯一名称)
	MenuID   uint64   `json:"menu_id" binding:"required" example:"1"`                   // 所属菜单ID
	Sort     uint32   `json:"sort" example:"1"`                                         // 排序号
	IsActive *bool    `json:"is_active" example:"true"`                                 // 是否启用
	Descr    string   `json:"descr" example:"用户新增按钮"`                                   // 按钮描述
	ApiIDs   []uint64 `json:"api_ids" example:"1,2"`                                    // 关联的接口ID列表
}

// UpdateButtonReq 更新按钮权限请求
type UpdateButtonReq struct {
	Name     string   `json:"name" binding:"required,min=2,max=64" example:"user:add"` // 按钮标识
	MenuID   uint64   `json:"menu_id" binding:"required" example:"1"`                   // 所属菜单ID
	Sort     uint32   `json:"sort" example:"1"`                                         // 排序号
	IsActive *bool    `json:"is_active" example:"true"`                                 // 是否启用
	Descr    string   `json:"descr" example:"用户新增按钮"`                                   // 按钮描述
	ApiIDs   []uint64 `json:"api_ids" example:"1,2"`                                    // 关联的接口ID列表
}

// ListButtonReq 按钮列表查询参数
type ListButtonReq struct {
	Page     int    `form:"page,default=1" example:"1"`         // 页码
	PageSize int    `form:"page_size,default=20" example:"20"`  // 每页条数
	Name     string `form:"name" example:"user:add"`            // 按钮名称过滤
	MenuID   uint64 `form:"menu_id" example:"1"`                // 所属菜单ID过滤
	IsActive *bool  `form:"is_active" example:"true"`           // 状态过滤
	OrderBy  string `form:"order_by" example:"sort asc"`        // 排序规则
}

// ==================== API 接口相关 DTO ====================

// CreateApiReq 创建 API 资源请求
type CreateApiReq struct {
	URL    string `json:"url" binding:"required" example:"/api/v1/users"`     // 路由 URL 匹配路径
	Method string `json:"method" binding:"required" example:"GET"`             // HTTP 请求方法 (GET, POST, PUT, DELETE等)
	Label  string `json:"label" example:"获取用户列表"`                             // 接口显示名称/标签
	Descr  string `json:"descr" example:"分页获取系统用户列表"`                          // 接口功能说明
}

// UpdateApiReq 更新 API 资源请求
type UpdateApiReq struct {
	URL    string `json:"url" binding:"required" example:"/api/v1/users"`     // 路由 URL 匹配路径
	Method string `json:"method" binding:"required" example:"GET"`             // HTTP 请求方法
	Label  string `json:"label" example:"获取用户列表"`                             // 接口显示名称
	Descr  string `json:"descr" example:"分页获取系统用户列表"`                          // 接口功能说明
}

// ListApiReq API 列表查询参数
type ListApiReq struct {
	Page     int    `form:"page,default=1" example:"1"`         // 页码
	PageSize int    `form:"page_size,default=20" example:"20"`  // 每页条数
	URL      string `form:"url" example:"/api/v1/users"`        // URL路径过滤
	Method   string `form:"method" example:"GET"`               // HTTP方法过滤
	Label    string `form:"label" example:"用户"`                 // 接口标签模糊过滤
	OrderBy  string `form:"order_by" example:"id desc"`         // 排序规则
}

// SyncRouteItem 待同步路由条目
type SyncRouteItem struct {
	URL    string `json:"url" binding:"required" example:"/api/v1/users"` // 路由 URL
	Method string `json:"method" binding:"required" example:"GET"`         // 请求方法
	Label  string `json:"label" example:"用户管理"`                           // 接口名称
	Descr  string `json:"descr" example:"获取用户列表"`                         // 接口描述
}

// SyncApisReq 批量同步 API 路由请求
type SyncApisReq struct {
	Routes []SyncRouteItem `json:"routes" binding:"required"` // 路由列表
}

// SyncApisResp 批量同步 API 响应
type SyncApisResp struct {
	Synced int `json:"synced" example:"15"` // 成功同步的新增路由数
}
