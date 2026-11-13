package iam

import (
	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/iam"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateRole 创建角色
// @Summary 创建角色
// @Description 创建新角色并配置关联的 API 权限、菜单权限和按钮权限
// @Tags IAM/角色管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateRoleReq true "创建角色参数"
// @Success 200 {object} Response{data=Role} "创建成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 409 {object} Response "角色名称已存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/roles [post]
func (s *Service) CreateRole(c *gin.Context) {
	var req CreateRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	roleDO := &biz.Role{
		Name:      req.Name,
		Descr:     req.Descr,
		ApiIDs:    req.ApiIDs,
		MenuIDs:   req.MenuIDs,
		ButtonIDs: req.ButtonIDs,
	}

	created, err := s.biz.Role.Create(c.Request.Context(), roleDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, created)
}

// UpdateRole 更新角色
// @Summary 更新角色
// @Description 更新角色信息及绑定的权限策略，并刷新该角色下所有用户的有效会话
// @Tags IAM/角色管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "角色ID"
// @Param request body UpdateRoleReq true "更新角色参数"
// @Success 200 {object} Response{data=Role} "更新成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "角色不存在"
// @Failure 409 {object} Response "角色名称已被其他记录使用"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/roles/{id} [put]
func (s *Service) UpdateRole(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	var req UpdateRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	roleDO := &biz.Role{
		ID:        id,
		Name:      req.Name,
		Descr:     req.Descr,
		ApiIDs:    req.ApiIDs,
		MenuIDs:   req.MenuIDs,
		ButtonIDs: req.ButtonIDs,
	}

	updated, err := s.biz.Role.Update(c.Request.Context(), roleDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, updated)
}

// DeleteRole 删除角色
// @Summary 删除角色
// @Description 删除指定角色并清理其在 Casbin 中的权限策略映射（角色下有关联用户时不可删除）
// @Tags IAM/角色管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "角色ID"
// @Success 200 {object} Response "删除成功"
// @Failure 400 {object} Response "参数不合法或角色下仍有关联用户"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "角色不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/roles/{id} [delete]
func (s *Service) DeleteRole(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	if err := s.biz.Role.Delete(c.Request.Context(), id); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "删除角色成功", nil)
}

// GetRole 获取角色详情
// @Summary 获取角色详情
// @Description 获取角色详细信息及其关联的 API、菜单、按钮权限集合
// @Tags IAM/角色管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "角色ID"
// @Success 200 {object} Response{data=Role} "获取成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "角色不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/roles/{id} [get]
func (s *Service) GetRole(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	role, err := s.biz.Role.Get(c.Request.Context(), id)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, role)
}

// ListRoles 分页查询角色列表
// @Summary 分页查询角色列表
// @Description 支持按角色名称模糊查询及分页排序
// @Tags IAM/角色管理
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param name query string false "角色名称模糊匹配"
// @Param order_by query string false "排序规则"
// @Success 200 {object} Response{data=RolePageResult} "查询成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/roles [get]
func (s *Service) ListRoles(c *gin.Context) {
	var req ListRoleReq
	if err := c.ShouldBindQuery(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	offset, limit := parsePagination(req.Page, req.PageSize)

	var filters []db.ListFilter
	if req.Name != "" {
		filters = append(filters, db.ListFilter{
			Field: "name",
			Op:    db.ListFilterContains,
			Value: req.Name,
		})
	}

	roles, total, err := s.biz.Role.List(c.Request.Context(), biz.RoleListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, RolePageResult{
		List:  roles,
		Total: total,
	})
}
