package iam

import (
	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/iam"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateUser 创建系统用户
// @Summary 创建系统用户
// @Description 创建新用户账号并分配初始角色与登录密码
// @Tags IAM/用户管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateUserReq true "创建用户参数"
// @Success 200 {object} Response{data=User} "创建成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 409 {object} Response "用户名已存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/users [post]
func (s *Service) CreateUser(c *gin.Context) {
	var req CreateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	userDO := &biz.User{
		Username: req.Username,
		RoleID:   req.RoleID,
		IsActive: isActive,
	}

	created, err := s.biz.User.Create(c.Request.Context(), userDO, req.Password)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, created)
}

// UpdateUser 更新系统用户信息
// @Summary 更新系统用户信息
// @Description 根据主键更新用户名、分配的角色或账号启用状态
// @Tags IAM/用户管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "用户ID"
// @Param request body UpdateUserReq true "更新用户参数"
// @Success 200 {object} Response{data=User} "更新成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "用户不存在"
// @Failure 409 {object} Response "用户名已被其他记录使用"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/users/{id} [put]
func (s *Service) UpdateUser(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	var req UpdateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	userDO := &biz.User{
		ID:       id,
		Username: req.Username,
		RoleID:   req.RoleID,
		Password: req.Password,
	}
	if req.IsActive != nil {
		userDO.IsActive = *req.IsActive
		userDO.IsActiveSet = true
	}

	updated, err := s.biz.User.Update(c.Request.Context(), userDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, updated)
}

// DeleteUser 删除系统用户
// @Summary 删除系统用户
// @Description 根据主键彻底删除系统用户账号
// @Tags IAM/用户管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "用户ID"
// @Success 200 {object} Response "删除成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "用户不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/users/{id} [delete]
func (s *Service) DeleteUser(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	if err := s.biz.User.Delete(c.Request.Context(), id); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "删除用户成功", nil)
}

// GetUser 获取指定用户详情
// @Summary 获取指定用户详情
// @Description 根据用户主键获取用户脱敏信息与关联角色
// @Tags IAM/用户管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "用户ID"
// @Success 200 {object} Response{data=User} "获取成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "用户不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/users/{id} [get]
func (s *Service) GetUser(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	user, err := s.biz.User.Get(c.Request.Context(), id)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, user)
}

// ListUsers 分页查询系统用户列表
// @Summary 分页查询系统用户列表
// @Description 支持按用户名、角色ID、状态条件筛选及分页排序
// @Tags IAM/用户管理
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param username query string false "用户名模糊匹配"
// @Param role_id query int false "角色ID过滤"
// @Param is_active query bool false "状态过滤"
// @Param order_by query string false "排序规则"
// @Success 200 {object} Response{data=UserPageResult} "查询成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/users [get]
func (s *Service) ListUsers(c *gin.Context) {
	var req ListUserReq
	if err := c.ShouldBindQuery(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	offset, limit := parsePagination(req.Page, req.PageSize)

	var filters []db.ListFilter
	if req.Username != "" {
		filters = append(filters, db.ListFilter{
			Field: "username",
			Op:    db.ListFilterContains,
			Value: req.Username,
		})
	}
	if req.RoleID > 0 {
		filters = append(filters, db.ListFilter{
			Field: "role_id",
			Op:    db.ListFilterEquals,
			Value: req.RoleID,
		})
	}
	if req.IsActive != nil {
		filters = append(filters, db.ListFilter{
			Field: "is_active",
			Op:    db.ListFilterEquals,
			Value: *req.IsActive,
		})
	}

	users, total, err := s.biz.User.List(c.Request.Context(), biz.UserListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, UserPageResult{
		List:  users,
		Total: total,
	})
}

// ChangePassword 修改用户密码
// @Summary 修改用户密码
// @Description 用户通过验证原密码修改为新密码，并将原有的活跃登录会话全部踢出
// @Tags IAM/用户管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "用户ID"
// @Param request body ChangePasswordReq true "修改密码参数"
// @Success 200 {object} Response "密码修改成功"
// @Failure 400 {object} Response "参数不合法或密码强度不足"
// @Failure 401 {object} Response "原密码错误或认证失效"
// @Failure 404 {object} Response "用户不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/users/{id}/change-password [post]
func (s *Service) ChangePassword(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	var req ChangePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	if err := s.biz.User.ChangePassword(c.Request.Context(), id, req.OldPassword, req.NewPassword); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "密码修改成功，所有登录会话已重置", nil)
}

// ResetPassword 管理员重置用户密码
// @Summary 管理员重置用户密码
// @Description 管理员直接重置用户账号登录密码，并强制终止该用户的所有会话
// @Tags IAM/用户管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "用户ID"
// @Param request body ResetPasswordReq true "重置密码参数"
// @Success 200 {object} Response "重置成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "用户不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/users/{id}/reset-password [post]
func (s *Service) ResetPassword(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	var req ResetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	if err := s.biz.User.ResetPassword(c.Request.Context(), id, req.NewPassword); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "密码重置成功", nil)
}
