package iam

import (
	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/iam"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateButton 创建按钮权限
// @Summary 创建按钮权限
// @Description 在指定菜单下创建按钮权限节点并同步 Casbin 授权策略
// @Tags IAM/按钮管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateButtonReq true "创建按钮参数"
// @Success 200 {object} Response{data=Button} "创建成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "关联菜单不存在"
// @Failure 409 {object} Response "按钮名称已存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/buttons [post]
func (s *Service) CreateButton(c *gin.Context) {
	var req CreateButtonReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	btnDO := &biz.Button{
		Name:     req.Name,
		MenuID:   req.MenuID,
		Sort:     req.Sort,
		IsActive: isActive,
		Descr:    req.Descr,
		ApiIDs:   req.ApiIDs,
	}

	created, err := s.biz.Button.Create(c.Request.Context(), btnDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, created)
}

// UpdateButton 更新按钮权限
// @Summary 更新按钮权限
// @Description 更新按钮权限属性、所属菜单或绑定的 API 接口，并同步策略规则
// @Tags IAM/按钮管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "按钮ID"
// @Param request body UpdateButtonReq true "更新按钮参数"
// @Success 200 {object} Response{data=Button} "更新成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "按钮不存在或关联菜单不存在"
// @Failure 409 {object} Response "按钮名称已被其他记录使用"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/buttons/{id} [put]
func (s *Service) UpdateButton(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	var req UpdateButtonReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	btnDO := &biz.Button{
		ID:     id,
		Name:   req.Name,
		MenuID: req.MenuID,
		Sort:   req.Sort,
		Descr:  req.Descr,
		ApiIDs: req.ApiIDs,
	}
	if req.IsActive != nil {
		btnDO.IsActive = *req.IsActive
	}

	updated, err := s.biz.Button.Update(c.Request.Context(), btnDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, updated)
}

// DeleteButton 删除按钮权限
// @Summary 删除按钮权限
// @Description 删除指定按钮并清理其在 Casbin 中的权限继承策略
// @Tags IAM/按钮管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "按钮ID"
// @Success 200 {object} Response "删除成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "按钮不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/buttons/{id} [delete]
func (s *Service) DeleteButton(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	if err := s.biz.Button.Delete(c.Request.Context(), id); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "删除按钮成功", nil)
}

// GetButton 获取按钮详情
// @Summary 获取按钮详情
// @Description 根据主键获取按钮详细信息及其关联菜单与 API 接口列表
// @Tags IAM/按钮管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "按钮ID"
// @Success 200 {object} Response{data=Button} "获取成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "按钮不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/buttons/{id} [get]
func (s *Service) GetButton(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	btn, err := s.biz.Button.Get(c.Request.Context(), id)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, btn)
}

// ListButtons 分页查询按钮列表
// @Summary 分页查询按钮列表
// @Description 支持按名称、所属菜单ID、状态过滤及分页排序
// @Tags IAM/按钮管理
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param name query string false "按钮名称模糊匹配"
// @Param menu_id query int false "所属菜单ID"
// @Param is_active query bool false "状态过滤"
// @Param order_by query string false "排序规则"
// @Success 200 {object} Response{data=ButtonPageResult} "查询成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/buttons [get]
func (s *Service) ListButtons(c *gin.Context) {
	var req ListButtonReq
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
	if req.MenuID > 0 {
		filters = append(filters, db.ListFilter{
			Field: "menu_id",
			Op:    db.ListFilterEquals,
			Value: req.MenuID,
		})
	}
	if req.IsActive != nil {
		filters = append(filters, db.ListFilter{
			Field: "is_active",
			Op:    db.ListFilterEquals,
			Value: *req.IsActive,
		})
	}

	btns, total, err := s.biz.Button.List(c.Request.Context(), biz.ButtonListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, ButtonPageResult{
		List:  btns,
		Total: total,
	})
}
