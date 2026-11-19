package iam

import (
	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/iam"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateMenu 创建系统菜单
// @Summary 创建系统菜单
// @Description 创建新的菜单路由节点并同步 Casbin 菜单与 API 继承权限策略
// @Tags IAM/菜单管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateMenuReq true "创建菜单参数"
// @Success 200 {object} Response{data=Menu} "创建成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 409 {object} Response "菜单名称或路径已存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/menus [post]
func (s *Service) CreateMenu(c *gin.Context) {
	var req CreateMenuReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	menuDO := &biz.Menu{
		Name:      req.Name,
		Path:      req.Path,
		Component: req.Component,
		Meta: biz.MenuMeta{
			Title: req.Meta.Title,
			Icon:  req.Meta.Icon,
		},
		Sort:     req.Sort,
		IsActive: isActive,
		Descr:    req.Descr,
		ParentID: req.ParentID,
		ApiIDs:   req.ApiIDs,
	}

	created, err := s.biz.Menu.Create(c.Request.Context(), menuDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, created)
}

// UpdateMenu 更新系统菜单
// @Summary 更新系统菜单
// @Description 更新菜单属性及父子层级关系（防止循环引用）并同步权限策略
// @Tags IAM/菜单管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "菜单ID"
// @Param request body UpdateMenuReq true "更新菜单参数"
// @Success 200 {object} Response{data=Menu} "更新成功"
// @Failure 400 {object} Response "参数不合法或检测到循环层级"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "菜单不存在"
// @Failure 409 {object} Response "菜单名称或路径已被其他记录使用"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/menus/{id} [put]
func (s *Service) UpdateMenu(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	var req UpdateMenuReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	menuDO := &biz.Menu{
		ID:        id,
		Name:      req.Name,
		Path:      req.Path,
		Component: req.Component,
		Meta: biz.MenuMeta{
			Title: req.Meta.Title,
			Icon:  req.Meta.Icon,
		},
		Sort:     req.Sort,
		Descr:    req.Descr,
		ParentID: req.ParentID,
		ApiIDs:   req.ApiIDs,
	}
	if req.IsActive != nil {
		menuDO.IsActive = *req.IsActive
	}

	updated, err := s.biz.Menu.Update(c.Request.Context(), menuDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, updated)
}

// DeleteMenu 删除系统菜单
// @Summary 删除系统菜单
// @Description 删除菜单（若包含子菜单或关联按钮则禁止删除，需先清理子节点）
// @Tags IAM/菜单管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "菜单ID"
// @Success 200 {object} Response "删除成功"
// @Failure 400 {object} Response "参数不合法或存在关联子菜单/按钮"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "菜单不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/menus/{id} [delete]
func (s *Service) DeleteMenu(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	if err := s.biz.Menu.Delete(c.Request.Context(), id); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "删除菜单成功", nil)
}

// GetMenu 获取指定菜单详情
// @Summary 获取指定菜单详情
// @Description 根据主键获取菜单信息、元数据及绑定的 API 列表
// @Tags IAM/菜单管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "菜单ID"
// @Success 200 {object} Response{data=Menu} "获取成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "菜单不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/menus/{id} [get]
func (s *Service) GetMenu(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	menu, err := s.biz.Menu.Get(c.Request.Context(), id)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, menu)
}

// ListMenus 分页查询菜单列表
// @Summary 分页查询菜单列表
// @Description 支持按名称、路径、状态筛选及分页排序
// @Tags IAM/菜单管理
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param name query string false "菜单名称模糊匹配"
// @Param path query string false "路由路径过滤"
// @Param is_active query bool false "状态过滤"
// @Param order_by query string false "排序规则 (如 sort asc)"
// @Success 200 {object} Response{data=MenuPageResult} "查询成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/menus [get]
func (s *Service) ListMenus(c *gin.Context) {
	var req ListMenuReq
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
	if req.Path != "" {
		filters = append(filters, db.ListFilter{
			Field: "path",
			Op:    db.ListFilterContains,
			Value: req.Path,
		})
	}
	if req.IsActive != nil {
		filters = append(filters, db.ListFilter{
			Field: "is_active",
			Op:    db.ListFilterEquals,
			Value: *req.IsActive,
		})
	}

	menus, total, err := s.biz.Menu.List(c.Request.Context(), db.ListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, MenuPageResult{
		List:  menus,
		Total: total,
	})
}

// GetMenuTree 获取系统菜单树
// @Summary 获取系统菜单树
// @Description 获取系统完整层级嵌套的菜单树结构，按 sort 升序排序
// @Tags IAM/菜单管理
// @Security BearerAuth
// @Produce json
// @Success 200 {object} Response{data=[]MenuTreeNode} "获取成功"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/menus/tree [get]
func (s *Service) GetMenuTree(c *gin.Context) {
	tree, err := s.biz.Menu.ListTree(c.Request.Context())
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, tree)
}
