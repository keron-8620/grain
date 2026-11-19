package iam

import (
	"strings"

	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/iam"
	"grain/pkg/db"
	"grain/pkg/db/filter"
	"grain/pkg/errorx"
)

// CreateApi 创建 API 接口资源
// @Summary 创建 API 接口资源
// @Description 注册新的 API 路由端点到权限目录并自动在 Casbin 中生成基础访问策略
// @Tags IAM/接口管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateApiReq true "创建API参数"
// @Success 200 {object} Response{data=Api} "创建成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 409 {object} Response "该API路由已存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/apis [post]
func (s *Service) CreateApi(c *gin.Context) {
	var req CreateApiReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	apiDO := &biz.Api{
		URL:    req.URL,
		Method: req.Method,
		Label:  req.Label,
		Descr:  req.Descr,
	}

	created, err := s.biz.Api.Create(c.Request.Context(), apiDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, created)
}

// UpdateApi 更新 API 接口资源
// @Summary 更新 API 接口资源
// @Description 更新 API 路径、请求方法或标签，并自动同步更新 Casbin 策略规则
// @Tags IAM/接口管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "API ID"
// @Param request body UpdateApiReq true "更新API参数"
// @Success 200 {object} Response{data=Api} "更新成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "API不存在"
// @Failure 409 {object} Response "该API路由已被其他记录使用"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/apis/{id} [put]
func (s *Service) UpdateApi(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	var req UpdateApiReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	apiDO := &biz.Api{
		ID:     id,
		URL:    req.URL,
		Method: req.Method,
		Label:  req.Label,
		Descr:  req.Descr,
	}

	updated, err := s.biz.Api.Update(c.Request.Context(), apiDO)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, updated)
}

// DeleteApi 删除 API 接口资源
// @Summary 删除 API 接口资源
// @Description 删除指定 API 路由记录并级联清理对应的 Casbin 策略规则
// @Tags IAM/接口管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "API ID"
// @Success 200 {object} Response "删除成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "API不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/apis/{id} [delete]
func (s *Service) DeleteApi(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	if err := s.biz.Api.Delete(c.Request.Context(), id); err != nil {
		Failure(c, err)
		return
	}

	SuccessMsg(c, "删除API成功", nil)
}

// GetApi 获取 API 接口详情
// @Summary 获取 API 接口详情
// @Description 根据主键获取 API 资源定义及说明
// @Tags IAM/接口管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "API ID"
// @Success 200 {object} Response{data=Api} "获取成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 404 {object} Response "API不存在"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/apis/{id} [get]
func (s *Service) GetApi(c *gin.Context) {
	id, err := parseUintID(c, "id")
	if err != nil {
		Failure(c, err)
		return
	}

	api, err := s.biz.Api.Get(c.Request.Context(), id)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, api)
}

// ListApis 分页查询 API 列表
// @Summary 分页查询 API 列表
// @Description 支持按路径、请求方法、标签过滤及分页排序
// @Tags IAM/接口管理
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param url query string false "路由路径模糊匹配"
// @Param method query string false "HTTP方法 (GET, POST等)"
// @Param label query string false "接口标签模糊匹配"
// @Param order_by query string false "排序规则"
// @Success 200 {object} Response{data=ApiPageResult} "查询成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/apis [get]
func (s *Service) ListApis(c *gin.Context) {
	var req ListApiReq
	if err := c.ShouldBindQuery(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	offset, limit := parsePagination(req.Page, req.PageSize)

	var filters []filter.ListFilter
	if req.URL != "" {
		filters = append(filters, filter.ListFilter{
			Field: "url",
			Op:    filter.ListFilterContains,
			Value: req.URL,
		})
	}
	if req.Method != "" {
		filters = append(filters, filter.ListFilter{
			Field: "method",
			Op:    filter.ListFilterEquals,
			Value: strings.ToUpper(req.Method),
		})
	}
	if req.Label != "" {
		filters = append(filters, filter.ListFilter{
			Field: "label",
			Op:    filter.ListFilterContains,
			Value: req.Label,
		})
	}

	apis, total, err := s.biz.Api.List(c.Request.Context(), db.ListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, ApiPageResult{
		List:  apis,
		Total: total,
	})
}

// SyncApis 批量同步 API 路由
// @Summary 批量同步 API 路由
// @Description 批量导入系统当前实际注册的路由清单，新增未知路由并初始化 Casbin 策略
// @Tags IAM/接口管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body SyncApisReq true "路由列表"
// @Success 200 {object} Response{data=SyncApisResp} "同步成功"
// @Failure 400 {object} Response "参数不合法"
// @Failure 401 {object} Response "未登录或登录已失效"
// @Failure 403 {object} Response "无操作权限"
// @Failure 500 {object} Response "内部服务异常"
// @Router /api/v1/apis/sync [post]
func (s *Service) SyncApis(c *gin.Context) {
	var req SyncApisReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	routes := make([]biz.ApiRoute, len(req.Routes))
	for i, r := range req.Routes {
		routes[i] = biz.ApiRoute{
			URL:    r.URL,
			Method: r.Method,
			Label:  r.Label,
			Descr:  r.Descr,
		}
	}

	count, err := s.biz.Api.SyncRoutes(c.Request.Context(), routes)
	if err != nil {
		Failure(c, err)
		return
	}

	Success(c, SyncApisResp{Synced: count})
}
