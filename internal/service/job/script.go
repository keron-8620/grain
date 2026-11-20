package job

import (
	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/job"
	"grain/internal/service/common"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateScript 创建脚本
// @Summary 创建脚本
// @Description 将脚本正文写入配置的存储后端（Git 仓库或本地目录），并保存元数据
// @Tags Job/脚本管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateScriptReq true "脚本信息与正文"
// @Success 200 {object} common.Response{data=ScriptResp} "创建成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 409 {object} common.Response "同名脚本已存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/scripts [post]
func (s *Service) CreateScript(c *gin.Context) {
	if s.scripts == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本模块未初始化"))
		return
	}

	username, err := currentUsername(c.Request.Context())
	if err != nil {
		common.Failure(c, err)
		return
	}

	var req CreateScriptReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	status := true
	if req.Status != nil {
		status = *req.Status
	}

	created, err := s.scripts.Create(c.Request.Context(), &biz.Script{
		Name:      req.Name,
		Descr:     req.Descr,
		ParamDesc: req.ParamDesc,
		Project:   req.Project,
		Label:     req.Label,
		Language:  req.Language,
		Status:    status,
		Username:  username,
	}, []byte(req.Content))
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toScriptResp(created))
}

// UpdateScript 更新脚本
// @Summary 更新脚本
// @Description 全量更新脚本元数据；传入 content 时同时替换仓库中的正文
// @Tags Job/脚本管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "脚本ID"
// @Param request body UpdateScriptReq true "脚本信息"
// @Success 200 {object} common.Response{data=ScriptResp} "更新成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "脚本不存在"
// @Failure 409 {object} common.Response "同名脚本已存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/scripts/{id} [put]
func (s *Service) UpdateScript(c *gin.Context) {
	if s.scripts == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	var req UpdateScriptReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	existing, err := s.scripts.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}

	next := &biz.Script{
		ID:        id,
		Name:      req.Name,
		Descr:     req.Descr,
		ParamDesc: req.ParamDesc,
		Project:   req.Project,
		Label:     req.Label,
		Language:  req.Language,
		Status:    existing.Status,
		Username:  existing.Username,
	}
	if next.Language == "" {
		next.Language = existing.Language
	}
	if req.Status != nil {
		next.Status = *req.Status
	}

	var content []byte
	if req.Content != nil {
		content = []byte(*req.Content)
	}

	updated, err := s.scripts.Update(c.Request.Context(), next, content)
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toScriptResp(updated))
}

// DeleteScript 删除脚本
// @Summary 删除脚本
// @Description 删除脚本元数据及存储后端中的正文
// @Tags Job/脚本管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "脚本ID"
// @Success 200 {object} common.Response "删除成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "脚本不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/scripts/{id} [delete]
func (s *Service) DeleteScript(c *gin.Context) {
	if s.scripts == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	if err := s.scripts.Delete(c.Request.Context(), id); err != nil {
		common.Failure(c, err)
		return
	}
	common.SuccessMsg(c, "删除脚本成功", nil)
}

// GetScript 获取脚本详情
// @Summary 获取脚本
// @Description 根据主键获取脚本元数据
// @Tags Job/脚本管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "脚本ID"
// @Success 200 {object} common.Response{data=ScriptResp} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "脚本不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/scripts/{id} [get]
func (s *Service) GetScript(c *gin.Context) {
	if s.scripts == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	script, err := s.scripts.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toScriptResp(script))
}

// GetScriptContent 获取脚本正文
// @Summary 获取脚本正文
// @Description 从脚本存储后端读取正文
// @Tags Job/脚本管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "脚本ID"
// @Success 200 {object} common.Response{data=ScriptContentResp} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "脚本不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/scripts/{id}/content [get]
func (s *Service) GetScriptContent(c *gin.Context) {
	if s.scripts == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	content, err := s.scripts.GetContent(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, ScriptContentResp{Content: string(content)})
}

// ListScripts 分页查询脚本
// @Summary 脚本列表
// @Description 按项目、标签、语言、名称、状态分页筛选脚本
// @Tags Job/脚本管理
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param project query string false "项目精确匹配"
// @Param label query string false "标签精确匹配"
// @Param language query string false "语言精确匹配"
// @Param name query string false "名称模糊匹配"
// @Param status query bool false "启用状态"
// @Param order_by query string false "排序规则"
// @Success 200 {object} common.Response{data=ScriptPageResult} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/scripts [get]
func (s *Service) ListScripts(c *gin.Context) {
	if s.scripts == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本模块未初始化"))
		return
	}

	var req ListScriptReq
	if err := c.ShouldBindQuery(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	offset, limit := common.ParsePagination(req.Page, req.PageSize)

	filters := make([]db.ListFilter, 0, 5)
	if req.Project != "" {
		filters = append(filters, db.ListFilter{Field: "project", Op: db.ListFilterEquals, Value: req.Project})
	}
	if req.Label != "" {
		filters = append(filters, db.ListFilter{Field: "label", Op: db.ListFilterEquals, Value: req.Label})
	}
	if req.Language != "" {
		filters = append(filters, db.ListFilter{Field: "language", Op: db.ListFilterEquals, Value: req.Language})
	}
	if req.Name != "" {
		filters = append(filters, db.ListFilter{Field: "name", Op: db.ListFilterContains, Value: req.Name})
	}
	if req.Status != nil {
		filters = append(filters, db.ListFilter{Field: "status", Op: db.ListFilterEquals, Value: *req.Status})
	}

	scripts, total, err := s.scripts.List(c.Request.Context(), db.ListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}

	common.Success(c, ScriptPageResult{List: toScriptRespList(scripts), Total: total})
}
