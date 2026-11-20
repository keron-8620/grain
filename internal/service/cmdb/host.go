package cmdb

import (
	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/cmdb"
	"grain/internal/service/common"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateHost 纳管一台主机
// @Summary 纳管主机
// @Description 创建主机记录；SSH 主机会先尝试部署免密公钥，WinRM 主机按配置校验证书连通性
// @Tags CMDB/主机管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateHostReq true "主机信息"
// @Success 200 {object} common.Response{data=HostResp} "创建成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 409 {object} common.Response "主机连接信息已存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/hosts [post]
func (s *Service) CreateHost(c *gin.Context) {
	if s.host == nil {
		common.Failure(c, errorx.CodeConfigError.Error("CMDB 模块未初始化"))
		return
	}

	var req CreateHostReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	created, err := s.host.Create(c.Request.Context(), &biz.Host{
		Name:     req.Name,
		Label:    req.Label,
		HostIP:   req.HostIP,
		HostPort: req.HostPort,
		HostUser: req.HostUser,
		Protocol: req.Protocol,
		PyPath:   req.PyPath,
		Remark:   req.Remark,
		OSType:   req.OSType,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toHostResp(created))
}

// UpdateHost 更新主机信息
// @Summary 更新主机
// @Description 全量替换主机信息；连接参数变化时会重新执行免密公钥部署或 WinRM 校验
// @Tags CMDB/主机管理
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "主机ID"
// @Param request body UpdateHostReq true "主机信息"
// @Success 200 {object} common.Response{data=HostResp} "更新成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "主机不存在"
// @Failure 409 {object} common.Response "主机连接信息已存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/hosts/{id} [put]
func (s *Service) UpdateHost(c *gin.Context) {
	if s.host == nil {
		common.Failure(c, errorx.CodeConfigError.Error("CMDB 模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	var req UpdateHostReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	// Preserve connection type and OS when the client omits them: defaulting a
	// WinRM host to ssh would silently change how later script executions run.
	existing, err := s.host.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}
	if req.Protocol == "" {
		req.Protocol = existing.Protocol
	}
	if req.OSType == "" {
		req.OSType = existing.OSType
	}
	if req.HostPort == 0 {
		req.HostPort = existing.HostPort
	}

	updated, err := s.host.Update(c.Request.Context(), &biz.Host{
		ID:       id,
		Name:     req.Name,
		Label:    req.Label,
		HostIP:   req.HostIP,
		HostPort: req.HostPort,
		HostUser: req.HostUser,
		Protocol: req.Protocol,
		PyPath:   req.PyPath,
		Remark:   req.Remark,
		OSType:   req.OSType,
		// Preserve the pinned host key; only onboarding refreshes it.
		HostKey: existing.HostKey,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toHostResp(updated))
}

// RefreshHostKey 刷新 SSH 主机密钥
// @Summary 刷新主机密钥
// @Description 重新连接 SSH 主机并重新记录主机公钥；用于主机重装或密钥轮换后恢复远程执行
// @Tags CMDB/主机管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "主机ID"
// @Success 200 {object} common.Response{data=HostResp} "刷新成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "主机不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/hosts/{id}/refresh-key [post]
func (s *Service) RefreshHostKey(c *gin.Context) {
	if s.host == nil {
		common.Failure(c, errorx.CodeConfigError.Error("CMDB 模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	host, err := s.host.RefreshHostKey(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toHostResp(host))
}

// DeleteHost 删除主机
// @Summary 删除主机
// @Description 软删除主机记录并清理 Ansible host_vars
// @Tags CMDB/主机管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "主机ID"
// @Success 200 {object} common.Response "删除成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "主机不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/hosts/{id} [delete]
func (s *Service) DeleteHost(c *gin.Context) {
	if s.host == nil {
		common.Failure(c, errorx.CodeConfigError.Error("CMDB 模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	if err := s.host.Delete(c.Request.Context(), id); err != nil {
		common.Failure(c, err)
		return
	}
	common.SuccessMsg(c, "删除主机成功", nil)
}

// GetHost 获取主机详情
// @Summary 获取主机
// @Description 根据主键获取主机连接信息
// @Tags CMDB/主机管理
// @Security BearerAuth
// @Produce json
// @Param id path int true "主机ID"
// @Success 200 {object} common.Response{data=HostResp} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "主机不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/hosts/{id} [get]
func (s *Service) GetHost(c *gin.Context) {
	if s.host == nil {
		common.Failure(c, errorx.CodeConfigError.Error("CMDB 模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	host, err := s.host.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toHostResp(host))
}

// ListHosts 分页查询主机
// @Summary 主机列表
// @Description 按名称、标签、IP、协议、操作系统分页筛选主机
// @Tags CMDB/主机管理
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param name query string false "名称模糊匹配"
// @Param label query string false "标签精确匹配"
// @Param host_ip query string false "IP模糊匹配"
// @Param protocol query string false "连接协议 (ssh/winrm)"
// @Param os_type query string false "操作系统 (linux/windows)"
// @Param order_by query string false "排序规则"
// @Success 200 {object} common.Response{data=HostPageResult} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/hosts [get]
func (s *Service) ListHosts(c *gin.Context) {
	if s.host == nil {
		common.Failure(c, errorx.CodeConfigError.Error("CMDB 模块未初始化"))
		return
	}

	var req ListHostReq
	if err := c.ShouldBindQuery(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	offset, limit := common.ParsePagination(req.Page, req.PageSize)

	filters := make([]db.ListFilter, 0, 5)
	if req.Name != "" {
		filters = append(filters, db.ListFilter{Field: "name", Op: db.ListFilterContains, Value: req.Name})
	}
	if req.Label != "" {
		filters = append(filters, db.ListFilter{Field: "label", Op: db.ListFilterEquals, Value: req.Label})
	}
	if req.HostIP != "" {
		filters = append(filters, db.ListFilter{Field: "host_ip", Op: db.ListFilterContains, Value: req.HostIP})
	}
	if req.Protocol != "" {
		filters = append(filters, db.ListFilter{Field: "protocol", Op: db.ListFilterEquals, Value: req.Protocol})
	}
	if req.OSType != "" {
		filters = append(filters, db.ListFilter{Field: "os_type", Op: db.ListFilterEquals, Value: req.OSType})
	}

	hosts, total, err := s.host.List(c.Request.Context(), db.ListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}

	common.Success(c, HostPageResult{List: toHostRespList(hosts), Total: total})
}
