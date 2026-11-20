package job

import (
	"context"

	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/job"
	"grain/internal/service/common"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateSchedule 创建计划任务
// @Summary 创建计划任务
// @Description 创建 cron 计划任务；启用时立即注册到调度器
// @Tags Job/计划任务
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateScheduleReq true "计划任务参数"
// @Success 200 {object} common.Response{data=ScheduleResp} "创建成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules [post]
func (s *Service) CreateSchedule(c *gin.Context) {
	if s.schedules == nil {
		common.Failure(c, errorx.CodeConfigError.Error("计划任务模块未初始化"))
		return
	}

	username, err := currentUsername(c.Request.Context())
	if err != nil {
		common.Failure(c, err)
		return
	}

	var req CreateScheduleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}
	if err := validateEnvVars(req.EnvVars); err != nil {
		common.Failure(c, err)
		return
	}

	created, err := s.schedules.Create(c.Request.Context(), &biz.Schedule{
		Name:          req.Name,
		Specification: req.Specification,
		IsEnabled:     req.IsEnabled,
		EnvVars:       req.EnvVars,
		ScriptArgs:    req.ScriptArgs,
		WorkDir:       req.WorkDir,
		Timeout:       req.Timeout,
		IsRetry:       req.IsRetry,
		RetryInterval: req.RetryInterval,
		MaxRetries:    req.MaxRetries,
		Username:      username,
		HostID:        req.HostID,
		ScriptID:      req.ScriptID,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toScheduleResp(created))
}

// UpdateSchedule 更新计划任务
// @Summary 更新计划任务
// @Description 全量更新计划任务并重新注册 cron 条目
// @Tags Job/计划任务
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "计划任务ID"
// @Param request body UpdateScheduleReq true "计划任务参数"
// @Success 200 {object} common.Response{data=ScheduleResp} "更新成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "计划任务不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules/{id} [put]
func (s *Service) UpdateSchedule(c *gin.Context) {
	if s.schedules == nil {
		common.Failure(c, errorx.CodeConfigError.Error("计划任务模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	var req UpdateScheduleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}
	if err := validateEnvVars(req.EnvVars); err != nil {
		common.Failure(c, err)
		return
	}

	existing, err := s.schedules.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}

	updated, err := s.schedules.Update(c.Request.Context(), &biz.Schedule{
		ID:            id,
		Name:          req.Name,
		Specification: req.Specification,
		IsEnabled:     req.IsEnabled,
		EnvVars:       req.EnvVars,
		ScriptArgs:    req.ScriptArgs,
		WorkDir:       req.WorkDir,
		Timeout:       req.Timeout,
		IsRetry:       req.IsRetry,
		RetryInterval: req.RetryInterval,
		MaxRetries:    req.MaxRetries,
		Username:      existing.Username,
		HostID:        req.HostID,
		ScriptID:      req.ScriptID,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toScheduleResp(updated))
}

// DeleteSchedule 删除计划任务
// @Summary 删除计划任务
// @Description 删除计划任务并从调度器移除
// @Tags Job/计划任务
// @Security BearerAuth
// @Produce json
// @Param id path int true "计划任务ID"
// @Success 200 {object} common.Response "删除成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "计划任务不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules/{id} [delete]
func (s *Service) DeleteSchedule(c *gin.Context) {
	if s.schedules == nil {
		common.Failure(c, errorx.CodeConfigError.Error("计划任务模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	if err := s.schedules.Delete(c.Request.Context(), id); err != nil {
		common.Failure(c, err)
		return
	}
	common.SuccessMsg(c, "删除计划任务成功", nil)
}

// GetSchedule 获取计划任务详情
// @Summary 获取计划任务
// @Description 根据主键获取计划任务配置
// @Tags Job/计划任务
// @Security BearerAuth
// @Produce json
// @Param id path int true "计划任务ID"
// @Success 200 {object} common.Response{data=ScheduleResp} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "计划任务不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules/{id} [get]
func (s *Service) GetSchedule(c *gin.Context) {
	if s.schedules == nil {
		common.Failure(c, errorx.CodeConfigError.Error("计划任务模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	schedule, err := s.schedules.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toScheduleResp(schedule))
}

// ListSchedules 分页查询计划任务
// @Summary 计划任务列表
// @Description 按名称、启用状态、脚本、主机分页筛选计划任务
// @Tags Job/计划任务
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param name query string false "名称模糊匹配"
// @Param is_enabled query bool false "启用状态"
// @Param script_id query int false "脚本ID"
// @Param host_id query int false "主机ID"
// @Param order_by query string false "排序规则"
// @Success 200 {object} common.Response{data=SchedulePageResult} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules [get]
func (s *Service) ListSchedules(c *gin.Context) {
	if s.schedules == nil {
		common.Failure(c, errorx.CodeConfigError.Error("计划任务模块未初始化"))
		return
	}

	var req ListScheduleReq
	if err := c.ShouldBindQuery(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	offset, limit := common.ParsePagination(req.Page, req.PageSize)

	filters := make([]db.ListFilter, 0, 4)
	if req.Name != "" {
		filters = append(filters, db.ListFilter{Field: "name", Op: db.ListFilterContains, Value: req.Name})
	}
	if req.IsEnabled != nil {
		filters = append(filters, db.ListFilter{Field: "is_enabled", Op: db.ListFilterEquals, Value: *req.IsEnabled})
	}
	if req.ScriptID > 0 {
		filters = append(filters, db.ListFilter{Field: "script_id", Op: db.ListFilterEquals, Value: req.ScriptID})
	}
	if req.HostID > 0 {
		filters = append(filters, db.ListFilter{Field: "host_id", Op: db.ListFilterEquals, Value: req.HostID})
	}

	schedules, total, err := s.schedules.List(c.Request.Context(), db.ListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}

	common.Success(c, SchedulePageResult{List: toScheduleRespList(schedules), Total: total})
}

// EnableSchedule 启用计划任务
// @Summary 启用计划任务
// @Description 启用计划任务并注册到调度器
// @Tags Job/计划任务
// @Security BearerAuth
// @Produce json
// @Param id path int true "计划任务ID"
// @Success 200 {object} common.Response "启用成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "计划任务不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules/{id}/enable [post]
func (s *Service) EnableSchedule(c *gin.Context) {
	s.setScheduleEnabled(c, true)
}

// DisableSchedule 停用计划任务
// @Summary 停用计划任务
// @Description 停用计划任务并从调度器移除
// @Tags Job/计划任务
// @Security BearerAuth
// @Produce json
// @Param id path int true "计划任务ID"
// @Success 200 {object} common.Response "停用成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "计划任务不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules/{id}/disable [post]
func (s *Service) DisableSchedule(c *gin.Context) {
	s.setScheduleEnabled(c, false)
}

func (s *Service) setScheduleEnabled(c *gin.Context, enabled bool) {
	if s.schedules == nil {
		common.Failure(c, errorx.CodeConfigError.Error("计划任务模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	if err := s.schedules.SetEnabled(c.Request.Context(), id, enabled); err != nil {
		common.Failure(c, err)
		return
	}
	msg := "停用计划任务成功"
	if enabled {
		msg = "启用计划任务成功"
	}
	common.SuccessMsg(c, msg, nil)
}

// RunSchedule 立即执行计划任务
// @Summary 立即执行计划任务
// @Description 异步触发一次计划任务执行，立即返回；执行结果写入脚本执行记录
// @Tags Job/计划任务
// @Security BearerAuth
// @Produce json
// @Param id path int true "计划任务ID"
// @Success 202 {object} common.Response "已触发"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "计划任务不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/schedules/{id}/run [post]
func (s *Service) RunSchedule(c *gin.Context) {
	if s.schedules == nil {
		common.Failure(c, errorx.CodeConfigError.Error("计划任务模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	select {
	case s.runSlots <- struct{}{}:
	default:
		common.Failure(c, errorx.CodeRateLimitExceeded.Error("手动触发队列已满，请稍后重试"))
		return
	}

	// The execution may run for hours; detach it from the request lifecycle.
	ctx := context.WithoutCancel(c.Request.Context())
	go func() {
		defer func() { <-s.runSlots }()
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.ErrorContext(ctx, "手动执行计划任务时发生panic",
					"schedule_id", id, "panic", recovered)
			}
		}()
		if err := s.schedules.Run(ctx, id); err != nil {
			s.logger.ErrorContext(ctx, "手动执行计划任务失败",
				"schedule_id", id, "error", err)
		}
	}()

	c.JSON(202, common.Response{Code: 0, Msg: "计划任务已触发", Data: gin.H{"schedule_id": id}})
}
