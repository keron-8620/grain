package job

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	biz "grain/internal/biz/job"
	"grain/internal/conf"
	"grain/internal/service/common"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// CreateScriptRecord 触发脚本执行
// @Summary 触发脚本执行
// @Description 创建执行记录并异步执行脚本；host_id 为 0 时在本机执行，否则通过 SSH/WinRM 在目标主机执行
// @Tags Job/执行记录
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateScriptRecordReq true "执行参数"
// @Success 200 {object} common.Response{data=ScriptRecordResp} "已创建执行记录"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "脚本不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/script-records [post]
func (s *Service) CreateScriptRecord(c *gin.Context) {
	if s.records == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本执行模块未初始化"))
		return
	}

	username, err := currentUsername(c.Request.Context())
	if err != nil {
		common.Failure(c, err)
		return
	}

	var req CreateScriptRecordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}
	if err := validateEnvVars(req.EnvVars); err != nil {
		common.Failure(c, err)
		return
	}

	record, err := s.records.Create(c.Request.Context(), &biz.ExecuteInfo{
		TriggerType: biz.TriggerTypeAPI,
		ScriptID:    req.ScriptID,
		ScriptArgs:  req.ScriptArgs,
		EnvVars:     req.EnvVars,
		Timeout:     req.Timeout,
		WorkDir:     req.WorkDir,
		Username:    username,
		HostID:      req.HostID,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}

	// Build the response before handing the record to the execution goroutine:
	// Execute mutates status/exit code on the value it receives. A copy keeps
	// the response serialization race-free.
	resp := toScriptRecordResp(record)
	execRecord := *record

	// Execution is detached from the HTTP request: the client gets the record
	// immediately and polls it for status/logs. ExecuteAsync bounds the number
	// of queued executions and marks the record failed if admission is refused.
	execCtx := context.WithoutCancel(c.Request.Context())
	if err := s.records.ExecuteAsync(execCtx, &execRecord); err != nil {
		common.Failure(c, err)
		return
	}

	common.Success(c, resp)
}

// GetScriptRecord 获取执行记录详情
// @Summary 获取执行记录
// @Description 根据主键获取脚本执行状态与结果
// @Tags Job/执行记录
// @Security BearerAuth
// @Produce json
// @Param id path int true "执行记录ID"
// @Success 200 {object} common.Response{data=ScriptRecordResp} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "执行记录不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/script-records/{id} [get]
func (s *Service) GetScriptRecord(c *gin.Context) {
	if s.records == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本执行模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	record, err := s.records.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}
	common.Success(c, toScriptRecordResp(record))
}

// ListScriptRecords 分页查询执行记录
// @Summary 执行记录列表
// @Description 按脚本、主机、状态、触发方式、执行人分页筛选执行记录
// @Tags Job/执行记录
// @Security BearerAuth
// @Produce json
// @Param page query int false "页码 (默认1)"
// @Param page_size query int false "每页数量 (默认20, 最大100)"
// @Param script_id query int false "脚本ID"
// @Param host_id query int false "主机ID"
// @Param status query int false "状态 (0-6)"
// @Param trigger_type query string false "触发方式 (cron/api)"
// @Param username query string false "执行人"
// @Param order_by query string false "排序规则"
// @Success 200 {object} common.Response{data=ScriptRecordPageResult} "查询成功"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/script-records [get]
func (s *Service) ListScriptRecords(c *gin.Context) {
	if s.records == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本执行模块未初始化"))
		return
	}

	var req ListScriptRecordReq
	if err := c.ShouldBindQuery(&req); err != nil {
		common.Failure(c, errorx.CodeInvalidParam.Error("参数校验失败: "+err.Error()))
		return
	}

	offset, limit := common.ParsePagination(req.Page, req.PageSize)

	filters := make([]db.ListFilter, 0, 5)
	if req.ScriptID > 0 {
		filters = append(filters, db.ListFilter{Field: "script_id", Op: db.ListFilterEquals, Value: req.ScriptID})
	}
	if req.HostID > 0 {
		filters = append(filters, db.ListFilter{Field: "host_id", Op: db.ListFilterEquals, Value: req.HostID})
	}
	if req.Status != nil {
		filters = append(filters, db.ListFilter{Field: "status", Op: db.ListFilterEquals, Value: *req.Status})
	}
	if req.TriggerType != "" {
		filters = append(filters, db.ListFilter{Field: "trigger_type", Op: db.ListFilterEquals, Value: req.TriggerType})
	}
	if req.Username != "" {
		filters = append(filters, db.ListFilter{Field: "username", Op: db.ListFilterEquals, Value: req.Username})
	}

	records, total, err := s.records.List(c.Request.Context(), db.ListOptions{
		Offset:   offset,
		PageSize: limit,
		Filters:  filters,
		OrderBy:  req.OrderBy,
	})
	if err != nil {
		common.Failure(c, err)
		return
	}

	common.Success(c, ScriptRecordPageResult{List: toScriptRecordRespList(records), Total: total})
}

// CancelScriptRecord 取消执行
// @Summary 取消执行
// @Description 取消正在等待或运行的脚本执行
// @Tags Job/执行记录
// @Security BearerAuth
// @Produce json
// @Param id path int true "执行记录ID"
// @Success 200 {object} common.Response "已取消"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/script-records/{id}/cancel [post]
func (s *Service) CancelScriptRecord(c *gin.Context) {
	if s.records == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本执行模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	s.records.Cancel(c.Request.Context(), id)
	common.SuccessMsg(c, "已发送取消指令", gin.H{"script_record_id": id})
}

// DownloadScriptRecordLog 下载执行日志
// @Summary 下载执行日志
// @Description 下载脚本执行的 stdout/stderr 日志文件
// @Tags Job/执行记录
// @Security BearerAuth
// @Produce text/plain
// @Param id path int true "执行记录ID"
// @Success 200 {file} file "日志文件"
// @Failure 400 {object} common.Response "参数不合法"
// @Failure 401 {object} common.Response "未登录或登录已失效"
// @Failure 403 {object} common.Response "无操作权限"
// @Failure 404 {object} common.Response "记录或日志不存在"
// @Failure 500 {object} common.Response "内部服务异常"
// @Router /api/v1/script-records/{id}/log [get]
func (s *Service) DownloadScriptRecordLog(c *gin.Context) {
	if s.records == nil {
		common.Failure(c, errorx.CodeConfigError.Error("脚本执行模块未初始化"))
		return
	}

	id, err := common.ParseUintID(c, "id")
	if err != nil {
		common.Failure(c, err)
		return
	}

	record, err := s.records.Get(c.Request.Context(), id)
	if err != nil {
		common.Failure(c, err)
		return
	}

	name := strings.TrimSpace(record.LogName)
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		common.Failure(c, errorx.CodeInvalidParam.Error("执行日志名称非法"))
		return
	}

	logPath := biz.GenerateScriptLogPath(record.CreatedAt, name)
	logRoot := filepath.Join(conf.StorageDir, "logs")
	rel, err := filepath.Rel(logRoot, logPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		common.Failure(c, errorx.CodeInvalidParam.Error("执行日志路径非法"))
		return
	}

	if _, err := os.Stat(logPath); err != nil {
		if os.IsNotExist(err) {
			common.Failure(c, errorx.CodeRecordNotFound.Error("执行日志不存在"))
			return
		}
		common.Failure(c, errorx.Wrap(err, errorx.CodeExternalError, "读取执行日志失败"))
		return
	}

	c.FileAttachment(logPath, fmt.Sprintf("script-record-%d.log", record.ID))
}
