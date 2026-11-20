package job

import (
	"time"

	biz "grain/internal/biz/job"
	"grain/internal/service/common"
)

// ==================== 脚本 ====================

// ScriptResp is the public representation of script metadata.
type ScriptResp struct {
	ID        uint64    `json:"id" example:"1"`
	Name      string    `json:"name" example:"backup"`
	Descr     string    `json:"descr" example:"数据库备份"`
	ParamDesc string    `json:"param_desc" example:"--full"`
	Project   string    `json:"project" example:"ops"`
	Label     string    `json:"label" example:"db"`
	Language  string    `json:"language" example:"shell"`
	Status    bool      `json:"status" example:"true"`
	Username  string    `json:"username" example:"admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ScriptPageResult is a paginated script list.
type ScriptPageResult struct {
	List  []ScriptResp `json:"list"`
	Total int64        `json:"total" example:"1"`
}

// ScriptContentResp carries the script source stored in the repository.
type ScriptContentResp struct {
	Content string `json:"content"`
}

// CreateScriptReq is the request body for creating a script.
type CreateScriptReq struct {
	Name      string `json:"name" binding:"required,min=1,max=50" example:"backup"`
	Descr     string `json:"descr" binding:"omitempty,max=254" example:"数据库备份"`
	ParamDesc string `json:"param_desc" binding:"omitempty,max=254" example:"--full"`
	Project   string `json:"project" binding:"required,min=1,max=50" example:"ops"`
	Label     string `json:"label" binding:"required,min=1,max=50" example:"db"`
	Language  string `json:"language" binding:"omitempty,max=50" example:"shell"`
	Status    *bool  `json:"status" example:"true"`
	Content   string `json:"content" binding:"required" example:"#!/bin/sh\necho hi"`
}

// UpdateScriptReq is the request body for updating script metadata. Content is
// optional; when omitted the stored source is left untouched.
type UpdateScriptReq struct {
	Name      string  `json:"name" binding:"required,min=1,max=50" example:"backup"`
	Descr     string  `json:"descr" binding:"omitempty,max=254" example:"数据库备份"`
	ParamDesc string  `json:"param_desc" binding:"omitempty,max=254" example:"--full"`
	Project   string  `json:"project" binding:"required,min=1,max=50" example:"ops"`
	Label     string  `json:"label" binding:"required,min=1,max=50" example:"db"`
	Language  string  `json:"language" binding:"omitempty,max=50" example:"shell"`
	Status    *bool   `json:"status" example:"true"`
	Content   *string `json:"content" example:"#!/bin/sh\necho hi"`
}

// ListScriptReq is the query string for listing scripts.
type ListScriptReq struct {
	common.PaginationReq
	Project  string `form:"project" example:"ops"`
	Label    string `form:"label" example:"db"`
	Language string `form:"language" example:"shell"`
	Name     string `form:"name" example:"backup"`
	Status   *bool  `form:"status" example:"true"`
}

func toScriptResp(sc *biz.Script) ScriptResp {
	return ScriptResp{
		ID:        sc.ID,
		Name:      sc.Name,
		Descr:     sc.Descr,
		ParamDesc: sc.ParamDesc,
		Project:   sc.Project,
		Label:     sc.Label,
		Language:  sc.Language,
		Status:    sc.Status,
		Username:  sc.Username,
		CreatedAt: sc.CreatedAt,
		UpdatedAt: sc.UpdatedAt,
	}
}

func toScriptRespList(scripts []biz.Script) []ScriptResp {
	res := make([]ScriptResp, 0, len(scripts))
	for i := range scripts {
		res = append(res, toScriptResp(&scripts[i]))
	}
	return res
}

// ==================== 计划任务 ====================

// ScheduleResp is the public representation of a schedule.
type ScheduleResp struct {
	ID            uint64      `json:"id" example:"1"`
	Name          string      `json:"name" example:"nightly-backup"`
	Specification string      `json:"specification" example:"0 2 * * *"`
	IsEnabled     bool        `json:"is_enabled" example:"true"`
	EnvVars       string      `json:"env_vars" example:"{\"MODE\":\"full\"}"`
	ScriptArgs    string      `json:"script_args" example:"--full"`
	WorkDir       string      `json:"work_dir" example:"/tmp"`
	Timeout       int         `json:"timeout" example:"600"`
	IsRetry       bool        `json:"is_retry" example:"false"`
	RetryInterval int         `json:"retry_interval" example:"60"`
	MaxRetries    int         `json:"max_retries" example:"3"`
	Username      string      `json:"username" example:"admin"`
	HostID        uint64      `json:"host_id" example:"0"`
	ScriptID      uint64      `json:"script_id" example:"1"`
	Script        *ScriptResp `json:"script,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// SchedulePageResult is a paginated schedule list.
type SchedulePageResult struct {
	List  []ScheduleResp `json:"list"`
	Total int64          `json:"total" example:"1"`
}

// CreateScheduleReq is the request body for creating a schedule.
type CreateScheduleReq struct {
	Name          string `json:"name" binding:"required,min=1,max=100" example:"nightly-backup"`
	Specification string `json:"specification" binding:"required,max=100" example:"0 2 * * *"`
	IsEnabled     bool   `json:"is_enabled" example:"true"`
	EnvVars       string `json:"env_vars" binding:"omitempty,max=4096" example:"{\"MODE\":\"full\"}"`
	ScriptArgs    string `json:"script_args" binding:"omitempty,max=1000" example:"--full"`
	WorkDir       string `json:"work_dir" binding:"omitempty,max=254" example:"/tmp"`
	Timeout       int    `json:"timeout" binding:"omitempty,min=0,max=43200" example:"600"`
	IsRetry       bool   `json:"is_retry" example:"false"`
	RetryInterval int    `json:"retry_interval" binding:"omitempty,min=0,max=86400" example:"60"`
	MaxRetries    int    `json:"max_retries" binding:"omitempty,min=0,max=10" example:"3"`
	HostID        uint64 `json:"host_id" example:"0"`
	ScriptID      uint64 `json:"script_id" binding:"required" example:"1"`
}

// UpdateScheduleReq is the request body for replacing a schedule.
type UpdateScheduleReq struct {
	Name          string `json:"name" binding:"required,min=1,max=100" example:"nightly-backup"`
	Specification string `json:"specification" binding:"required,max=100" example:"0 2 * * *"`
	IsEnabled     bool   `json:"is_enabled" example:"true"`
	EnvVars       string `json:"env_vars" binding:"omitempty,max=4096" example:"{\"MODE\":\"full\"}"`
	ScriptArgs    string `json:"script_args" binding:"omitempty,max=1000" example:"--full"`
	WorkDir       string `json:"work_dir" binding:"omitempty,max=254" example:"/tmp"`
	Timeout       int    `json:"timeout" binding:"omitempty,min=0,max=43200" example:"600"`
	IsRetry       bool   `json:"is_retry" example:"false"`
	RetryInterval int    `json:"retry_interval" binding:"omitempty,min=0,max=86400" example:"60"`
	MaxRetries    int    `json:"max_retries" binding:"omitempty,min=0,max=10" example:"3"`
	HostID        uint64 `json:"host_id" example:"0"`
	ScriptID      uint64 `json:"script_id" binding:"required" example:"1"`
}

// ListScheduleReq is the query string for listing schedules.
type ListScheduleReq struct {
	common.PaginationReq
	Name      string `form:"name" example:"backup"`
	IsEnabled *bool  `form:"is_enabled" example:"true"`
	ScriptID  uint64 `form:"script_id" example:"1"`
	HostID    uint64 `form:"host_id" example:"0"`
}

func toScheduleResp(s *biz.Schedule) ScheduleResp {
	resp := ScheduleResp{
		ID:            s.ID,
		Name:          s.Name,
		Specification: s.Specification,
		IsEnabled:     s.IsEnabled,
		EnvVars:       s.EnvVars,
		ScriptArgs:    s.ScriptArgs,
		WorkDir:       s.WorkDir,
		Timeout:       s.Timeout,
		IsRetry:       s.IsRetry,
		RetryInterval: s.RetryInterval,
		MaxRetries:    s.MaxRetries,
		Username:      s.Username,
		HostID:        s.HostID,
		ScriptID:      s.ScriptID,
		CreatedAt:     s.CreatedAt,
		UpdatedAt:     s.UpdatedAt,
	}
	if s.Script != nil {
		script := toScriptResp(s.Script)
		resp.Script = &script
	}
	return resp
}

func toScheduleRespList(schedules []biz.Schedule) []ScheduleResp {
	res := make([]ScheduleResp, 0, len(schedules))
	for i := range schedules {
		res = append(res, toScheduleResp(&schedules[i]))
	}
	return res
}

// ==================== 执行记录 ====================

// ScriptRecordResp is the public representation of one script execution.
// EnvVars is intentionally not echoed back: it is write-only input.
type ScriptRecordResp struct {
	ID           uint64      `json:"id" example:"1"`
	TriggerType  string      `json:"trigger_type" example:"api"`
	Status       int         `json:"status" example:"2"`
	StatusText   string      `json:"status_text" example:"success"`
	ExitCode     int         `json:"exit_code" example:"0"`
	ScriptArgs   string      `json:"script_args" example:"--full"`
	WorkDir      string      `json:"work_dir" example:"/tmp"`
	Timeout      int         `json:"timeout" example:"600"`
	LogName      string      `json:"log_name" example:"5f0c....log"`
	ErrorMessage string      `json:"error_message" example:""`
	Username     string      `json:"username" example:"admin"`
	HostID       uint64      `json:"host_id" example:"0"`
	ScriptID     uint64      `json:"script_id" example:"1"`
	Script       *ScriptResp `json:"script,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

// ScriptRecordPageResult is a paginated execution-record list.
type ScriptRecordPageResult struct {
	List  []ScriptRecordResp `json:"list"`
	Total int64              `json:"total" example:"1"`
}

// CreateScriptRecordReq triggers one script execution.
type CreateScriptRecordReq struct {
	ScriptID   uint64 `json:"script_id" binding:"required" example:"1"`
	HostID     uint64 `json:"host_id" example:"0"`
	ScriptArgs string `json:"script_args" binding:"omitempty,max=1000" example:"--full"`
	EnvVars    string `json:"env_vars" binding:"omitempty,max=4096" example:"{\"MODE\":\"full\"}"`
	Timeout    int    `json:"timeout" binding:"omitempty,min=0,max=43200" example:"600"`
	WorkDir    string `json:"work_dir" binding:"omitempty,max=254" example:"/tmp"`
}

// ListScriptRecordReq is the query string for listing execution records.
type ListScriptRecordReq struct {
	common.PaginationReq
	ScriptID    uint64 `form:"script_id" example:"1"`
	HostID      uint64 `form:"host_id" example:"0"`
	Status      *int   `form:"status" example:"2"`
	TriggerType string `form:"trigger_type" binding:"omitempty,oneof=cron api" example:"api"`
	Username    string `form:"username" example:"admin"`
}

func toScriptRecordResp(sr *biz.ScriptRecord) ScriptRecordResp {
	resp := ScriptRecordResp{
		ID:           sr.ID,
		TriggerType:  string(sr.TriggerType),
		Status:       int(sr.Status),
		StatusText:   scriptStatusText(sr.Status),
		ExitCode:     sr.ExitCode,
		ScriptArgs:   sr.ScriptArgs,
		WorkDir:      sr.WorkDir,
		Timeout:      sr.Timeout,
		LogName:      sr.LogName,
		ErrorMessage: sr.ErrorMessage,
		Username:     sr.Username,
		HostID:       sr.HostID,
		ScriptID:     sr.ScriptID,
		CreatedAt:    sr.CreatedAt,
		UpdatedAt:    sr.UpdatedAt,
	}
	if sr.Script != nil {
		script := toScriptResp(sr.Script)
		resp.Script = &script
	}
	return resp
}

func toScriptRecordRespList(records []biz.ScriptRecord) []ScriptRecordResp {
	res := make([]ScriptRecordResp, 0, len(records))
	for i := range records {
		res = append(res, toScriptRecordResp(&records[i]))
	}
	return res
}

func scriptStatusText(status biz.ScriptRecordStatus) string {
	switch status {
	case biz.ScriptRecordStatusPending:
		return "pending"
	case biz.ScriptRecordStatusRunning:
		return "running"
	case biz.ScriptRecordStatusSuccess:
		return "success"
	case biz.ScriptRecordStatusFailed:
		return "failed"
	case biz.ScriptRecordStatusTimeout:
		return "timeout"
	case biz.ScriptRecordStatusCrashed:
		return "crashed"
	case biz.ScriptRecordStatusCancel:
		return "canceled"
	default:
		return "unknown"
	}
}
