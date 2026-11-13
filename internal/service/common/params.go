package common

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"grain/pkg/db"
	"grain/pkg/errorx"
)

// PaginationReq 基础分页请求参数
type PaginationReq struct {
	Page     int    `form:"page,default=1" example:"1"`         // 页码 (从 1 开始)
	PageSize int    `form:"page_size,default=20" example:"20"`  // 每页条数 (默认 20, 最大 100)
	OrderBy  string `form:"order_by" example:"created_at desc"` // 排序规则
}

// ParseUintID 解析 URL 路径参数为 uint64 主键
func ParseUintID(c *gin.Context, paramName string) (uint64, error) {
	val := c.Param(paramName)
	id, err := strconv.ParseUint(val, 10, 64)
	if err != nil || id == 0 {
		return 0, errorx.CodeInvalidParam.Error("无效的ID参数: " + val)
	}
	return id, nil
}

// ParsePagination 计算分页的 offset 与 limit，并应用默认值与最大条数截断限制
func ParsePagination(page, pageSize int) (offset, limit int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = db.DefaultPageSize
	} else if pageSize > db.MaxPageSize {
		pageSize = db.MaxPageSize
	}
	return (page - 1) * pageSize, pageSize
}
