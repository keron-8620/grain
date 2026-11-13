package common

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"grain/pkg/errorx"
)

// Response 统一 HTTP API 响应结构
type Response struct {
	Code int    `json:"code" example:"0"` // 业务状态码 (0 表示成功)
	Msg  string `json:"msg" example:"ok"` // 状态描述或提示信息
	Data any    `json:"data,omitempty"`   // 响应数据对象
}

// PageResult 通用分页响应包装
type PageResult struct {
	List  any   `json:"list"`             // 列表数据
	Total int64 `json:"total" example:"0"` // 总记录数
}

// Success 统一成功响应输出
func Success(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{
		Code: 0,
		Msg:  "ok",
		Data: data,
	})
}

// SuccessMsg 自定义提示文案的成功响应输出
func SuccessMsg(c *gin.Context, msg string, data any) {
	c.JSON(http.StatusOK, Response{
		Code: 0,
		Msg:  msg,
		Data: data,
	})
}

// Failure 统一异常响应输出，委托给 errorx.RespondWithError 进行标准错误码与 HTTP 状态码映射
func Failure(c *gin.Context, err error) {
	errorx.RespondWithError(c, err)
}
