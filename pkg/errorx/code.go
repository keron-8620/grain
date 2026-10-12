package errorx

import (
	"maps"
	"net/http"
	"strconv"
	"sync"
)

// BizCode 代表业务错误码。
// 建议采用 5 位数字编码规范：
//   - 0: 成功 (OK)
//   - 1xxxx: 客户端错误 / 通用参数 / 认证授权 (对应 HTTP 4xx)
//   - 2xxxx: 服务端系统内部错误 (对应 HTTP 500)
//   - 3xxxx: 外部依赖 / 下游基础设施异常 (对应 HTTP 502 / 503 / 504)
//   - 4xxxx: 业务逻辑受阻 / 业务规则不符 (对应 HTTP 400 / 422)
type BizCode int

const (
	CodeOK BizCode = 0

	// ---------------- 1xxxx 客户端错误 / 通用参数 / 安全认证 / 认证授权 (4xx) ----------------
	// 通用参数校验
	CodeInvalidParam         BizCode = 10001 // 参数校验失败
	CodeMissingParam         BizCode = 10002 // 缺少必要参数
	CodeInvalidFormat        BizCode = 10003 // 参数格式不正确
	CodeRequestBodyTooLarge  BizCode = 10004 // 请求内容过大
	CodeUnsupportedMediaType BizCode = 10005 // 不支持的媒体类型
	CodeValidationFailed     BizCode = 10006 // 参数验证错误

	// 上下文相关
	CodeNoContext        BizCode = 10101 // 上下文为空
	CodeCanceled         BizCode = 10102 // 操作取消
	CodeDeadlineExceeded BizCode = 10103 // 操作超时

	// 安全与防重放
	CodeHostHeaderInvalid      BizCode = 10201 // Host头无效
	CodeNonceNotFound          BizCode = 10202 // 请求头缺少随机数
	CodeReplayAttack           BizCode = 10203 // 检测为重放攻击
	CodeTimestampNotFound      BizCode = 10204 // 请求头缺少时间戳
	CodeTimestampInvalid       BizCode = 10205 // 无效的时间戳
	CodeTimestampExpired       BizCode = 10206 // 时间戳已过期
	CodePasswordStrengthFailed BizCode = 10207 // 密码强度不足

	// 身份与权限认证
	CodeBadRequest            BizCode = 10400 // 请求无效
	CodeUnauthorized          BizCode = 10401 // 未登录或凭证无效
	CodeTokenExpired          BizCode = 10402 // 凭证已过期
	CodeForbidden             BizCode = 10403 // 无权限访问
	CodeResourceNotFound      BizCode = 10404 // 资源不存在
	CodeMethodNotAllowed      BizCode = 10405 // 请求方法不允许
	CodeRequestTimeout        BizCode = 10408 // 请求超时
	CodeResourceAlreadyExists BizCode = 10409 // 资源已存在或冲突
	CodeTokenInvalid          BizCode = 10411 // 无效的登录凭证
	CodeMissingAuth           BizCode = 10412 // 缺少认证信息
	CodeTokenTypeMismatch     BizCode = 10413 // 令牌类型不匹配
	CodeAuthFailed            BizCode = 10414 // 身份认证失败
	CodeAccountLocked         BizCode = 10415 // 账号已被锁定
	CodeTooManyRequests       BizCode = 10429 // 请求过于频繁/限流
	CodeRateLimitExceeded     BizCode = 10430 // 请求过于频繁

	// ---------------- 2xxxx 服务端系统内部错误 / 数据库系统级异常 (500) ----------------
	CodeSystemError BizCode = 20000 // 系统繁忙
	CodeDBError     BizCode = 20001 // 数据服务异常
	CodeTimeout     BizCode = 20002 // 请求处理超时
	CodePanic       BizCode = 20003 // 服务内部崩溃
	CodeConfigError BizCode = 20004 // 系统配置异常
	CodeUnknown     BizCode = 20005 // 未知错误

	// 数据库系统底层异常
	CodeInvalidTransaction            BizCode = 21001 // 事务处理错误
	CodeNotImplemented                BizCode = 21002 // 功能未实现
	CodeUnsupportedRelation           BizCode = 21003 // 关联关系不支持
	CodeModelAccessibleFieldsRequired BizCode = 21004 // 模型字段不可访问
	CodeUnsupportedDriver             BizCode = 21005 // 不支持的数据库驱动
	CodeRegistered                    BizCode = 21006 // 模型已注册
	CodeDryRunModeUnsupported         BizCode = 21007 // 不支持干运行模式
	CodeInvalidDB                     BizCode = 21008 // 无效的数据库连接

	// ---------------- 3xxxx 外部依赖 / 下游基础设施 / 远程通信连接 (502 / 503 / 504) ----------------
	CodeExternalError   BizCode = 30000 // 依赖服务异常
	CodeThirdPartyError BizCode = 30001 // 第三方服务异常
	CodeCacheError      BizCode = 30002 // 缓存服务异常
	CodeMQError         BizCode = 30003 // 消息队列异常
	CodeRPCError        BizCode = 30004 // 下游RPC异常
	CodeGatewayTimeout  BizCode = 30005 // 网关上游超时

	// 远程连接服务 (SSH / WinRM)
	CodeSSHConnectionFailed   BizCode = 31001 // SSH连接失败
	CodeSSHKeyDeployFailed    BizCode = 31002 // SSH密钥部署失败
	CodeWinRMConnectionFailed BizCode = 31003 // WinRM连接失败
	CodeProtocolUnsupported   BizCode = 31004 // 不支持的连接协议

	// ---------------- 4xxxx 业务逻辑受阻 / 业务规则不符 (400 / 404 / 409 / 422) ----------------
	CodeBusinessError          BizCode = 40000 // 业务处理失败
	CodePreconditionFailed     BizCode = 40001 // 业务前置条件不满足
	CodeOperationNotAllowed    BizCode = 40002 // 当前状态不允许此操作
	CodeOptimisticLockFailed   BizCode = 40003 // 数据已被修改/版本冲突
	CodeDataIntegrityViolation BizCode = 40004 // 数据完整性约束冲突

	// 数据库业务与数据约束
	CodeRecordNotFound          BizCode = 41001 // 记录未找到
	CodeDuplicatedKey           BizCode = 41002 // 唯一性约束冲突
	CodeForeignKeyViolated      BizCode = 41003 // 外键约束冲突
	CodeCheckConstraintViolated BizCode = 41004 // 检查约束冲突
	CodeMissingWhereClause      BizCode = 41005 // 缺少where条件
	CodePrimaryKeyRequired      BizCode = 41006 // 主键未设置
	CodeModelValueRequired      BizCode = 41007 // 模型值未设置
	CodeSubQueryRequired        BizCode = 41008 // 子查询未设置
	CodeInvalidData             BizCode = 41009 // 无效的数据
	CodeInvalidField            BizCode = 41010 // 无效的字段
	CodeEmptySlice              BizCode = 41011 // 数组不能为空
	CodeInvalidValue            BizCode = 41012 // 无效的数据类型
	CodeInvalidValueOfLength    BizCode = 41013 // 关联值无效, 长度不匹配
	CodePreloadNotAllowed       BizCode = 41014 // 使用计数时不允许预加载

	// 文件上传下载
	CodeDownloadFileNotFound         BizCode = 42001 // 下载的文件未找到
	CodeDownloadFilePermissionDenied BizCode = 42002 // 下载文件权限被拒绝
	CodeDownloadFileFailed           BizCode = 42003 // 下载文件失败

	// 压缩解压文件
	CodeUnZIPFailed       BizCode = 42101 // 解压文件失败
	CodeZIPFailed         BizCode = 42102 // 压缩文件失败
	CodeZIPFileNotFound   BizCode = 42103 // 压缩文件未找到
	CodeZIPFileIsEmpty    BizCode = 42104 // 压缩文件为空
	CodeZIPFileIsNotValid BizCode = 42105 // 压缩文件无效

	// 缓存文件
	CodeExportCacheFileFailed BizCode = 42201 // 导出缓存文件失败
	CodeDeleteCacheFileFailed BizCode = 42202 // 删除缓存文件失败

	// 脚本相关
	CodeScriptNotFound     BizCode = 43001 // 脚本未找到
	CodeScriptIsBuiltin    BizCode = 43002 // 脚本为内置脚本
	CodeScriptIsDisabled   BizCode = 43003 // 脚本已禁用
	CodeScriptLogNotFound  BizCode = 43004 // 脚本日志未找到
	CodeScriptSaveFailed   BizCode = 43005 // 脚本保存失败
	CodeScriptRemoveFailed BizCode = 43006 // 脚本删除失败

	// 程序包相关
	CodePackageNotFound     BizCode = 44001 // 程序包未找到
	CodePackageSaveFailed   BizCode = 44002 // 程序包保存失败
	CodePackageRemoveFailed BizCode = 44003 // 程序包删除失败

	// 计划任务相关
	CodeCronSpecificationInvalid BizCode = 45001 // 计划任务表达式格式错误
)

var (
	httpStatusMu       sync.RWMutex
	customHTTPStatuses = make(map[BizCode]int)
)

// RegisterHTTPStatus 为指定错误码自定义绑定的 HTTP 状态码（并发安全）。
func RegisterHTTPStatus(code BizCode, status int) {
	httpStatusMu.Lock()
	defer httpStatusMu.Unlock()
	customHTTPStatuses[code] = status
}

// RegisterHTTPStatuses 批量自定义绑定的 HTTP 状态码（并发安全）。
func RegisterHTTPStatuses(statuses map[BizCode]int) {
	httpStatusMu.Lock()
	defer httpStatusMu.Unlock()
	maps.Copy(customHTTPStatuses, statuses)
}

// Int 返回整型错误码。
func (c BizCode) Int() int {
	return int(c)
}

// String 实现 fmt.Stringer，返回错误码的数字字符串。
func (c BizCode) String() string {
	return strconv.Itoa(int(c))
}

// Message 获取当前错误码的默认文案描述。
func (c BizCode) Message() string {
	return defaultMsg(c)
}

// IsSuccess 判断是否为成功码。
func (c BizCode) IsSuccess() bool {
	return c == CodeOK
}

// IsClientError 判断是否为客户端通用错误/参数错误/认证权限错误 (1xxxx)。
func (c BizCode) IsClientError() bool {
	return c >= 10000 && c < 20000
}

// IsServerError 判断是否为服务端系统内部错误 (2xxxx)。
func (c BizCode) IsServerError() bool {
	return c >= 20000 && c < 30000
}

// IsDependencyError 判断是否为外部依赖/下游组件错误 (3xxxx)。
func (c BizCode) IsDependencyError() bool {
	return c >= 30000 && c < 40000
}

// IsBusinessError 判断是否为业务规则/逻辑冲突错误 (4xxxx)。
func (c BizCode) IsBusinessError() bool {
	return c >= 40000 && c < 50000
}

// Error 基于当前错误码构建 *Error 实例。
// 若未传入 msg 或 msg[0] 为空，则自动使用默认文案。
func (c BizCode) Error(msg ...string) *Error {
	if len(msg) > 0 && msg[0] != "" {
		return New(c, msg[0])
	}
	return New(c, "")
}

// Errorf 基于当前错误码与格式化字符串构建 *Error 实例。
func (c BizCode) Errorf(format string, args ...any) *Error {
	return Errorf(c, format, args...)
}

// HTTPStatus 获取当前错误码推荐映射的 HTTP 状态码。
func (c BizCode) HTTPStatus() int {
	// 优先查询自定义映射
	httpStatusMu.RLock()
	if status, ok := customHTTPStatuses[c]; ok {
		httpStatusMu.RUnlock()
		return status
	}
	httpStatusMu.RUnlock()

	// 特殊精确匹配
	switch c {
	case CodeOK:
		return http.StatusOK
	case CodeUnauthorized, CodeTokenExpired, CodeTokenInvalid, CodeMissingAuth, CodeTokenTypeMismatch, CodeAuthFailed:
		return http.StatusUnauthorized
	case CodeForbidden, CodeAccountLocked, CodeDownloadFilePermissionDenied:
		return http.StatusForbidden
	case CodeResourceNotFound, CodeRecordNotFound, CodeDownloadFileNotFound, CodeZIPFileNotFound, CodeScriptNotFound, CodeScriptLogNotFound, CodePackageNotFound:
		return http.StatusNotFound
	case CodeMethodNotAllowed:
		return http.StatusMethodNotAllowed
	case CodeResourceAlreadyExists, CodeDuplicatedKey, CodeForeignKeyViolated:
		return http.StatusConflict
	case CodeRequestBodyTooLarge:
		return http.StatusRequestEntityTooLarge
	case CodeUnsupportedMediaType:
		return http.StatusUnsupportedMediaType
	case CodeTooManyRequests, CodeRateLimitExceeded:
		return http.StatusTooManyRequests
	case CodeRequestTimeout, CodeCanceled:
		return http.StatusRequestTimeout
	case CodeTimeout, CodeGatewayTimeout, CodeDeadlineExceeded:
		return http.StatusGatewayTimeout
	case CodeExternalError, CodeThirdPartyError, CodeRPCError:
		return http.StatusBadGateway
	case CodeNotImplemented:
		return http.StatusNotImplemented
	}

	// 区间兜底匹配
	switch {
	case c.IsClientError():
		return http.StatusBadRequest
	case c.IsServerError():
		return http.StatusInternalServerError
	case c.IsDependencyError():
		return http.StatusBadGateway
	case c.IsBusinessError():
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// defaultMsg 根据错误码获取默认提示信息。
func defaultMsg(c BizCode) string {
	if msg := GetErrorMessage(c); msg != "" {
		return msg
	}
	switch {
	case c.IsServerError():
		return "内部服务错误"
	case c.IsDependencyError():
		return "依赖服务异常，请稍后重试"
	case c.IsBusinessError():
		return "操作失败"
	default:
		return "请求参数有误"
	}
}

// HTTPStatus 根据 *Error 获取对应的 HTTP 状态码。
// 若 e 为 nil 则返回 http.StatusOK。
func HTTPStatus(e *Error) int {
	if e == nil {
		return http.StatusOK
	}
	return e.Code.HTTPStatus()
}
