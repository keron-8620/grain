package errorx

import (
	"maps"
	"sync"
)

var (
	msgMu               sync.RWMutex
	customErrorMessages = make(map[BizCode]string)

	builtinErrorMessages = map[BizCode]string{
		CodeOK: "ok",

		// 1xxxx 通用参数 / 上下文 / 安全防重放 / 认证授权
		CodeInvalidParam:           "参数校验失败",
		CodeMissingParam:           "缺少必要参数",
		CodeInvalidFormat:          "参数格式不正确",
		CodeRequestBodyTooLarge:    "请求内容超出允许大小",
		CodeUnsupportedMediaType:   "不支持的媒体类型",
		CodeValidationFailed:       "参数验证错误",
		CodeNoContext:              "上下文为空",
		CodeCanceled:               "操作已取消",
		CodeDeadlineExceeded:       "操作处理超时",
		CodeHostHeaderInvalid:      "Host头无效",
		CodeNonceNotFound:          "请求头缺少随机数",
		CodeReplayAttack:           "检测为重放攻击",
		CodeTimestampNotFound:      "请求头缺少时间戳",
		CodeTimestampInvalid:       "无效的时间戳",
		CodeTimestampExpired:       "时间戳已过期",
		CodePasswordStrengthFailed: "密码强度不足",
		CodeBadRequest:             "无效的请求",
		CodeUnauthorized:           "未登录或登录已失效",
		CodeTokenExpired:           "登录凭证已过期",
		CodeForbidden:              "无权限访问该资源",
		CodeResourceNotFound:       "请求的资源不存在",
		CodeMethodNotAllowed:       "请求方法不允许",
		CodeRequestTimeout:         "请求超时",
		CodeResourceAlreadyExists:  "资源已存在或冲突",
		CodeTokenInvalid:           "无效的登录凭证",
		CodeMissingAuth:            "缺少认证信息",
		CodeTokenTypeMismatch:      "令牌类型不匹配",
		CodeAuthFailed:             "身份认证失败",
		CodeAccountLocked:          "账号已被锁定",
		CodeTooManyRequests:        "请求过于频繁，请稍后重试",
		CodeRateLimitExceeded:      "请求过于频繁",

		// 2xxxx 系统内部错误 / 数据库系统底层异常
		CodeSystemError:                   "系统繁忙，请稍后重试",
		CodeDBError:                       "数据服务异常",
		CodeTimeout:                       "请求处理超时，请稍后重试",
		CodePanic:                         "系统发生未处理异常",
		CodeConfigError:                   "系统配置错误",
		CodeUnknown:                       "未知错误",
		CodeInvalidTransaction:            "事务处理错误",
		CodeNotImplemented:                "功能未实现",
		CodeUnsupportedRelation:           "关联关系不支持",
		CodeModelAccessibleFieldsRequired: "模型字段不可访问",
		CodeUnsupportedDriver:             "不支持的数据库驱动",
		CodeRegistered:                    "模型已注册",
		CodeDryRunModeUnsupported:         "不支持干运行模式",
		CodeInvalidDB:                     "无效的数据库连接",

		// 3xxxx 外部依赖 / 下游基础设施 / 远程连接
		CodeExternalError:         "依赖服务异常，请稍后重试",
		CodeThirdPartyError:       "第三方服务调用失败",
		CodeCacheError:            "缓存服务异常",
		CodeMQError:               "消息服务异常",
		CodeRPCError:              "下游服务调用失败",
		CodeGatewayTimeout:        "上游网关响应超时",
		CodeSSHConnectionFailed:   "SSH连接失败",
		CodeSSHKeyDeployFailed:    "SSH密钥部署失败",
		CodeWinRMConnectionFailed: "WinRM连接失败",
		CodeProtocolUnsupported:   "不支持的连接协议",

		// 4xxxx 业务逻辑受阻 / 数据库业务约束 / 文件 / 脚本 / 任务
		CodeBusinessError:                "业务处理失败",
		CodePreconditionFailed:           "业务前置条件不满足",
		CodeOperationNotAllowed:          "当前状态不允许该操作",
		CodeOptimisticLockFailed:         "数据已被修改，请刷新重试",
		CodeDataIntegrityViolation:       "数据完整性约束冲突",
		CodeRecordNotFound:               "记录未找到",
		CodeDuplicatedKey:                "唯一性约束冲突",
		CodeForeignKeyViolated:           "外键约束冲突",
		CodeCheckConstraintViolated:      "检查约束冲突",
		CodeMissingWhereClause:           "缺少where条件",
		CodePrimaryKeyRequired:           "主键未设置",
		CodeModelValueRequired:           "模型值未设置",
		CodeSubQueryRequired:             "子查询未设置",
		CodeInvalidData:                  "无效的数据",
		CodeInvalidField:                 "无效的字段",
		CodeEmptySlice:                   "数组不能为空",
		CodeInvalidValue:                 "无效的数据类型",
		CodeInvalidValueOfLength:         "关联值无效, 长度不匹配",
		CodePreloadNotAllowed:            "使用计数时不允许预加载",
		CodeDownloadFileNotFound:         "下载的文件未找到",
		CodeDownloadFilePermissionDenied: "下载文件权限被拒绝",
		CodeDownloadFileFailed:           "下载文件失败",
		CodeUnZIPFailed:                  "解压文件失败",
		CodeZIPFailed:                    "压缩文件失败",
		CodeZIPFileNotFound:              "压缩文件未找到",
		CodeZIPFileIsEmpty:               "压缩文件为空",
		CodeZIPFileIsNotValid:            "压缩文件无效",
		CodeExportCacheFileFailed:        "导出缓存文件失败",
		CodeDeleteCacheFileFailed:        "删除缓存文件失败",
		CodeScriptNotFound:               "脚本未找到",
		CodeScriptIsBuiltin:              "脚本为内置脚本",
		CodeScriptIsDisabled:             "脚本已禁用",
		CodeScriptLogNotFound:            "脚本日志未找到",
		CodeScriptSaveFailed:             "脚本保存失败",
		CodeScriptRemoveFailed:           "脚本删除失败",
		CodePackageNotFound:              "程序包未找到",
		CodePackageSaveFailed:            "程序包保存失败",
		CodePackageRemoveFailed:          "程序包删除失败",
		CodeCronSpecificationInvalid:     "计划任务表达式格式错误",
	}

	// defaultErrorMessages 保留用于向后兼容
	defaultErrorMessages = builtinErrorMessages
)

// RegisterErrorMessage 注册或覆盖单个错误码的默认提示信息（并发安全）。
func RegisterErrorMessage(code BizCode, msg string) {
	msgMu.Lock()
	defer msgMu.Unlock()
	customErrorMessages[code] = msg
}

// RegisterErrorMessages 批量注册或覆盖错误码的默认提示信息（并发安全）。
func RegisterErrorMessages(msgs map[BizCode]string) {
	msgMu.Lock()
	defer msgMu.Unlock()
	maps.Copy(customErrorMessages, msgs)
}

// GetErrorMessage 获取错误码对应的文案。
// 优先返回动态注册的文案，其次查找内置文案，若均未找到则返回空字符串。
func GetErrorMessage(c BizCode) string {
	msgMu.RLock()
	if msg, ok := customErrorMessages[c]; ok {
		msgMu.RUnlock()
		return msg
	}
	msgMu.RUnlock()

	if msg, ok := builtinErrorMessages[c]; ok {
		return msg
	}
	return ""
}
