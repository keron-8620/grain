package job

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"uuid"

	"github.com/masterzen/winrm"
	"golang.org/x/crypto/ssh"

	"grain/internal/biz/common"
	"grain/internal/conf"
	"grain/pkg/db"
	"grain/pkg/errorx"
	"grain/pkg/remote"
)

const (
	defaultMaxConcurrentScripts = 10                                          // default concurrency cap when unconfigured or invalid
	defaultExecScriptTimeout    = 10 * time.Minute                            // default execution timeout
	defaultExecScriptTimeoutSec = int(defaultExecScriptTimeout / time.Second) // default execution timeout in seconds
	maxExecScriptTimeout        = 12 * time.Hour                              // upper bound for execution timeout
)

type ctxKey string

const scriptRecordUUIDKey ctxKey = "script_record_uuid"

// TriggerType represents how a script execution was triggered.
type TriggerType string

const (
	TriggerTypeCron TriggerType = "cron"
	TriggerTypeAPI  TriggerType = "api"
)

// ScriptRecordStatus represents the lifecycle state of a script execution.
type ScriptRecordStatus int

const (
	ScriptRecordStatusPending ScriptRecordStatus = iota // 0 - pending
	ScriptRecordStatusRunning                           // 1 - running
	ScriptRecordStatusSuccess                           // 2 - succeeded
	ScriptRecordStatusFailed                            // 3 - failed
	ScriptRecordStatusTimeout                           // 4 - timed out
	ScriptRecordStatusCrashed                           // 5 - crashed
	ScriptRecordStatusCancel                            // 6 - canceled
)

// ExecuteInfo carries the input parameters to schedule a script execution.
type ExecuteInfo struct {
	TriggerType TriggerType `json:"trigger_type"`
	ScriptID    uint64      `json:"script_id"`
	ScriptArgs  string      `json:"script_args"`
	EnvVars     string      `json:"env_vars"`
	Timeout     int         `json:"timeout"`
	WorkDir     string      `json:"work_dir"`
	Username    string      `json:"username"`
	HostID      uint64      `json:"host_id"`
}

// ScriptRecord is the script execution record domain model (Domain Object - DO).
type ScriptRecord struct {
	ID           uint64
	TriggerType  TriggerType
	Status       ScriptRecordStatus
	ExitCode     int
	EnvVars      string
	ScriptArgs   string
	WorkDir      string
	Timeout      int
	LogName      string
	ErrorMessage string
	Username     string
	HostID       uint64
	ScriptID     uint64
	Script       *Script
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// LogValue implements slog.LogValuer for structured logging.
func (sr *ScriptRecord) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("script_record_id", sr.ID),
		slog.String("trigger_type", string(sr.TriggerType)),
		slog.Int("status", int(sr.Status)),
		slog.Int("exit_code", sr.ExitCode),
		slog.String("env_vars", sr.EnvVars),
		slog.String("script_args", sr.ScriptArgs),
		slog.String("work_dir", sr.WorkDir),
		slog.Int("timeout", sr.Timeout),
		slog.String("log_name", sr.LogName),
		slog.String("error_message", sr.ErrorMessage),
		slog.String("username", sr.Username),
		slog.Uint64("script_id", sr.ScriptID),
		slog.String("created_at", sr.CreatedAt.String()),
		slog.String("updated_at", sr.UpdatedAt.String()),
	)
}

// ScriptRecordRepo is the ScriptRecord repository interface contract.
type ScriptRecordRepo interface {
	Create(ctx context.Context, sr *ScriptRecord) (*ScriptRecord, error)
	Update(ctx context.Context, id uint64, status, code int, msg string) error
	FindByID(ctx context.Context, id uint64) (*ScriptRecord, error)
	FindByIDs(ctx context.Context, ids []uint64) ([]ScriptRecord, error)
	List(ctx context.Context, opts db.ListOptions) ([]ScriptRecord, int64, error)
	// MarkInterrupted fails records left in pending/running state by a previous
	// process. It returns the number of affected rows.
	MarkInterrupted(ctx context.Context, message string) (int64, error)
}

// ScriptRecordUseCache manages script execution lifecycle, concurrency limits,
// cancellation handles, and execution records.
type ScriptRecordUseCache struct {
	scriptRepo       ScriptRepo
	recordRepo       ScriptRecordRepo
	logger           *slog.Logger
	contexts         map[uint64]context.CancelFunc
	mutex            sync.RWMutex
	sem              chan struct{}
	scriptRoot       string
	sshKeyPassphrase string

	// queue bounds the number of accepted-but-not-yet-finished API executions.
	queue       chan struct{}
	lifecycleMu sync.Mutex
	stopping    bool
	active      sync.WaitGroup
}

// NewScriptRecordUseCache creates a new ScriptRecordUseCache instance.
func NewScriptRecordUseCache(scriptRepo ScriptRepo, recordRepo ScriptRecordRepo, logger *slog.Logger, maxConcurrentScripts int) *ScriptRecordUseCache {
	if logger == nil {
		logger = slog.Default()
	}
	if maxConcurrentScripts <= 0 || maxConcurrentScripts > defaultMaxConcurrentScripts {
		maxConcurrentScripts = defaultMaxConcurrentScripts
	}
	return &ScriptRecordUseCache{
		scriptRepo: scriptRepo,
		recordRepo: recordRepo,
		logger:     logger,
		contexts:   make(map[uint64]context.CancelFunc),
		sem:        make(chan struct{}, maxConcurrentScripts),
		queue:      make(chan struct{}, maxConcurrentScripts*10),
	}
}

// SetSSHKeyPassphrase configures the passphrase of the execution SSH key.
// It must be called during startup; the passphrase is never persisted.
func (uc *ScriptRecordUseCache) SetSSHKeyPassphrase(passphrase string) {
	uc.sshKeyPassphrase = passphrase
}

// SetScriptRoot pins the directory of the script working copy used for local
// execution. It must be called once during startup, before executions begin.
// An empty value restores the default (conf.StorageDir/script).
func (uc *ScriptRecordUseCache) SetScriptRoot(dir string) {
	uc.scriptRoot = strings.TrimSpace(dir)
}

// ExecuteAsync accepts an execution without blocking the caller. It rejects
// submissions when the bounded queue is full or the service is stopping, and
// marks the record as crashed in that case.
func (uc *ScriptRecordUseCache) ExecuteAsync(ctx context.Context, record *ScriptRecord) error {
	if record == nil {
		return errorx.CodeInvalidParam.Error("执行记录不能为nil")
	}

	select {
	case uc.queue <- struct{}{}:
	default:
		uc.failQueuedRecord(record, "执行队列已满，请稍后重试")
		return errorx.CodeRateLimitExceeded.Error("执行队列已满，请稍后重试")
	}

	uc.lifecycleMu.Lock()
	stopping := uc.stopping
	uc.lifecycleMu.Unlock()
	if stopping {
		<-uc.queue
		uc.failQueuedRecord(record, "服务正在关闭，任务未执行")
		return errorx.CodeRateLimitExceeded.Error("服务正在关闭，任务未执行")
	}

	go func() {
		defer func() { <-uc.queue }()
		if _, err := uc.Execute(ctx, record); err != nil {
			uc.logger.WarnContext(ctx, "脚本执行结束但返回错误",
				slog.Uint64("script_record_id", record.ID), slog.Any("error", err))
		}
	}()
	return nil
}

// Recover fails records left pending/running by a previous process. It must run
// once at startup, before new executions are accepted.
func (uc *ScriptRecordUseCache) Recover(ctx context.Context) (int64, error) {
	if uc.recordRepo == nil {
		return 0, nil
	}
	n, err := uc.recordRepo.MarkInterrupted(ctx, "服务重启，任务执行中断")
	if err != nil {
		return 0, err
	}
	if n > 0 {
		uc.logger.WarnContext(ctx, "标记了上次进程遗留的未完成任务", slog.Int64("count", n))
	}
	return n, nil
}

// Stop rejects new executions, cancels running ones and waits (bounded by ctx)
// for them to persist their final state.
func (uc *ScriptRecordUseCache) Stop(ctx context.Context) {
	uc.lifecycleMu.Lock()
	uc.stopping = true
	uc.lifecycleMu.Unlock()

	uc.CancelAll()

	done := make(chan struct{})
	go func() {
		uc.active.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		uc.logger.WarnContext(ctx, "等待运行中的脚本退出超时")
	}
}

// CancelAll cancels every registered execution.
func (uc *ScriptRecordUseCache) CancelAll() {
	uc.mutex.RLock()
	cancels := make([]context.CancelFunc, 0, len(uc.contexts))
	for _, cancel := range uc.contexts {
		cancels = append(cancels, cancel)
	}
	uc.mutex.RUnlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (uc *ScriptRecordUseCache) beginExecution() bool {
	uc.lifecycleMu.Lock()
	defer uc.lifecycleMu.Unlock()
	if uc.stopping {
		return false
	}
	uc.active.Add(1)
	return true
}

func (uc *ScriptRecordUseCache) endExecution() {
	uc.active.Done()
}

func (uc *ScriptRecordUseCache) failQueuedRecord(record *ScriptRecord, message string) {
	if record == nil {
		return
	}
	record.Status = ScriptRecordStatusCrashed
	record.ErrorMessage = message
	if record.ID != 0 && uc.recordRepo != nil {
		_ = uc.recordRepo.Update(context.Background(), record.ID, int(record.Status), record.ExitCode, message)
	}
}

// StoreCancel registers a cancel function for a running script record.
func (uc *ScriptRecordUseCache) StoreCancel(id uint64, cancel context.CancelFunc) {
	uc.mutex.Lock()
	defer uc.mutex.Unlock()
	uc.contexts[id] = cancel
}

// DeleteCancel removes the cancel function associated with a script record.
func (uc *ScriptRecordUseCache) DeleteCancel(id uint64) {
	uc.mutex.Lock()
	defer uc.mutex.Unlock()
	delete(uc.contexts, id)
}

// GetCancel retrieves the cancel function for a script record if present.
func (uc *ScriptRecordUseCache) GetCancel(id uint64) context.CancelFunc {
	uc.mutex.RLock()
	defer uc.mutex.RUnlock()
	return uc.contexts[id]
}

// Execute runs the script described by record under concurrency and timeout
// bounds, streaming stdout/stderr to the execution log file and persisting
// final status transitions.
func (uc *ScriptRecordUseCache) Execute(ctx context.Context, record *ScriptRecord) (res *ScriptRecord, err error) {
	startTime := time.Now()
	if record == nil {
		uc.logger.ErrorContext(ctx, "执行记录不能为nil")
		return nil, errorx.CodeInvalidParam.Error("执行记录不能为nil")
	}
	if !uc.beginExecution() {
		uc.failQueuedRecord(record, "服务正在关闭，任务未执行")
		return record, errorx.CodeRateLimitExceeded.Error("服务正在关闭，任务未执行")
	}
	defer uc.endExecution()

	uuidKey := uuid.New().String()
	ctx = context.WithValue(ctx, scriptRecordUUIDKey, uuidKey)
	uc.logger.DebugContext(ctx, "脚本执行:参数详情", slog.Any("script_record", record))

	exCtx, cancel := context.WithTimeout(ctx, resolveExecTimeout(record.Timeout))
	uc.StoreCancel(record.ID, cancel)

	var logFile *os.File

	cleanCtx := context.WithValue(context.Background(), scriptRecordUUIDKey, uuidKey)
	cleanCtx, timeoutCancel := context.WithTimeout(cleanCtx, resolveExecTimeout(record.Timeout))
	defer func() {
		r := recover()
		uc.finalizeExecution(cleanCtx, cancel, record, logFile, startTime, r)
		if r != nil {
			res = record
			err = errorx.CodePanic.Error(record.ErrorMessage)
		}
		timeoutCancel()
	}()

	// Acquire a concurrency slot while remaining responsive to cancellation/timeout.
	select {
	case uc.sem <- struct{}{}:
		defer func() { <-uc.sem }()
	case <-exCtx.Done():
		if errors.Is(exCtx.Err(), context.DeadlineExceeded) {
			record.Status = ScriptRecordStatusTimeout
			record.ErrorMessage = "等待执行并发额度超时"
		} else {
			record.Status = ScriptRecordStatusCancel
			record.ErrorMessage = "等待执行并发额度时任务已取消"
		}
		uc.logger.WarnContext(exCtx, "脚本执行:"+record.ErrorMessage,
			slog.Uint64("script_record_id", record.ID),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		return record, exCtx.Err()
	}

	// Prepare log directory and open log file.
	logPath := GenerateScriptLogPath(record.CreatedAt, record.LogName)
	logFile, err = uc.openExecutionLog(exCtx, logPath, startTime)
	if err != nil {
		record.Status = ScriptRecordStatusCrashed
		record.ErrorMessage = err.Error()
		return record, err
	}

	// Validate script path and file existence.
	scriptPath, err := uc.resolveAndVerifyScript(exCtx, record, logFile, startTime)
	if err != nil {
		return record, err
	}

	if record.HostID == 0 {
		runErr := uc.executeLocal(exCtx, record, scriptPath, logPath, logFile)
		uc.applyExecutionResult(exCtx, record, logFile, runErr, startTime, time.Now())
		return record, runErr
	}

	hostVars, _, err := common.LoadAnsibleHostVars(exCtx, record.HostID)
	if err != nil || hostVars == nil {
		record.Status = ScriptRecordStatusFailed
		record.ErrorMessage = "加载远程主机信息失败"
		_, _ = fmt.Fprintf(logFile, "%s, host_id=%d, err=%v\n", record.ErrorMessage, record.HostID, err)
		return record, err
	}

	var runErr error
	switch hostVars.AnsibleConnection {
	case common.ProtocolSSH:
		runErr = uc.executeSSH(exCtx, record, scriptPath, logPath, logFile, hostVars)
	case common.ProtocolWinRM:
		runErr = uc.executeWinRM(exCtx, record, scriptPath, logPath, logFile, hostVars)
	default:
		record.Status = ScriptRecordStatusFailed
		record.ErrorMessage = fmt.Sprintf("不支持的远程方式: connect=%s", hostVars.AnsibleConnection)
		runErr = errors.New(record.ErrorMessage)
		return record, runErr
	}
	uc.applyExecutionResult(exCtx, record, logFile, runErr, startTime, time.Now())
	return record, runErr
}

// Cancel signals a running or queued script execution to stop.
func (uc *ScriptRecordUseCache) Cancel(ctx context.Context, id uint64) {
	if cancel := uc.GetCancel(id); cancel != nil {
		cancel()
		return
	}
	uc.logger.WarnContext(ctx, "script task to be canceled not found", slog.Uint64("script_record_id", id))
}

// Create validates the execution request and persists a pending ScriptRecord.
func (uc *ScriptRecordUseCache) Create(ctx context.Context, execInfo *ExecuteInfo) (*ScriptRecord, error) {
	if execInfo == nil {
		return nil, errorx.CodeInvalidParam.Error("执行信息不能为空")
	}
	if execInfo.Username == "" {
		return nil, errorx.CodeMissingParam.Error("执行人不能为空")
	}
	if execInfo.ScriptID == 0 {
		return nil, errorx.CodeMissingParam.Error("执行记录必须指定执行脚本")
	}

	script, err := uc.scriptRepo.FindByID(ctx, execInfo.ScriptID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if script == nil {
		return nil, errorx.CodeRecordNotFound.Error("关联脚本不存在")
	}
	if !script.Status {
		return nil, errorx.CodeMissingParam.Error("该脚本已被禁用")
	}

	timeout := execInfo.Timeout
	if timeout <= 0 {
		timeout = defaultExecScriptTimeoutSec
	}

	record := &ScriptRecord{
		TriggerType:  execInfo.TriggerType,
		Status:       ScriptRecordStatusPending,
		ExitCode:     -1,
		ScriptID:     execInfo.ScriptID,
		ScriptArgs:   execInfo.ScriptArgs,
		EnvVars:      execInfo.EnvVars,
		WorkDir:      execInfo.WorkDir,
		LogName:      fmt.Sprintf("%s.log", uuid.New().String()),
		ErrorMessage: "",
		Timeout:      timeout,
		Username:     execInfo.Username,
		HostID:       execInfo.HostID,
		// Keep the resolved metadata in memory: Execute derives the on-disk
		// path from the project/label/name/language key.
		Script: script,
	}

	created, err := uc.recordRepo.Create(ctx, record)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return created, nil
}

// Get returns a script execution record by ID.
func (uc *ScriptRecordUseCache) Get(ctx context.Context, id uint64) (*ScriptRecord, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的脚本执行记录ID")
	}

	record, err := uc.recordRepo.FindByID(ctx, id)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if record == nil {
		return nil, errorx.CodeRecordNotFound.Error("脚本执行记录不存在")
	}
	return record, nil
}

// GetByIDs returns script execution records for the given IDs.
func (uc *ScriptRecordUseCache) GetByIDs(ctx context.Context, ids []uint64) ([]ScriptRecord, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	records, err := uc.recordRepo.FindByIDs(ctx, ids)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return records, nil
}

// List lists script execution records with pagination, filters, and ordering.
func (uc *ScriptRecordUseCache) List(ctx context.Context, opts db.ListOptions) ([]ScriptRecord, int64, error) {
	records, total, err := uc.recordRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return records, total, nil
}

// GenerateScriptLogPath builds the log file path under the configured storage directory.
func GenerateScriptLogPath(data time.Time, logName string) string {
	return filepath.Join(conf.StorageDir, "logs", data.Format(time.DateOnly), logName)
}

// ==================== internals ====================

func resolveExecTimeout(timeoutSec int) time.Duration {
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout <= 0 {
		return defaultExecScriptTimeout
	}
	if timeout >= maxExecScriptTimeout {
		return maxExecScriptTimeout
	}
	return timeout
}

func parseScriptArgs(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}

func (uc *ScriptRecordUseCache) finalizeExecution(
	exCtx context.Context,
	cancel context.CancelFunc,
	record *ScriptRecord,
	logFile *os.File,
	startTime time.Time,
	recovered any,
) {
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(exCtx), 5*time.Second)
	defer cleanupCancel()

	if recovered != nil {
		stack := debug.Stack()
		switch v := recovered.(type) {
		case error:
			record.ErrorMessage = v.Error()
		case string:
			record.ErrorMessage = v
		default:
			record.ErrorMessage = fmt.Sprintf("%v", v)
		}

		uc.logger.ErrorContext(cleanupCtx, "脚本执行:发生panic",
			slog.String("error", record.ErrorMessage),
			slog.Any("panic", recovered),
			slog.String("stack", string(stack)),
			slog.Uint64("script_record_id", record.ID),
			slog.Duration("total_duration", time.Since(startTime)),
		)

		if logFile != nil {
			now := time.Now().Format(time.RFC3339)
			_, _ = fmt.Fprintf(logFile, "[%s] [PANIC] 脚本执行发生严重错误: %s\n", now, record.ErrorMessage)
			_, _ = fmt.Fprintf(logFile, "[%s] [STACK] %s\n", now, stack)
		}
		record.Status = ScriptRecordStatusCrashed
	}

	if err := uc.recordRepo.Update(cleanupCtx, record.ID, int(record.Status), record.ExitCode, record.ErrorMessage); err != nil {
		if logFile != nil {
			_, _ = fmt.Fprintf(logFile, "[%s] [ERROR] 更新脚本记录状态失败: %s\n", time.Now().Format(time.RFC3339), err.Error())
		}
		uc.logger.ErrorContext(cleanupCtx, "脚本执行:更新脚本记录状态失败",
			slog.Any("error", err),
			slog.Uint64("script_record_id", record.ID),
			slog.Duration("total_duration", time.Since(startTime)),
		)
	}

	if logFile != nil {
		if err := logFile.Close(); err != nil {
			uc.logger.ErrorContext(cleanupCtx, "日志文件句柄关闭失败", slog.Any("error", err))
		}
	}

	uc.DeleteCancel(record.ID)
	cancel()

	uc.logger.DebugContext(cleanupCtx, "脚本执行:执行完成",
		slog.Int("status", int(record.Status)),
		slog.Int("exit_code", record.ExitCode),
		slog.String("err_msg", record.ErrorMessage),
		slog.Duration("total_duration", time.Since(startTime)),
	)
}

func (uc *ScriptRecordUseCache) openExecutionLog(ctx context.Context, logPath string, startTime time.Time) (*os.File, error) {
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		uc.logger.ErrorContext(ctx, "脚本执行:创建日志目录失败",
			slog.Any("error", err),
			slog.String("path", logDir),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}

	// #nosec G304 -- logPath is generated internally from storage config and UUID
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		uc.logger.ErrorContext(ctx, "脚本执行:创建日志文件失败",
			slog.Any("error", err),
			slog.String("path", logPath),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		return nil, fmt.Errorf("创建日志文件失败: %w", err)
	}
	return file, nil
}

func (uc *ScriptRecordUseCache) resolveAndVerifyScript(
	ctx context.Context,
	record *ScriptRecord,
	logFile *os.File,
	startTime time.Time,
) (string, error) {
	scriptPath, err := scriptDiskPathIn(record.Script, uc.scriptRoot)
	if err != nil {
		record.Status = ScriptRecordStatusCrashed
		record.ErrorMessage = fmt.Sprintf("脚本路径校验失败: %s", err.Error())
		_, _ = fmt.Fprintf(logFile, "脚本路径校验失败: %s\n", err.Error())
		uc.logger.ErrorContext(ctx, "脚本执行:脚本路径校验失败",
			slog.Any("error", err),
			slog.Uint64("script_id", record.ScriptID),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		return "", err
	}

	info, err := os.Stat(scriptPath)
	if err != nil {
		record.Status = ScriptRecordStatusCrashed
		record.ErrorMessage = fmt.Sprintf("检查脚本文件失败: %v", err)
		_, _ = fmt.Fprintf(logFile, "检查脚本文件失败: %v\n", err)
		uc.logger.ErrorContext(ctx, "脚本执行:检查脚本文件失败",
			slog.Any("error", err),
			slog.String("script_path", scriptPath),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		return "", err
	}
	if info.IsDir() {
		dirErr := fmt.Errorf("脚本路径是目录而非文件: %s", scriptPath)
		record.Status = ScriptRecordStatusCrashed
		record.ErrorMessage = dirErr.Error()
		_, _ = fmt.Fprintf(logFile, "%s\n", dirErr.Error())
		return "", dirErr
	}

	uc.logger.DebugContext(ctx, "脚本执行:脚本文件存在", slog.String("script_path", scriptPath))
	return scriptPath, nil
}

func (uc *ScriptRecordUseCache) configureWorkDir(
	ctx context.Context,
	cmd *exec.Cmd,
	record *ScriptRecord,
	logFile *os.File,
	startTime time.Time,
) error {
	if record.WorkDir == "" {
		return nil
	}
	if err := os.MkdirAll(record.WorkDir, 0750); err != nil {
		record.Status = ScriptRecordStatusCrashed
		record.ErrorMessage = fmt.Sprintf("创建工作目录失败: %v", err)
		_, _ = fmt.Fprintf(logFile, "创建工作目录失败: %s\n", err)
		uc.logger.ErrorContext(ctx, "脚本执行:创建工作目录失败",
			slog.Any("error", err),
			slog.String("work_dir", record.WorkDir),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		return err
	}
	cmd.Dir = record.WorkDir
	uc.logger.DebugContext(ctx, "脚本执行:工作目录设置成功", slog.String("work_dir", record.WorkDir))
	return nil
}

func (uc *ScriptRecordUseCache) buildCommandEnv(ctx context.Context, record *ScriptRecord, logPath string) []string {
	env := append(os.Environ(),
		fmt.Sprintf("JOB_RECORD_ID=%d", record.ID),
		fmt.Sprintf("JOB_LOG_PATH=%s", logPath),
		fmt.Sprintf("JOB_BASE_DIR=%s", conf.BaseDir),
	)
	if record.EnvVars == "" {
		return env
	}

	var envMap map[string]string
	if err := json.Unmarshal([]byte(record.EnvVars), &envMap); err != nil {
		uc.logger.WarnContext(ctx, "脚本执行:解析环境变量失败", slog.Any("error", err), slog.String("env_vars", record.EnvVars))
		return env
	}

	for k, v := range envMap {
		if k != "" {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	uc.logger.DebugContext(ctx, "脚本执行:环境变量设置成功", slog.Int("env_var_count", len(envMap)))
	return env
}

func (uc *ScriptRecordUseCache) buildProcessCancelFunc(ctx context.Context, cmd *exec.Cmd) func() error {
	return func() error {
		if cmd.Process == nil {
			return nil
		}

		process := cmd.Process
		pid := process.Pid

		pgid, err := syscall.Getpgid(pid)
		if err != nil {
			uc.logger.DebugContext(ctx, "脚本执行:获取进程组ID失败, 将直接终止单个进程",
				slog.Any("error", err),
				slog.Int("pid", pid),
			)
			return uc.terminateSingleProcess(ctx, process)
		}

		return uc.terminateProcessGroup(ctx, pgid, pid)
	}
}

func (uc *ScriptRecordUseCache) terminateSingleProcess(ctx context.Context, process *os.Process) error {
	pid := process.Pid
	if err := process.Signal(syscall.SIGTERM); err != nil {
		uc.logger.DebugContext(ctx, "脚本执行:发送SIGTERM信号失败, 尝试强制终止",
			slog.Any("error", err),
			slog.Int("pid", pid),
		)
		return process.Kill()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := process.Signal(syscall.Signal(0)); err != nil {
			uc.logger.DebugContext(ctx, "脚本执行:进程已成功终止", slog.Int("pid", pid))
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	uc.logger.DebugContext(ctx, "脚本执行:进程终止超时, 尝试强制终止", slog.Int("pid", pid))
	return process.Kill()
}

func (uc *ScriptRecordUseCache) terminateProcessGroup(ctx context.Context, pgid, pid int) error {
	uc.logger.DebugContext(ctx, "脚本执行:向进程组发送SIGTERM信号", slog.Int("pgid", pgid), slog.Int("pid", pid))
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		uc.logger.DebugContext(ctx, "脚本执行:发送SIGTERM信号到进程组失败, 尝试发送SIGKILL", slog.Any("error", err), slog.Int("pgid", pgid))
		return syscall.Kill(-pgid, syscall.SIGKILL)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-pgid, 0); err != nil {
			uc.logger.DebugContext(ctx, "脚本执行:进程组已成功终止", slog.Int("pgid", pgid), slog.Int("pid", pid))
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	uc.logger.DebugContext(ctx, "脚本执行:进程组终止超时, 尝试强制终止", slog.Int("pgid", pgid), slog.Int("pid", pid))
	return syscall.Kill(-pgid, syscall.SIGKILL)
}

func (uc *ScriptRecordUseCache) applyExecutionResult(
	exCtx context.Context,
	record *ScriptRecord,
	logFile *os.File,
	runErr error,
	execStartTime, execEndTime time.Time,
) {
	execDuration := execEndTime.Sub(execStartTime).Seconds()

	if runErr == nil {
		record.ExitCode = 0
		record.Status = ScriptRecordStatusSuccess
		_, _ = fmt.Fprintf(logFile, "[%s] 脚本执行成功 (耗时: %.3fs)\n",
			execEndTime.Format(time.RFC3339), execDuration)
		return
	}

	switch {
	case errors.Is(exCtx.Err(), context.DeadlineExceeded):
		record.Status = ScriptRecordStatusTimeout
		record.ErrorMessage = "脚本执行超时"
		_, _ = fmt.Fprintf(logFile, "[%s] 脚本执行超时 (耗时: %.3fs)\n", execEndTime.Format(time.RFC3339), execDuration)

	case errors.Is(exCtx.Err(), context.Canceled):
		record.Status = ScriptRecordStatusCancel
		record.ErrorMessage = "脚本执行已取消"
		_, _ = fmt.Fprintf(logFile, "[%s] 脚本执行已取消 (耗时: %.3fs)\n", execEndTime.Format(time.RFC3339), execDuration)

	default:
		record.Status = ScriptRecordStatusFailed
		if exitError, ok := errors.AsType[*exec.ExitError](runErr); ok {
			record.ExitCode = exitError.ExitCode()
		}
		record.ErrorMessage = runErr.Error()
		_, _ = fmt.Fprintf(logFile, "[%s] 脚本执行失败 (退出码: %d, 耗时: %.3fs): %s\n",
			execEndTime.Format(time.RFC3339), record.ExitCode, execDuration, runErr)
	}
}

func (uc *ScriptRecordUseCache) executeLocal(
	ctx context.Context,
	record *ScriptRecord,
	scriptPath string,
	logPath string,
	logFile *os.File,
) error {
	execStartTime := time.Now()
	_, _ = fmt.Fprintf(logFile, "[%s] 开始执行脚本 (ID: %d, ScriptID: %d)\n",
		execStartTime.Format(time.RFC3339), record.ID, record.ScriptID)

	// Build command, working directory, and environment variables.
	cmdArgs := parseScriptArgs(record.ScriptArgs)
	uc.logger.DebugContext(ctx, "脚本执行:解析命令参数",
		slog.String("command_args", record.ScriptArgs),
		slog.Any("parsed_args", cmdArgs),
	)

	// Stage the script in a private temporary directory. The working copy may
	// be a git checkout whose files are not executable (0644/0600), and running
	// the source file in place would either fail or let a concurrent script
	// update change the code mid-execution.
	execPath, cleanupScript, err := stageLocalScript(scriptPath)
	if err != nil {
		record.Status = ScriptRecordStatusCrashed
		record.ErrorMessage = fmt.Sprintf("准备本地脚本失败: %v", err)
		_, _ = fmt.Fprintf(logFile, "准备本地脚本失败: %v\n", err)
		return err
	}
	defer cleanupScript()

	// #nosec G204 -- execPath is a private copy created by stageLocalScript
	cmd := exec.CommandContext(ctx, execPath, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
	cmd.Cancel = uc.buildProcessCancelFunc(ctx, cmd)

	if err := uc.configureWorkDir(ctx, cmd, record, logFile, execStartTime); err != nil {
		return err
	}
	cmd.Env = uc.buildCommandEnv(ctx, record, logPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.WaitDelay = 3 * time.Second

	// Transition record to running before starting the child process.
	record.Status = ScriptRecordStatusRunning
	if err := uc.recordRepo.Update(ctx, record.ID, int(record.Status), record.ExitCode, record.ErrorMessage); err != nil {
		_, _ = fmt.Fprintf(logFile, "[%s] [ERROR] 更新脚本记录状态失败: %s\n", time.Now().Format(time.RFC3339), err.Error())
		uc.logger.ErrorContext(ctx, "脚本执行:更新脚本记录状态失败",
			slog.Any("error", err),
			slog.Uint64("script_record_id", record.ID),
			slog.Duration("total_duration", time.Since(execStartTime)),
		)
		record.Status = ScriptRecordStatusCrashed
		return err
	}

	// Execute the command and record the outcome.
	uc.logger.InfoContext(ctx, "脚本执行:开始执行命令",
		slog.String("script_path", scriptPath),
		slog.Any("args", cmdArgs),
	)
	_, _ = fmt.Fprintf(logFile, "执行命令: %s %s\n", scriptPath, strings.Join(cmdArgs, " "))

	return cmd.Run()
}

// stageLocalScript copies a script into a fresh 0700 temporary directory and
// returns the executable path plus a cleanup function. Executing a copy keeps
// the git working tree immutable and works regardless of the file mode stored
// in version control.
func stageLocalScript(scriptPath string) (string, func(), error) {
	data, err := os.ReadFile(scriptPath) // #nosec G304 -- scriptPath is validated by resolveAndVerifyScript
	if err != nil {
		return "", nil, fmt.Errorf("读取脚本文件失败: %w", err)
	}

	dir, err := os.MkdirTemp("", "grain-script-*")
	if err != nil {
		return "", nil, fmt.Errorf("创建脚本临时目录失败: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	target := filepath.Join(dir, filepath.Base(scriptPath))
	if err := os.WriteFile(target, data, 0o700); err != nil { // #nosec G306 -- executable script copy inside a 0700 directory
		cleanup()
		return "", nil, fmt.Errorf("写入脚本临时文件失败: %w", err)
	}
	if err := os.Chmod(target, 0o700); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("设置脚本执行权限失败: %w", err)
	}
	return target, cleanup, nil
}

// ==================== remote execution ====================

const (
	defaultSSHPort        = remote.DefaultSSHPort
	defaultWinRMPort      = remote.DefaultWinRMHTTPPort
	defaultWinRMHTTPSPort = remote.DefaultWinRMHTTPSPort

	remoteCleanupTimeout = 10 * time.Second // best-effort cleanup after execution

	// winrmUploadChunkSize is the number of base64 characters sent per WinRM
	// command. It stays well below the default WinRM envelope size (150 KiB)
	// and is a multiple of 4 so every chunk decodes independently.
	winrmUploadChunkSize = 48 * 1024
)

// remoteEnvVar is a validated environment variable to inject into the remote
// process. Values are always quoted by the protocol-specific command builder.
type remoteEnvVar struct {
	name  string
	value string
}

// executeSSH uploads the script to the target over SSH, runs it there, and
// streams the remote stdout/stderr into the execution log. Credentials come
// from the Ansible host vars or from the local SSH agent/default keys.
func (uc *ScriptRecordUseCache) executeSSH(
	ctx context.Context,
	record *ScriptRecord,
	scriptPath string,
	logPath string,
	logFile *os.File,
	hostVars *common.AnsibleHostVars,
) error {
	execStartTime := time.Now()

	host := strings.TrimSpace(hostVars.AnsibleHost)
	user := strings.TrimSpace(hostVars.AnsibleUser)
	if host == "" || user == "" {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime,
			errorx.CodeConfigError.Error("SSH主机信息不完整，缺少 ansible_host 或 ansible_user"))
	}

	port := int(hostVars.AnsiblePort)
	if port <= 0 || port > 65535 {
		port = defaultSSHPort
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	_, _ = fmt.Fprintf(logFile, "[%s] 开始远程执行 (SSH: %s@%s)\n",
		execStartTime.Format(time.RFC3339), user, addr)
	uc.logger.InfoContext(ctx, "脚本执行:开始SSH远程执行",
		slog.Uint64("script_record_id", record.ID),
		slog.Uint64("host_id", record.HostID),
		slog.String("addr", addr),
		slog.String("log_path", logPath),
	)

	// Remote execution is passwordless by design: passwords must never be
	// persisted or accepted from host_vars.
	if strings.TrimSpace(hostVars.AnsiblePassword) != "" {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime,
			errorx.CodeConfigError.Error("远程执行禁止使用密码认证，请通过 CMDB 接入时部署 SSH 公钥"))
	}
	if strings.TrimSpace(hostVars.AnsibleSSHPrivateKeyFile) == "" {
		uc.logger.WarnContext(ctx, "脚本执行:主机未配置执行私钥，尝试 ssh-agent/默认密钥",
			slog.Uint64("host_id", record.HostID))
	}

	// Verify the server identity against the key pinned during host onboarding.
	// Legacy hosts without a pinned key must be re-saved in CMDB first.
	hostKey, keyErr := remote.ParseHostKey(hostVars.AnsibleSSHHostKey)
	if keyErr != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime,
			errorx.Wrap(keyErr, errorx.CodeConfigError,
				"主机未记录 SSH 主机密钥，请在主机管理中重新保存该主机以采集指纹"))
	}

	authMethods, cleanupAuth, err := remote.ResolveSSHAuth(ctx, remote.SSHAuthConfig{
		Password:             hostVars.AnsiblePassword,
		PrivateKeyPath:       hostVars.AnsibleSSHPrivateKeyFile,
		PrivateKeyPassphrase: uc.sshKeyPassphrase,
		EnableAgent:          true,
		EnableDefaultKeys:    true,
	})
	if err != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}
	defer cleanupAuth()

	client, err := remote.DialSSH(ctx, remote.SSHConfig{
		Addr:            addr,
		User:            user,
		AuthMethods:     authMethods,
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	})
	if err != nil {
		if strings.Contains(err.Error(), "host key mismatch") {
			return uc.failRemoteExecution(ctx, record, logFile, execStartTime,
				errorx.CodeSSHConnectionFailed.Errorf(
					"SSH主机密钥与已记录指纹不一致，连接已拒绝（可能为主机重装或中间人攻击）: %s", addr))
		}
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			uc.logger.DebugContext(ctx, "脚本执行:关闭SSH客户端失败",
				slog.Any("error", closeErr),
				slog.String("addr", addr),
			)
		}
	}()

	if err := uc.markRemoteExecutionRunning(ctx, record, logFile, execStartTime); err != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}

	// Use a per-execution directory so concurrent runs cannot overwrite each
	// other's script. The directory is removed on every exit path.
	remoteDir := path.Join("/tmp", "grain-exec-"+remoteExecutionID(ctx))
	remotePath := path.Join(remoteDir, filepath.Base(scriptPath))
	defer uc.cleanupSSHDir(ctx, client, remoteDir)

	_, _ = fmt.Fprintf(logFile, "[%s] 上传脚本到远程主机: %s\n",
		time.Now().Format(time.RFC3339), remotePath)
	if err := uc.uploadScriptToSSH(ctx, client, scriptPath, remotePath, logFile); err != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}

	command := uc.buildSSHRemoteCommand(record, remotePath, uc.buildRemoteEnvVars(ctx, record))
	args := parseScriptArgs(record.ScriptArgs)
	_, _ = fmt.Fprintf(logFile, "[%s] 远程执行命令: %s %s\n",
		time.Now().Format(time.RFC3339), remotePath, strings.Join(args, " "))

	runErr := remote.RunSSHCommand(ctx, client, command, nil, logFile, logFile)
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			record.ExitCode = exitErr.ExitStatus()
		}
	}
	return runErr
}

// executeWinRM uploads the script to the target over WinRM, runs it with
// PowerShell, and streams the remote stdout/stderr into the execution log.
// Credentials come from the Ansible host vars (password or client certificate).
func (uc *ScriptRecordUseCache) executeWinRM(
	ctx context.Context,
	record *ScriptRecord,
	scriptPath string,
	logPath string,
	logFile *os.File,
	hostVars *common.AnsibleHostVars,
) error {
	execStartTime := time.Now()

	client, endpoint, err := uc.newWinRMClient(ctx, hostVars)
	if err != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}

	scheme := "http"
	if endpoint.HTTPS {
		scheme = "https"
	}
	remoteAddr := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	_, _ = fmt.Fprintf(logFile, "[%s] 开始远程执行 (WinRM: %s://%s@%s)\n",
		execStartTime.Format(time.RFC3339), scheme, hostVars.AnsibleUser, remoteAddr)
	uc.logger.InfoContext(ctx, "脚本执行:开始WinRM远程执行",
		slog.Uint64("script_record_id", record.ID),
		slog.Uint64("host_id", record.HostID),
		slog.String("addr", remoteAddr),
		slog.String("log_path", logPath),
	)

	if err := uc.markRemoteExecutionRunning(ctx, record, logFile, execStartTime); err != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}

	fileName := fmt.Sprintf("grain_%d_%s.ps1", record.ID,
		strings.ReplaceAll(remoteExecutionID(ctx), "-", ""))
	defer uc.cleanupWinRMTempFile(ctx, client, fileName)

	_, _ = fmt.Fprintf(logFile, "[%s] 上传脚本到远程主机: %%TEMP%%\\%s\n",
		time.Now().Format(time.RFC3339), fileName)
	if err := uc.uploadScriptToWinRM(ctx, client, scriptPath, fileName); err != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}

	command := uc.buildWinRMRemoteCommand(record, fileName, uc.buildRemoteEnvVars(ctx, record))
	args := parseScriptArgs(record.ScriptArgs)
	_, _ = fmt.Fprintf(logFile, "[%s] 远程执行 PowerShell 脚本: %s %s\n",
		time.Now().Format(time.RFC3339), fileName, strings.Join(args, " "))

	encoded, err := encodeWinRMPowerShell(command)
	if err != nil {
		return uc.failRemoteExecution(ctx, record, logFile, execStartTime, err)
	}
	exitCode, runErr := client.RunWithContext(ctx, encoded, logFile, logFile)
	if exitCode > 0 {
		record.ExitCode = exitCode
	}
	if runErr == nil && exitCode != 0 {
		// WinRM reports the remote exit code out-of-band; turn a non-zero code
		// into an error so the record is marked failed.
		runErr = fmt.Errorf("远程脚本执行失败, 退出码: %d", exitCode)
	}
	return runErr
}

// markRemoteExecutionRunning persists the running transition before the remote
// script starts. A failure to persist is treated as a crashed execution, in
// line with local execution.
func (uc *ScriptRecordUseCache) markRemoteExecutionRunning(
	ctx context.Context,
	record *ScriptRecord,
	logFile *os.File,
	startTime time.Time,
) error {
	record.Status = ScriptRecordStatusRunning
	if err := uc.recordRepo.Update(ctx, record.ID, int(record.Status), record.ExitCode, record.ErrorMessage); err != nil {
		_, _ = fmt.Fprintf(logFile, "[%s] [ERROR] 更新脚本记录状态失败: %s\n",
			time.Now().Format(time.RFC3339), err.Error())
		uc.logger.ErrorContext(ctx, "脚本执行:更新脚本记录状态失败",
			slog.Any("error", err),
			slog.Uint64("script_record_id", record.ID),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		record.Status = ScriptRecordStatusCrashed
		return err
	}
	return nil
}

// failRemoteExecution records a remote setup/execution failure and mirrors it
// into the execution log. Timeout/cancel still take precedence later in
// applyExecutionResult.
func (uc *ScriptRecordUseCache) failRemoteExecution(
	ctx context.Context,
	record *ScriptRecord,
	logFile *os.File,
	startTime time.Time,
	err error,
) error {
	if err == nil {
		return nil
	}
	record.Status = ScriptRecordStatusFailed
	record.ErrorMessage = err.Error()
	_, _ = fmt.Fprintf(logFile, "[%s] [ERROR] %s\n", time.Now().Format(time.RFC3339), err.Error())
	uc.logger.ErrorContext(ctx, "脚本执行:远程执行失败",
		slog.Any("error", err),
		slog.Uint64("script_record_id", record.ID),
		slog.Uint64("host_id", record.HostID),
		slog.Duration("total_duration", time.Since(startTime)),
	)
	return err
}

// remoteExecutionID returns a stable identifier for the execution, used to
// isolate remote temporary files between concurrent runs.
func remoteExecutionID(ctx context.Context) string {
	if id, ok := ctx.Value(scriptRecordUUIDKey).(string); ok && id != "" {
		return id
	}
	return uuid.New().String()
}

// uploadScriptToSSH streams the local script to a remote file over an SSH
// session, making it private and executable.
func (uc *ScriptRecordUseCache) uploadScriptToSSH(
	ctx context.Context,
	client *ssh.Client,
	localPath, remotePath string,
	logFile *os.File,
) error {
	// #nosec G304 -- localPath was validated by resolveAndVerifyScript
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("打开本地脚本失败: %w", err)
	}
	defer func() { _ = file.Close() }()

	command := "umask 077 && mkdir -p " + posixSingleQuote(path.Dir(remotePath)) +
		" && cat > " + posixSingleQuote(remotePath) +
		" && chmod 700 " + posixSingleQuote(remotePath)
	if err := remote.RunSSHCommand(ctx, client, command, file, logFile, logFile); err != nil {
		return fmt.Errorf("上传脚本到远程主机失败: %w", err)
	}
	return nil
}

func (uc *ScriptRecordUseCache) cleanupSSHDir(ctx context.Context, client *ssh.Client, remoteDir string) {
	if client == nil || remoteDir == "" {
		return
	}

	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), remoteCleanupTimeout)
	defer cancel()

	session, err := client.NewSession()
	if err != nil {
		uc.logger.DebugContext(cleanupCtx, "脚本执行:创建SSH清理会话失败", slog.Any("error", err))
		return
	}
	defer func() { _ = session.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := session.Run("rm -rf " + posixSingleQuote(remoteDir)); err != nil {
			uc.logger.DebugContext(cleanupCtx, "脚本执行:清理远程脚本失败",
				slog.Any("error", err), slog.String("remote_dir", remoteDir))
		}
	}()

	select {
	case <-done:
	case <-cleanupCtx.Done():
		_ = session.Close()
	}
}

// newWinRMClient maps Ansible host vars onto the shared WinRM client builder.
// Transport names follow the ansible_winrm_transport values used by pywinrm.
func (uc *ScriptRecordUseCache) newWinRMClient(
	ctx context.Context,
	hostVars *common.AnsibleHostVars,
) (*winrm.Client, *winrm.Endpoint, error) {
	if strings.TrimSpace(hostVars.AnsiblePassword) != "" {
		return nil, nil, errorx.CodeConfigError.Error("远程执行禁止使用密码认证，请使用 WinRM 客户端证书")
	}

	cert, err := loadWinRMMaterial(hostVars.AnsibleWinRMCertPath, hostVars.AnsibleWinRMCertPEM, "证书")
	if err != nil {
		return nil, nil, err
	}
	key, err := loadWinRMMaterial(hostVars.AnsibleWinRMKeyPath, hostVars.AnsibleWinRMCertKeyPEM, "私钥")
	if err != nil {
		return nil, nil, err
	}

	port, useTLS := winRMConnectionTarget(hostVars)
	transport := strings.ToLower(strings.TrimSpace(hostVars.AnsibleWinRMTransport))
	if transport == "" {
		transport = "basic"
	}

	// Client certificate authentication requires TLS. When the port was left
	// at its default, switch it to the HTTPS default as well.
	if transport == "cert" && !useTLS && hostVars.AnsiblePort == 0 {
		port = defaultWinRMHTTPSPort
		useTLS = true
	}
	if !useTLS && (transport == "basic" || transport == "plaintext") {
		uc.logger.WarnContext(ctx, "脚本执行:WinRM basic认证未启用TLS，凭据可能以明文传输",
			slog.String("host", strings.TrimSpace(hostVars.AnsibleHost)))
	}

	timeout := remote.DefaultWinRMTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	return remote.NewWinRMClient(remote.WinRMConfig{
		Host:       strings.TrimSpace(hostVars.AnsibleHost),
		Port:       port,
		User:       strings.TrimSpace(hostVars.AnsibleUser),
		Password:   hostVars.AnsiblePassword,
		UseTLS:     useTLS,
		Insecure:   isWinRMCertValidationIgnored(hostVars.AnsibleWinRMCertValidate),
		ClientCert: cert,
		ClientKey:  key,
		Transport:  transport,
		Timeout:    timeout,
	})
}

// loadWinRMMaterial prefers the configured file path and falls back to legacy
// inline PEM. It never returns password material.
func loadWinRMMaterial(path, legacyPEM, label string) ([]byte, error) {
	if path = strings.TrimSpace(path); path != "" {
		data, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted config
		if err != nil {
			return nil, errorx.Wrap(err, errorx.CodeConfigError, "读取 WinRM 客户端"+label+"失败")
		}
		return data, nil
	}
	return []byte(strings.TrimSpace(legacyPEM)), nil
}

// winRMConnectionTarget resolves the effective port and TLS setting from the
// Ansible host vars.
func winRMConnectionTarget(hostVars *common.AnsibleHostVars) (port int, useTLS bool) {
	port = int(hostVars.AnsiblePort)
	switch strings.ToLower(strings.TrimSpace(hostVars.AnsibleWinRMScheme)) {
	case "https":
		useTLS = true
	case "http":
		useTLS = false
	default:
		useTLS = port == defaultWinRMHTTPSPort
	}
	if port <= 0 || port > 65535 {
		if useTLS {
			port = defaultWinRMHTTPSPort
		} else {
			port = defaultWinRMPort
		}
	}
	return port, useTLS
}

func isWinRMCertValidationIgnored(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ignore", "false", "0", "no", "disabled":
		return true
	default:
		return false
	}
}

// uploadScriptToWinRM writes the script into %TEMP% in base64 chunks so a
// large script never exceeds the WinRM SOAP envelope limit.
func (uc *ScriptRecordUseCache) uploadScriptToWinRM(
	ctx context.Context,
	client *winrm.Client,
	localPath, fileName string,
) error {
	// #nosec G304 -- localPath was validated by resolveAndVerifyScript
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("读取本地脚本失败: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	pathExpr := "$p = Join-Path $env:TEMP " + powershellSingleQuote(fileName)

	if encoded == "" {
		command := pathExpr + "; [IO.File]::WriteAllBytes($p, [byte[]]@())"
		encodedCommand, encErr := encodeWinRMPowerShell(command)
		if encErr != nil {
			return encErr
		}
		exitCode, err := client.RunWithContext(ctx, encodedCommand, io.Discard, io.Discard)
		if err != nil {
			return fmt.Errorf("上传脚本到远程主机失败: %w", err)
		}
		if exitCode != 0 {
			return fmt.Errorf("上传脚本到远程主机失败, 退出码: %d", exitCode)
		}
		return nil
	}

	for offset := 0; offset < len(encoded); offset += winrmUploadChunkSize {
		if err := ctx.Err(); err != nil {
			return err
		}

		end := min(offset+winrmUploadChunkSize, len(encoded))
		chunk := encoded[offset:end]

		var command string
		if offset == 0 {
			command = pathExpr + "; [IO.File]::WriteAllBytes($p, [Convert]::FromBase64String('" + chunk + "'))"
		} else {
			command = pathExpr +
				"; $b = [Convert]::FromBase64String('" + chunk + "')" +
				"; $fs = [IO.File]::Open($p, [IO.FileMode]::Append, [IO.FileAccess]::Write)" +
				"; try { $fs.Write($b, 0, $b.Length) } finally { $fs.Dispose() }"
		}

		encodedCommand, encErr := encodeWinRMPowerShell(command)
		if encErr != nil {
			return encErr
		}
		exitCode, err := client.RunWithContext(ctx, encodedCommand, io.Discard, io.Discard)
		if err != nil {
			return fmt.Errorf("上传脚本到远程主机失败 (offset=%d): %w", offset, err)
		}
		if exitCode != 0 {
			return fmt.Errorf("上传脚本到远程主机失败 (offset=%d), 退出码: %d", offset, exitCode)
		}
	}
	return nil
}

func (uc *ScriptRecordUseCache) cleanupWinRMTempFile(ctx context.Context, client *winrm.Client, fileName string) {
	if client == nil || fileName == "" {
		return
	}

	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), remoteCleanupTimeout)
	defer cancel()

	command := "$p = Join-Path $env:TEMP " + powershellSingleQuote(fileName) +
		"; Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue"
	encodedCommand, encErr := encodeWinRMPowerShell(command)
	if encErr != nil {
		uc.logger.DebugContext(cleanupCtx, "脚本执行:WinRM 清理命令编码失败", slog.Any("error", encErr))
		return
	}
	if _, err := client.RunWithContext(cleanupCtx, encodedCommand, io.Discard, io.Discard); err != nil {
		uc.logger.DebugContext(cleanupCtx, "脚本执行:清理WinRM远程脚本失败", slog.Any("error", err))
	}
}

// buildSSHRemoteCommand composes the POSIX shell command executed remotely:
// prepare the working directory, export the environment, then run the script.
func (uc *ScriptRecordUseCache) buildSSHRemoteCommand(
	record *ScriptRecord,
	remotePath string,
	envVars []remoteEnvVar,
) string {
	steps := make([]string, 0, len(envVars)+3)
	if workDir := strings.TrimSpace(record.WorkDir); workDir != "" {
		steps = append(steps, "mkdir -p "+posixSingleQuote(workDir), "cd "+posixSingleQuote(workDir))
	}
	for _, item := range envVars {
		steps = append(steps, "export "+item.name+"="+posixSingleQuote(item.value))
	}

	execLine := posixSingleQuote(remotePath)
	for _, arg := range parseScriptArgs(record.ScriptArgs) {
		execLine += " " + posixSingleQuote(arg)
	}
	steps = append(steps, execLine)

	return strings.Join(steps, " && ")
}

// buildWinRMRemoteCommand composes the PowerShell wrapper that prepares the
// working directory, exports the environment, runs the uploaded script with
// its arguments, and propagates the script exit code.
//
// The returned string is PowerShell code, not a cmd.exe command line: callers
// MUST pass it through encodeWinRMPowerShell before handing it to the winrm
// client.
func (uc *ScriptRecordUseCache) buildWinRMRemoteCommand(
	record *ScriptRecord,
	fileName string,
	envVars []remoteEnvVar,
) string {
	parts := []string{
		"$ErrorActionPreference = 'Continue'",
		"$p = Join-Path $env:TEMP " + powershellSingleQuote(fileName),
	}
	if workDir := strings.TrimSpace(record.WorkDir); workDir != "" {
		parts = append(parts,
			"New-Item -ItemType Directory -Force -Path "+powershellSingleQuote(workDir)+" | Out-Null",
			"Set-Location -LiteralPath "+powershellSingleQuote(workDir),
		)
	}
	for _, item := range envVars {
		parts = append(parts, "$env:"+item.name+" = "+powershellSingleQuote(item.value))
	}

	invoke := "& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $p"
	for _, arg := range parseScriptArgs(record.ScriptArgs) {
		invoke += " " + powershellSingleQuote(arg)
	}
	parts = append(parts,
		invoke,
		"$code = $LASTEXITCODE",
		"Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue",
		"exit $code",
	)

	return strings.Join(parts, "; ")
}

// encodeWinRMPowerShell wraps a PowerShell script into an encoded command so
// that the WinRM "cmd" shell only sees `powershell.exe -EncodedCommand <b64>`.
//
// Passing a raw command string is unsafe: masterzen/winrm executes it through
// cmd.exe, where PowerShell single-quote quoting does not apply, so values such
// as work_dir / env values / args could append arbitrary commands with `&`.
// Every WinRM execution path must go through this helper.
func encodeWinRMPowerShell(script string) (string, error) {
	encoded := winrm.Powershell(script)
	if encoded == "" {
		return "", errorx.CodeInvalidParam.Error("WinRM 脚本编码失败")
	}
	return encoded, nil
}

// buildRemoteEnvVars merges the always-present job variables with the user
// supplied JSON object, filtering out invalid names and sorting for stable
// command generation.
func (uc *ScriptRecordUseCache) buildRemoteEnvVars(ctx context.Context, record *ScriptRecord) []remoteEnvVar {
	envVars := []remoteEnvVar{
		{name: "JOB_RECORD_ID", value: strconv.FormatUint(record.ID, 10)},
	}
	if record.EnvVars == "" {
		return envVars
	}

	var envMap map[string]string
	if err := json.Unmarshal([]byte(record.EnvVars), &envMap); err != nil {
		uc.logger.WarnContext(ctx, "脚本执行:解析远程环境变量失败",
			slog.Any("error", err), slog.String("env_vars", record.EnvVars))
		return envVars
	}

	names := make([]string, 0, len(envMap))
	for name := range envMap {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if !isValidEnvName(name) {
			uc.logger.WarnContext(ctx, "脚本执行:忽略非法的远程环境变量名", slog.String("name", name))
			continue
		}
		envVars = append(envVars, remoteEnvVar{name: name, value: envMap[name]})
	}
	return envVars
}

func isValidEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// posixSingleQuote quotes a value for a POSIX shell using single quotes.
func posixSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// powershellSingleQuote quotes a value for PowerShell using single quotes.
func powershellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
