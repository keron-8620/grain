package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	"uuid"

	"grain/internal/conf"
	"grain/pkg/db"
	"grain/pkg/errorx"
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
}

// ScriptRecordUseCache manages script execution lifecycle, concurrency limits,
// cancellation handles, and execution records.
type ScriptRecordUseCache struct {
	scriptRepo ScriptRepo
	recordRepo ScriptRecordRepo
	logger     *slog.Logger
	contexts   map[uint64]context.CancelFunc
	mutex      sync.RWMutex
	sem        chan struct{}
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

	ctx = context.WithValue(ctx, scriptRecordUUIDKey, uuid.New().String())
	uc.logger.DebugContext(ctx, "脚本执行:参数详情", slog.Any("script_record", record))

	exCtx, cancel := context.WithCancel(ctx)
	uc.StoreCancel(record.ID, cancel)

	exCtx, timeoutCancel := context.WithTimeout(exCtx, resolveExecTimeout(record.Timeout))
	defer timeoutCancel()

	var logFile *os.File
	defer func() {
		r := recover()
		uc.finalizeExecution(exCtx, cancel, record, logFile, startTime, r)
		if r != nil {
			res = record
			err = errorx.CodePanic.Error(record.ErrorMessage)
		}
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

	execStartTime := time.Now()
	_, _ = fmt.Fprintf(logFile, "[%s] 开始执行脚本 (ID: %d, ScriptID: %d)\n",
		execStartTime.Format(time.RFC3339), record.ID, record.ScriptID)

	// Validate script path and file existence.
	scriptPath, err := uc.resolveAndVerifyScript(exCtx, record, logFile, startTime)
	if err != nil {
		return record, err
	}

	// Build command, working directory, and environment variables.
	cmdArgs := parseScriptArgs(record.ScriptArgs)
	uc.logger.DebugContext(exCtx, "脚本执行:解析命令参数",
		slog.String("command_args", record.ScriptArgs),
		slog.Any("parsed_args", cmdArgs),
	)

	// #nosec G204 -- scriptPath is validated via scriptRepoPath
	cmd := exec.CommandContext(exCtx, scriptPath, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
	cmd.Cancel = uc.buildProcessCancelFunc(exCtx, cmd)

	if err := uc.configureWorkDir(exCtx, cmd, record, logFile, startTime); err != nil {
		return record, err
	}
	cmd.Env = uc.buildCommandEnv(exCtx, record, logPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.WaitDelay = 3 * time.Second

	// Transition record to running before starting the child process.
	record.Status = ScriptRecordStatusRunning
	if err := uc.recordRepo.Update(exCtx, record.ID, int(record.Status), record.ExitCode, record.ErrorMessage); err != nil {
		_, _ = fmt.Fprintf(logFile, "[%s] [ERROR] 更新脚本记录状态失败: %s\n", time.Now().Format(time.RFC3339), err.Error())
		uc.logger.ErrorContext(exCtx, "脚本执行:更新脚本记录状态失败",
			slog.Any("error", err),
			slog.Uint64("script_record_id", record.ID),
			slog.Duration("total_duration", time.Since(startTime)),
		)
		record.Status = ScriptRecordStatusCrashed
		return record, err
	}

	// Execute the command and record the outcome.
	uc.logger.InfoContext(exCtx, "脚本执行:开始执行命令",
		slog.String("script_path", scriptPath),
		slog.Any("args", cmdArgs),
	)
	_, _ = fmt.Fprintf(logFile, "执行命令: %s %s\n", scriptPath, strings.Join(cmdArgs, " "))

	runErr := cmd.Run()
	uc.applyExecutionResult(exCtx, record, logFile, runErr, execStartTime, time.Now())
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
	scriptPath, err := scriptDiskPath(record.Script)
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
