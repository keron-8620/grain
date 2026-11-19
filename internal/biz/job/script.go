package job

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"grain/internal/conf"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// maxScriptContentSize caps a single uploaded script (1 MiB).
const maxScriptContentSize = 1 << 20

// scriptExtensions maps a script language to its repository file extension.
var scriptExtensions = map[string]string{
	"python":     ".py",
	"py":         ".py",
	"shell":      ".sh",
	"bash":       ".sh",
	"sh":         ".sh",
	"powershell": ".ps1",
	"ps1":        ".ps1",
	"go":         ".go",
	"golang":     ".go",
	"javascript": ".js",
	"js":         ".js",
	"typescript": ".ts",
	"ts":         ".ts",
	"batch":      ".bat",
	"bat":        ".bat",
	"cmd":        ".bat",
	"ruby":       ".rb",
	"rb":         ".rb",
	"perl":       ".pl",
	"pl":         ".pl",
}

// Script is the script domain model (Domain Object - DO).
type Script struct {
	ID        uint64
	Name      string
	Descr     string
	ParamDesc string
	Project   string
	Label     string
	Language  string
	Status    bool
	Username  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ScriptStore persists script source files in a versioned repository.
type ScriptStore interface {
	// Save writes content to path, commits it, and returns the commit hash.
	Save(ctx context.Context, path string, content []byte, message string) (string, error)
	// Read returns the file content at path.
	Read(ctx context.Context, path string) ([]byte, error)
	// Delete removes path, commits the removal, and returns the commit hash.
	Delete(ctx context.Context, path string, message string) (string, error)
}

// ScriptRepo is the Script repository interface contract.
type ScriptRepo interface {
	Create(ctx context.Context, script *Script) (*Script, error)
	Update(ctx context.Context, script *Script) (*Script, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64) (*Script, error)
	FindByIDs(ctx context.Context, ids []uint64) ([]Script, error)
	FindByProjectLableName(ctx context.Context, project, lable, name string) (*Script, error)
	List(ctx context.Context, opts db.ListOptions) ([]Script, int64, error)
}

// ScriptUseCase manages script metadata in the database and script content in
// the configured git repository.
type ScriptUseCase struct {
	scriptRepo ScriptRepo
	store      ScriptStore
	logger     *slog.Logger
}

// NewScriptUseCase creates a new ScriptUseCase instance.
func NewScriptUseCase(scriptRepo ScriptRepo, store ScriptStore, logger *slog.Logger) *ScriptUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	return &ScriptUseCase{
		scriptRepo: scriptRepo,
		store:      store,
		logger:     logger,
	}
}

// Create stores the script content in the git repository and then persists its
// metadata. If metadata persistence fails the file is rolled back.
func (uc *ScriptUseCase) Create(ctx context.Context, script *Script, content []byte) (*Script, error) {
	if script == nil {
		return nil, errorx.CodeInvalidParam.Error("脚本信息不能为空")
	}
	if err := uc.storeRequired(); err != nil {
		return nil, err
	}
	if err := validateScript(script); err != nil {
		return nil, err
	}
	if err := validateScriptContent(content, true); err != nil {
		return nil, err
	}

	existing, err := uc.scriptRepo.FindByProjectLableName(ctx, script.Project, script.Label, script.Name)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if existing != nil {
		return nil, errorx.CodeDuplicatedKey.Error("项目/标签下已存在同名脚本")
	}

	repoPath, err := scriptRepoPath(script)
	if err != nil {
		return nil, err
	}
	commit, err := uc.store.Save(ctx, repoPath, content, "script: add "+repoPath)
	if err != nil {
		return nil, errorx.Wrap(err, errorx.CodeExternalError, "脚本文件写入Git仓库失败")
	}

	created, err := uc.scriptRepo.Create(ctx, script)
	if err != nil {
		uc.logger.ErrorContext(ctx, "failed to persist script metadata, rolling back git file",
			slog.String("path", repoPath), slog.String("commit", commit), slog.Any("error", err))
		if _, delErr := uc.store.Delete(ctx, repoPath, "script: rollback add "+repoPath); delErr != nil {
			uc.logger.WarnContext(ctx, "failed to roll back git file",
				slog.String("path", repoPath), slog.Any("error", delErr))
		}
		return nil, errorx.FromDBError(err)
	}

	uc.logger.InfoContext(ctx, "script created",
		slog.Uint64("script_id", created.ID),
		slog.String("path", repoPath),
		slog.String("commit", commit),
	)
	return created, nil
}

// Update replaces script metadata. A non-nil content replaces the file in the
// repository. When the project/label/name/language changes, the file is moved
// to the new derived path. If database persistence fails, git changes are
// rolled back.
func (uc *ScriptUseCase) Update(ctx context.Context, script *Script, content []byte) (*Script, error) {
	if script == nil || script.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的脚本ID")
	}
	if err := uc.storeRequired(); err != nil {
		return nil, err
	}
	if err := validateScript(script); err != nil {
		return nil, err
	}
	if content != nil {
		if err := validateScriptContent(content, false); err != nil {
			return nil, err
		}
	}

	oldScript, err := uc.scriptRepo.FindByID(ctx, script.ID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldScript == nil {
		return nil, errorx.CodeRecordNotFound.Error("脚本不存在")
	}

	if scriptKeyChanged(oldScript, script) {
		existing, err := uc.scriptRepo.FindByProjectLableName(ctx, script.Project, script.Label, script.Name)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != script.ID {
			return nil, errorx.CodeDuplicatedKey.Error("项目/标签下已存在同名脚本")
		}
	}

	oldPath, oldPathErr := scriptRepoPath(oldScript)
	if oldPathErr != nil {
		return nil, oldPathErr
	}
	newPath, err := scriptRepoPath(script)
	if err != nil {
		return nil, err
	}

	rollbackGit, err := uc.syncScriptFileWithRollback(ctx, oldPath, newPath, content)
	if err != nil {
		return nil, err
	}

	updated, err := uc.scriptRepo.Update(ctx, script)
	if err != nil {
		uc.logger.ErrorContext(ctx, "failed to update script metadata, rolling back git changes",
			slog.Uint64("script_id", script.ID),
			slog.String("old_path", oldPath),
			slog.String("new_path", newPath),
			slog.Any("error", err),
		)
		if rollbackGit != nil {
			rollbackGit()
		}
		return nil, errorx.FromDBError(err)
	}
	return updated, nil
}

// Delete removes the script file from the repository and then the metadata.
func (uc *ScriptUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的脚本ID")
	}
	if err := uc.storeRequired(); err != nil {
		return err
	}

	script, err := uc.scriptRepo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if script == nil {
		return errorx.CodeRecordNotFound.Error("脚本不存在")
	}

	repoPath, pathErr := scriptRepoPath(script)
	if pathErr != nil {
		// Legacy rows may not satisfy the current path rules. Do not block
		// metadata cleanup because of an unaddressable file path.
		uc.logger.WarnContext(ctx, "skipping script file deletion: invalid stored script key",
			slog.Uint64("script_id", id), slog.Any("error", pathErr))
	} else if _, err := uc.store.Delete(ctx, repoPath, "script: delete "+repoPath); err != nil {
		return errorx.Wrap(err, errorx.CodeExternalError, "从Git仓库删除脚本文件失败")
	}

	if err := uc.scriptRepo.Delete(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}
	return nil
}

// Get returns script metadata by ID.
func (uc *ScriptUseCase) Get(ctx context.Context, id uint64) (*Script, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的脚本ID")
	}

	script, err := uc.scriptRepo.FindByID(ctx, id)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if script == nil {
		return nil, errorx.CodeRecordNotFound.Error("脚本不存在")
	}
	return script, nil
}

// GetByIDs returns script metadata for the given IDs.
func (uc *ScriptUseCase) GetByIDs(ctx context.Context, ids []uint64) ([]Script, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	scripts, err := uc.scriptRepo.FindByIDs(ctx, ids)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	return scripts, nil
}

// List lists scripts with pagination, filters, and ordering.
func (uc *ScriptUseCase) List(ctx context.Context, opts db.ListOptions) ([]Script, int64, error) {
	scripts, total, err := uc.scriptRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	return scripts, total, nil
}

// GetContent returns the script source stored in the git repository.
func (uc *ScriptUseCase) GetContent(ctx context.Context, id uint64) ([]byte, error) {
	if err := uc.storeRequired(); err != nil {
		return nil, err
	}

	script, err := uc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	repoPath, err := scriptRepoPath(script)
	if err != nil {
		return nil, err
	}

	content, err := uc.store.Read(ctx, repoPath)
	if err != nil {
		return nil, errorx.Wrap(err, errorx.CodeExternalError, "从Git仓库读取脚本文件失败")
	}
	return content, nil
}

// ==================== internals ====================

func (uc *ScriptUseCase) storeRequired() error {
	if uc.store == nil {
		return errorx.CodeConfigError.Error("未配置脚本Git仓库")
	}
	return nil
}

// syncScriptFileWithRollback synchronizes repository file updates or moves, and
// returns a best-effort rollback closure in case subsequent DB persistence fails.
func (uc *ScriptUseCase) syncScriptFileWithRollback(ctx context.Context, oldPath, newPath string, content []byte) (func(), error) {
	if content == nil && oldPath == newPath {
		return nil, nil
	}

	// Snapshot the previous file content so we can restore it if DB update fails.
	prevData, readErr := uc.store.Read(ctx, oldPath)

	switch {
	case content != nil:
		if _, err := uc.store.Save(ctx, newPath, content, "script: update "+newPath); err != nil {
			return nil, errorx.Wrap(err, errorx.CodeExternalError, "脚本文件写入Git仓库失败")
		}
		uc.deleteMovedFile(ctx, oldPath, newPath)

	case oldPath != newPath:
		// Metadata-only rename: carry the existing source to the new path.
		if readErr != nil {
			return nil, errorx.Wrap(readErr, errorx.CodeExternalError, "从Git仓库读取原脚本文件失败")
		}
		if _, err := uc.store.Save(ctx, newPath, prevData, "script: move "+oldPath+" -> "+newPath); err != nil {
			return nil, errorx.Wrap(err, errorx.CodeExternalError, "脚本文件写入Git仓库失败")
		}
		uc.deleteMovedFile(ctx, oldPath, newPath)
	}

	return func() {
		if oldPath != newPath {
			if _, err := uc.store.Delete(ctx, newPath, "script: rollback move "+newPath); err != nil {
				uc.logger.WarnContext(ctx, "failed to remove new script file during rollback",
					slog.String("new_path", newPath), slog.Any("error", err))
			}
		}
		if readErr == nil {
			if _, err := uc.store.Save(ctx, oldPath, prevData, "script: rollback restore "+oldPath); err != nil {
				uc.logger.WarnContext(ctx, "failed to restore old script file during rollback",
					slog.String("old_path", oldPath), slog.Any("error", err))
			}
		}
	}, nil
}

// deleteMovedFile removes the old path after a successful move. Failure is
// logged but does not fail the update because the new file is authoritative.
func (uc *ScriptUseCase) deleteMovedFile(ctx context.Context, oldPath, newPath string) {
	if oldPath == newPath {
		return
	}
	if _, err := uc.store.Delete(ctx, oldPath, "script: remove "+oldPath+" after move to "+newPath); err != nil {
		uc.logger.WarnContext(ctx, "failed to remove old script file after move",
			slog.String("old_path", oldPath),
			slog.String("new_path", newPath),
			slog.Any("error", err),
		)
	}
}

func validateScript(script *Script) error {
	script.Name = strings.TrimSpace(script.Name)
	script.Project = strings.TrimSpace(script.Project)
	script.Label = strings.TrimSpace(script.Label)
	script.Language = strings.TrimSpace(script.Language)
	script.Username = strings.TrimSpace(script.Username)

	if script.Name == "" {
		return errorx.CodeMissingParam.Error("脚本名称不能为空")
	}
	if script.Project == "" {
		return errorx.CodeMissingParam.Error("项目不能为空")
	}
	if script.Label == "" {
		return errorx.CodeMissingParam.Error("标签不能为空")
	}
	return nil
}

func validateScriptContent(content []byte, required bool) error {
	if required && len(bytes.TrimSpace(content)) == 0 {
		return errorx.CodeMissingParam.Error("脚本内容不能为空")
	}
	if len(content) > maxScriptContentSize {
		return errorx.CodeInvalidParam.Error(fmt.Sprintf("脚本内容不能超过 %d 字节", maxScriptContentSize))
	}
	return nil
}

func scriptKeyChanged(oldScript, newScript *Script) bool {
	return oldScript.Project != newScript.Project ||
		oldScript.Label != newScript.Label ||
		oldScript.Name != newScript.Name
}

// scriptRepoPath derives the repository-relative path from the business key:
// <project>/<label>/<name><ext>.
func scriptRepoPath(script *Script) (string, error) {
	if script == nil {
		return "", errorx.CodeInvalidParam.Error("脚本信息不能为空")
	}
	project, err := validPathSegment(script.Project, "项目")
	if err != nil {
		return "", err
	}
	label, err := validPathSegment(script.Label, "标签")
	if err != nil {
		return "", err
	}
	name, err := validPathSegment(script.Name, "脚本名称")
	if err != nil {
		return "", err
	}

	ext := scriptExtensions[strings.ToLower(strings.TrimSpace(script.Language))]
	if ext == "" {
		ext = ".txt"
	}
	if !strings.HasSuffix(strings.ToLower(name), ext) {
		name += ext
	}
	return filepath.Join(project, label, name), nil
}

// scriptDiskPath derives the full filesystem path where the script is stored
// on disk for execution.
func scriptDiskPath(script *Script) (string, error) {
	relPath, err := scriptRepoPath(script)
	if err != nil {
		return "", err
	}
	return filepath.Join(conf.StorageDir, "script", relPath), nil
}

func validPathSegment(value, field string) (string, error) {
	segment := strings.TrimSpace(value)
	if segment == "" || segment == "." || segment == ".." {
		return "", errorx.CodeInvalidParam.Error(field + "不能为空或格式非法")
	}
	if strings.ContainsAny(segment, `/\`) || strings.ContainsRune(segment, 0) {
		return "", errorx.CodeInvalidParam.Error(field + "不能包含路径分隔符")
	}
	return segment, nil
}
