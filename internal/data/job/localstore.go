package job

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"emperror.dev/errors"

	biz "grain/internal/biz/job"
)

// localStorage is a filesystem-backed ScriptStore used when the Git repository
// is disabled. It keeps the same repository-relative layout as the git store
// (<project>/<label>/<name><ext>) so switching storage backends does not change
// script paths.
type localStorage struct {
	root string
}

// NewLocalScriptStore creates a filesystem script store rooted at dir.
func NewLocalScriptStore(dir string) (biz.ScriptStore, error) {
	root := strings.TrimSpace(dir)
	if root == "" {
		return nil, fmt.Errorf("local script store: root directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("local script store: create root %q: %w", root, err)
	}
	return &localStorage{root: root}, nil
}

func (s *localStorage) resolve(repoPath string) (string, error) {
	clean, err := sanitizePath(repoPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, filepath.FromSlash(clean)), nil
}

// Save writes content atomically. The returned commit hash is empty because the
// local store has no version history.
func (s *localStorage) Save(_ context.Context, repoPath string, content []byte, _ string) (string, error) {
	target, err := s.resolve(repoPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", fmt.Errorf("local script store: create directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(target), ".grain-script-*")
	if err != nil {
		return "", fmt.Errorf("local script store: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("local script store: write %q: %w", repoPath, err)
	}
	if err := tmp.Chmod(0o700); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("local script store: chmod %q: %w", repoPath, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("local script store: close %q: %w", repoPath, err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return "", fmt.Errorf("local script store: rename %q: %w", repoPath, err)
	}
	return "", nil
}

func (s *localStorage) Read(_ context.Context, repoPath string) ([]byte, error) {
	target, err := s.resolve(repoPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(target) // #nosec G304 -- target is validated by sanitizePath and rooted at s.root
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("local script store: %q not found", repoPath)
		}
		return nil, fmt.Errorf("local script store: read %q: %w", repoPath, err)
	}
	return data, nil
}

func (s *localStorage) Delete(_ context.Context, repoPath string, _ string) (string, error) {
	target, err := s.resolve(repoPath)
	if err != nil {
		return "", err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("local script store: delete %q: %w", repoPath, err)
	}
	s.pruneEmptyDirs(filepath.Dir(target))
	return "", nil
}

// pruneEmptyDirs removes empty parent directories up to (but excluding) the
// store root. Failures are ignored: leftovers are harmless.
func (s *localStorage) pruneEmptyDirs(dir string) {
	root := filepath.Clean(s.root)
	for {
		clean := filepath.Clean(dir)
		if clean == root || !strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return
		}
		entries, err := os.ReadDir(clean)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := os.Remove(clean); err != nil {
			return
		}
		dir = filepath.Dir(clean)
	}
}
