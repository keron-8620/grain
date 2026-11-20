// Package gitstore persists files in a configured git repository. It keeps a
// local working copy, pulls before mutations, commits every change with the
// configured author, and pushes the configured branch to origin.
package job

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"

	biz "grain/internal/biz/job"
)

// AuthType selects how the store authenticates against the remote.
type AuthType string

const (
	// AuthNone is used for local repositories and public HTTPS endpoints.
	AuthNone AuthType = "none"
	// AuthHTTP uses username/password (or token) over HTTPS.
	AuthHTTP AuthType = "http"
	// AuthSSH uses an SSH private key (or ssh-agent when SSHKeyPath is empty).
	AuthSSH AuthType = "ssh"
)

// GitConfig describes the backing git repository.
type GitConfig struct {
	URL              string        // remote repository URL
	Branch           string        // branch to read/write, defaults to main
	Dir              string        // local working copy directory
	AuthorName       string        // commit author name, defaults to grain
	AuthorEmail      string        // commit author email, defaults to grain@localhost
	AuthType         AuthType      // none, http, ssh
	Username         string        // HTTP username or SSH user
	Password         string        // HTTP password or access token
	SSHKeyPath       string        // SSH private key path; empty uses ssh-agent
	SSHKeyPassphrase string        // optional SSH key passphrase
	KnownHosts       string        // known_hosts file for SSH; empty uses defaults
	SSHHostKey       string        // pinned SSH host key (authorized_keys line)
	Timeout          time.Duration // per-operation timeout, defaults to 60s
	InsecureSkipTLS  bool          // skip HTTPS certificate verification
}

// gitStore is a git-backed file store. Operations on one gitStore are serialized
// because they share a single working copy.
type gitStore struct {
	cfg  GitConfig
	auth transport.AuthMethod
	mu   sync.Mutex
}

// New validates the configuration, loads credentials, and returns a store.
// The remote is cloned lazily on the first operation.
func NewGitStore(cfg GitConfig) (biz.ScriptStore, error) {
	cfg.URL = strings.TrimSpace(cfg.URL)
	cfg.Dir = strings.TrimSpace(cfg.Dir)
	cfg.Branch = strings.TrimSpace(cfg.Branch)
	cfg.AuthType = AuthType(strings.ToLower(strings.TrimSpace(string(cfg.AuthType))))

	if cfg.URL == "" {
		return nil, fmt.Errorf("git store: repository URL is required")
	}
	if cfg.Dir == "" {
		return nil, fmt.Errorf("git store: local working directory is required")
	}
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.AuthorName == "" {
		cfg.AuthorName = "grain"
	}
	if cfg.AuthorEmail == "" {
		cfg.AuthorEmail = "grain@localhost"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.AuthType == "" {
		cfg.AuthType = AuthNone
	}

	auth, err := buildAuth(cfg)
	if err != nil {
		return nil, err
	}
	return &gitStore{cfg: cfg, auth: auth}, nil
}

// Save writes content to the given repository-relative path and commits it.
// If the file already has identical content, no commit is created and the
// current HEAD hash is returned. The returned commit hash is empty only when
// the repository has no commits yet.
func (s *gitStore) Save(ctx context.Context, repoPath string, content []byte, message string) (string, error) {
	clean, err := sanitizePath(repoPath)
	if err != nil {
		return "", err
	}

	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	repo, err := s.openRepo(ctx)
	if err != nil {
		return "", err
	}
	if err := s.pull(ctx, repo); err != nil {
		return "", err
	}

	fullPath := s.fullPath(clean)
	// #nosec G304 -- clean 经过filepath.Clean，且由内部逻辑生成，无外部可控输入
	if current, readErr := os.ReadFile(fullPath); readErr == nil && bytes.Equal(current, content) {
		return s.headHash(repo)
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		return "", fmt.Errorf("git store: create directory for %q: %w", clean, err)
	}
	if err := os.WriteFile(fullPath, content, 0o600); err != nil {
		return "", fmt.Errorf("git store: write %q: %w", clean, err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("git store: worktree: %w", err)
	}
	if _, err := worktree.Add(clean); err != nil {
		return "", fmt.Errorf("git store: stage %q: %w", clean, err)
	}
	return s.commitAndPush(ctx, repo, message)
}

// Read returns the content of a repository-relative path. The repository is
// pulled first so that changes pushed by other instances are visible.
func (s *gitStore) Read(ctx context.Context, repoPath string) ([]byte, error) {
	clean, err := sanitizePath(repoPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	repo, err := s.openRepo(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.pull(ctx, repo); err != nil {
		return nil, err
	}

	data, readErr := os.ReadFile(s.fullPath(clean))
	if readErr != nil {
		return nil, fmt.Errorf("git store: read %q: %w", clean, readErr)
	}
	return data, nil
}

// Delete removes a repository-relative file and commits the removal. Deleting
// a file that does not exist is a no-op.
func (s *gitStore) Delete(ctx context.Context, repoPath string, message string) (string, error) {
	clean, err := sanitizePath(repoPath)
	if err != nil {
		return "", err
	}

	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	repo, err := s.openRepo(ctx)
	if err != nil {
		return "", err
	}
	if err := s.pull(ctx, repo); err != nil {
		return "", err
	}

	fullPath := s.fullPath(clean)
	if _, statErr := os.Stat(fullPath); statErr != nil {
		if os.IsNotExist(statErr) {
			return s.headHash(repo)
		}
		return "", fmt.Errorf("git store: stat %q: %w", clean, statErr)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("git store: worktree: %w", err)
	}
	if _, err := worktree.Remove(clean); err != nil {
		return "", fmt.Errorf("git store: remove %q: %w", clean, err)
	}

	return s.commitAndPush(ctx, repo, message)
}

// ==================== internals ====================

func (s *gitStore) branchRef() plumbing.ReferenceName {
	return plumbing.NewBranchReferenceName(s.cfg.Branch)
}

func (s *gitStore) fullPath(clean string) string {
	return filepath.Join(s.cfg.Dir, filepath.FromSlash(clean))
}

func (s *gitStore) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, s.cfg.Timeout)
}

func (s *gitStore) signature() *object.Signature {
	return &object.Signature{
		Name:  s.cfg.AuthorName,
		Email: s.cfg.AuthorEmail,
		When:  time.Now(),
	}
}

// openRepo opens the local working copy, cloning it on first use. An empty
// remote is handled by initializing a fresh repository on the configured
// branch so the first commit can be pushed.
func (s *gitStore) openRepo(ctx context.Context) (*git.Repository, error) {
	if _, err := os.Stat(filepath.Join(s.cfg.Dir, ".git")); err == nil {
		repo, openErr := git.PlainOpen(s.cfg.Dir)
		if openErr != nil {
			return nil, fmt.Errorf("git store: open %q: %w", s.cfg.Dir, openErr)
		}
		return repo, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("git store: stat %q: %w", s.cfg.Dir, err)
	}

	if err := os.MkdirAll(filepath.Dir(strings.TrimRight(s.cfg.Dir, string(os.PathSeparator))), 0o700); err != nil {
		return nil, fmt.Errorf("git store: create working directory: %w", err)
	}

	repo, err := git.PlainCloneContext(ctx, s.cfg.Dir, false, &git.CloneOptions{
		URL:             s.cfg.URL,
		Auth:            s.auth,
		ReferenceName:   s.branchRef(),
		SingleBranch:    true,
		InsecureSkipTLS: s.cfg.InsecureSkipTLS,
	})
	if err == nil {
		return repo, nil
	}
	if !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil, fmt.Errorf("git store: clone %q: %w", s.cfg.URL, err)
	}

	// The remote has no commits yet: initialize a matching local repository.
	if removeErr := os.RemoveAll(s.cfg.Dir); removeErr != nil {
		return nil, fmt.Errorf("git store: reset empty working directory: %w", removeErr)
	}
	repo, err = git.PlainInitWithOptions(s.cfg.Dir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: s.branchRef()},
	})
	if err != nil {
		return nil, fmt.Errorf("git store: init empty repository: %w", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{s.cfg.URL}}); err != nil {
		return nil, fmt.Errorf("git store: add origin remote: %w", err)
	}
	return repo, nil
}

func (s *gitStore) pull(ctx context.Context, repo *git.Repository) error {
	// A repository without HEAD has nothing to merge yet.
	if _, err := repo.Head(); err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return nil
		}
		return fmt.Errorf("git store: resolve HEAD: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("git store: worktree: %w", err)
	}
	err = worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:      "origin",
		Auth:            s.auth,
		ReferenceName:   s.branchRef(),
		SingleBranch:    true,
		InsecureSkipTLS: s.cfg.InsecureSkipTLS,
	})
	if err == nil ||
		errors.Is(err, git.NoErrAlreadyUpToDate) ||
		errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil
	}
	return fmt.Errorf("git store: pull: %w", err)
}

func (s *gitStore) commitAndPush(ctx context.Context, repo *git.Repository, message string) (string, error) {
	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("git store: worktree: %w", err)
	}

	hash, err := worktree.Commit(message, &git.CommitOptions{Author: s.signature()})
	if err != nil {
		return "", fmt.Errorf("git store: commit: %w", err)
	}

	ref := s.branchRef()
	if err := repo.PushContext(ctx, &git.PushOptions{
		RemoteName:      "origin",
		Auth:            s.auth,
		RefSpecs:        []config.RefSpec{config.RefSpec(string(ref) + ":" + string(ref))},
		InsecureSkipTLS: s.cfg.InsecureSkipTLS,
	}); err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return hash.String(), fmt.Errorf("git store: push %q: %w", ref, err)
	}
	return hash.String(), nil
}

func (s *gitStore) headHash(repo *git.Repository) (string, error) {
	ref, err := repo.Head()
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("git store: resolve HEAD: %w", err)
	}
	return ref.Hash().String(), nil
}

func buildAuth(cfg GitConfig) (transport.AuthMethod, error) {
	switch cfg.AuthType {
	case AuthNone:
		return nil, nil
	case AuthHTTP:
		username := cfg.Username
		if username == "" {
			username = "git"
		}
		return &githttp.BasicAuth{Username: username, Password: cfg.Password}, nil
	case AuthSSH:
		username := cfg.Username
		if username == "" {
			username = "git"
		}

		callback, err := gitHostKeyCallback(cfg)
		if err != nil {
			return nil, err
		}

		if cfg.SSHKeyPath == "" {
			auth, err := gitssh.NewSSHAgentAuth(username)
			if err != nil {
				return nil, fmt.Errorf("git store: ssh agent auth: %w", err)
			}
			if callback != nil {
				auth.HostKeyCallback = callback
			}
			return auth, nil
		}

		key, err := os.ReadFile(cfg.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("git store: read ssh key: %w", err)
		}
		var signer ssh.Signer
		if cfg.SSHKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(cfg.SSHKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			return nil, fmt.Errorf("git store: parse ssh key: %w", err)
		}
		return &gitssh.PublicKeys{
			User:            username,
			Signer:          signer,
			HostKeyCallback: callback,
		}, nil
	default:
		return nil, fmt.Errorf("git store: unsupported auth type %q", cfg.AuthType)
	}
}

// gitHostKeyCallback builds a host-key verifier for SSH remotes. There is no
// insecure fallback: either job.script_repo.ssh_host_key is pinned, or a
// known_hosts file (configured or the system default) must exist.
func gitHostKeyCallback(cfg GitConfig) (ssh.HostKeyCallback, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, nil
	}
	if !isSSHRemote(cfg.URL) {
		return nil, nil
	}
	if pinned := strings.TrimSpace(cfg.SSHHostKey); pinned != "" {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pinned))
		if err != nil {
			return nil, fmt.Errorf("git store: parse pinned ssh_host_key: %w", err)
		}
		return ssh.FixedHostKey(key), nil
	}
	if knownHosts := strings.TrimSpace(cfg.KnownHosts); knownHosts != "" {
		if _, err := os.Stat(knownHosts); err != nil {
			return nil, fmt.Errorf("git store: known_hosts %q: %w", knownHosts, err)
		}
		callback, err := gitssh.NewKnownHostsCallback(knownHosts)
		if err != nil {
			return nil, fmt.Errorf("git store: load known_hosts %q: %w", knownHosts, err)
		}
		return callback, nil
	}
	callback, err := gitssh.NewKnownHostsCallback()
	if err != nil {
		return nil, fmt.Errorf("git store: no known_hosts available; configure job.script_repo.known_hosts or ssh_host_key: %w", err)
	}
	return callback, nil
}

func isSSHRemote(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if strings.HasPrefix(strings.ToLower(rawURL), "ssh://") {
		return true
	}
	// SCP-like syntax: git@example.com:org/repo.git
	if strings.Contains(rawURL, "://") {
		return false
	}
	return strings.Contains(rawURL, "@") && strings.Contains(rawURL, ":")
}

// sanitizePath validates a repository-relative slash-separated path.
func sanitizePath(repoPath string) (string, error) {
	raw := strings.TrimSpace(strings.ReplaceAll(repoPath, "\\", "/"))
	if raw == "" {
		return "", fmt.Errorf("git store: path is required")
	}
	if strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("git store: absolute paths are not allowed: %q", repoPath)
	}
	clean := path.Clean(raw)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("git store: invalid path %q", repoPath)
	}
	for _, segment := range strings.Split(clean, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("git store: invalid path %q", repoPath)
		}
	}
	return clean, nil
}
