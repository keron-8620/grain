package job

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// seedRepository creates a bare remote with a single commit on the given branch.
func seedRepository(t *testing.T, branch string) string {
	t.Helper()

	base := t.TempDir()
	remoteDir := filepath.Join(base, "remote.git")
	_, err := git.PlainInit(remoteDir, true)
	require.NoError(t, err)

	seedDir := filepath.Join(base, "seed")
	repo, err := git.PlainInitWithOptions(seedDir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName(branch)},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(seedDir, "README.md"), []byte("seed"), 0o644))

	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("README.md")
	require.NoError(t, err)
	_, err = worktree.Commit("seed", &git.CommitOptions{
		Author: &object.Signature{Name: "seed", Email: "seed@test", When: time.Now()},
	})
	require.NoError(t, err)

	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{remoteDir}})
	require.NoError(t, err)
	ref := plumbing.NewBranchReferenceName(branch)
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec(string(ref) + ":" + string(ref))},
	})
	require.NoError(t, err)

	return remoteDir
}

func cloneContent(t *testing.T, remote, branch, repoPath string) []byte {
	t.Helper()

	dir := t.TempDir()
	_, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:           remote,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		SingleBranch:  true,
	})
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(repoPath)))
	require.NoError(t, err)
	return content
}

func TestStore_SaveReadDelete(t *testing.T) {
	ctx := context.Background()
	remote := seedRepository(t, "main")
	store, err := NewGitStore(GitConfig{
		URL:         remote,
		Branch:      "main",
		Dir:         filepath.Join(t.TempDir(), "work"),
		AuthorName:  "grain",
		AuthorEmail: "grain@test",
	})
	require.NoError(t, err)

	const repoPath = "web/release/deploy.py"

	hash, err := store.Save(ctx, repoPath, []byte("print('hi')"), "add deploy script")
	require.NoError(t, err)
	assert.Len(t, hash, 40)

	content, err := store.Read(ctx, repoPath)
	require.NoError(t, err)
	assert.Equal(t, "print('hi')", string(content))
	assert.Equal(t, "print('hi')", string(cloneContent(t, remote, "main", repoPath)))

	// Saving identical content must not create a new commit.
	sameHash, err := store.Save(ctx, repoPath, []byte("print('hi')"), "no-op")
	require.NoError(t, err)
	assert.Equal(t, hash, sameHash)

	// A second working copy reads the file from the remote.
	other, err := NewGitStore(GitConfig{
		URL:         remote,
		Branch:      "main",
		Dir:         filepath.Join(t.TempDir(), "other"),
		AuthorName:  "grain",
		AuthorEmail: "grain@test",
	})
	require.NoError(t, err)
	content, err = other.Read(ctx, repoPath)
	require.NoError(t, err)
	assert.Equal(t, "print('hi')", string(content))

	// Delete removes the file and is idempotent.
	_, err = store.Delete(ctx, repoPath, "remove deploy script")
	require.NoError(t, err)

	_, err = store.Read(ctx, repoPath)
	require.Error(t, err)

	_, err = store.Delete(ctx, repoPath, "remove deploy script again")
	require.NoError(t, err)
}

func TestStore_EmptyRemote(t *testing.T) {
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "empty.git")
	_, err := git.PlainInit(remote, true)
	require.NoError(t, err)

	store, err := NewGitStore(GitConfig{
		URL:         remote,
		Branch:      "main",
		Dir:         filepath.Join(t.TempDir(), "work"),
		AuthorName:  "grain",
		AuthorEmail: "grain@test",
	})
	require.NoError(t, err)

	const repoPath = "scripts/hello.sh"
	hash, err := store.Save(ctx, repoPath, []byte("echo hello"), "first commit")
	require.NoError(t, err)
	assert.Len(t, hash, 40)
	assert.Equal(t, "echo hello", string(cloneContent(t, remote, "main", repoPath)))
}

func TestStore_RejectsInvalidPaths(t *testing.T) {
	store, err := NewGitStore(GitConfig{
		URL: "file:///nonexistent/repo.git",
		Dir: filepath.Join(t.TempDir(), "work"),
	})
	require.NoError(t, err)

	for _, p := range []string{"", ".", "..", "../escape", "/absolute", "a/../../b", `a\..\b`} {
		_, err := store.Save(context.Background(), p, []byte("x"), "msg")
		require.Errorf(t, err, "path %q should be rejected", p)
	}
}

func TestNew_Validation(t *testing.T) {
	_, err := NewGitStore(GitConfig{Dir: t.TempDir()})
	require.Error(t, err)

	_, err = NewGitStore(GitConfig{URL: "file:///repo.git"})
	require.Error(t, err)

	_, err = NewGitStore(GitConfig{URL: "file:///repo.git", Dir: t.TempDir(), AuthType: "kerberos"})
	require.Error(t, err)

	_, err = NewGitStore(GitConfig{URL: "file:///repo.git", Dir: t.TempDir(), AuthType: AuthSSH, SSHKeyPath: filepath.Join(t.TempDir(), "missing.key")})
	require.Error(t, err)
}

func TestBuildAuthSSHPinnedHostKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600))

	serverKey, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	pinned := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(serverKey)))

	auth, err := buildAuth(GitConfig{
		URL:        "ssh://git@example.com/org/repo.git",
		Dir:        t.TempDir(),
		AuthType:   AuthSSH,
		SSHKeyPath: keyPath,
		SSHHostKey: pinned,
	})
	require.NoError(t, err)

	keys, ok := auth.(*gitssh.PublicKeys)
	require.True(t, ok)
	require.NotNil(t, keys.HostKeyCallback)
	require.NoError(t, keys.HostKeyCallback("example.com:22", nil, serverKey))

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherKey, err := ssh.NewPublicKey(otherPub)
	require.NoError(t, err)
	require.Error(t, keys.HostKeyCallback("example.com:22", nil, otherKey))
}

func TestBuildAuthSSHRequiresKnownHosts(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600))

	t.Setenv("SSH_KNOWN_HOSTS", filepath.Join(t.TempDir(), "missing_known_hosts"))
	_, err = buildAuth(GitConfig{
		URL:        "ssh://git@example.com/org/repo.git",
		Dir:        t.TempDir(),
		AuthType:   AuthSSH,
		SSHKeyPath: keyPath,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "known_hosts")
}
