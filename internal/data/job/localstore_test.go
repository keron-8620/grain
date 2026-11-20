package job

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalScriptStore_SaveReadDelete(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalScriptStore(root)
	require.NoError(t, err)

	ctx := context.Background()
	path := "project/label/demo.sh"

	hash, err := store.Save(ctx, path, []byte("#!/bin/sh\necho hi\n"), "add demo")
	require.NoError(t, err)
	assert.Empty(t, hash, "local store has no commit hash")

	content, err := store.Read(ctx, path)
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\necho hi\n", string(content))

	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(path)))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "scripts must be executable by the service user")

	_, err = store.Delete(ctx, path, "delete demo")
	require.NoError(t, err)
	_, err = store.Read(ctx, path)
	assert.Error(t, err)

	// Parent directories created for the script are pruned again.
	_, err = os.Stat(filepath.Join(root, "project"))
	assert.True(t, os.IsNotExist(err))
}

func TestLocalScriptStore_RejectsTraversal(t *testing.T) {
	store, err := NewLocalScriptStore(t.TempDir())
	require.NoError(t, err)

	for _, p := range []string{"../escape.sh", "/abs.sh", "a/../../escape.sh", ""} {
		_, err := store.Save(context.Background(), p, []byte("x"), "evil")
		assert.Error(t, err, "path %q must be rejected", p)
	}
}
