package job

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/db"
	"grain/pkg/errorx"
)

// mockScriptRepo is an in-memory ScriptRepo used by the use case tests.
type mockScriptRepo struct {
	scripts      map[uint64]*Script
	nextID       uint64
	createErr    error
	updateErr    error
	deleteErr    error
	findErr      error
	findByKeyErr error
	listErr      error
}

func newMockScriptRepo() *mockScriptRepo {
	return &mockScriptRepo{
		scripts: make(map[uint64]*Script),
		nextID:  1,
	}
}

func (m *mockScriptRepo) Create(_ context.Context, script *Script) (*Script, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	saved := *script
	saved.ID = m.nextID
	m.nextID++
	m.scripts[saved.ID] = &saved
	return &saved, nil
}

func (m *mockScriptRepo) Update(_ context.Context, script *Script) (*Script, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	existing, ok := m.scripts[script.ID]
	if !ok {
		return nil, errorx.CodeRecordNotFound.Error("record not found")
	}
	*existing = *script
	cp := *existing
	return &cp, nil
}

func (m *mockScriptRepo) Delete(_ context.Context, id uint64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.scripts, id)
	return nil
}

func (m *mockScriptRepo) FindByID(_ context.Context, id uint64) (*Script, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	script, ok := m.scripts[id]
	if !ok {
		return nil, nil
	}
	cp := *script
	return &cp, nil
}

func (m *mockScriptRepo) FindByIDs(_ context.Context, ids []uint64) ([]Script, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	res := make([]Script, 0, len(ids))
	for _, id := range ids {
		if script, ok := m.scripts[id]; ok {
			res = append(res, *script)
		}
	}
	return res, nil
}

func (m *mockScriptRepo) FindByProjectLableName(_ context.Context, project, lable, name string) (*Script, error) {
	if m.findByKeyErr != nil {
		return nil, m.findByKeyErr
	}
	for _, script := range m.scripts {
		if script.Project == project && script.Label == lable && script.Name == name {
			cp := *script
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *mockScriptRepo) List(_ context.Context, _ db.ListOptions) ([]Script, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	res := make([]Script, 0, len(m.scripts))
	for _, script := range m.scripts {
		res = append(res, *script)
	}
	return res, int64(len(res)), nil
}

// fakeScriptStore is an in-memory ScriptStore.
type fakeScriptStore struct {
	files     map[string][]byte
	saves     []string
	deletes   []string
	saveErr   error
	readErr   error
	deleteErr error
	commits   int
}

func newFakeScriptStore() *fakeScriptStore {
	return &fakeScriptStore{files: make(map[string][]byte)}
}

func (f *fakeScriptStore) Save(_ context.Context, path string, content []byte, _ string) (string, error) {
	if f.saveErr != nil {
		return "", f.saveErr
	}
	f.files[path] = append([]byte(nil), content...)
	f.saves = append(f.saves, path)
	f.commits++
	return fmt.Sprintf("commit-%d", f.commits), nil
}

func (f *fakeScriptStore) Read(_ context.Context, path string) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	content, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), content...), nil
}

func (f *fakeScriptStore) Delete(_ context.Context, path string, _ string) (string, error) {
	if f.deleteErr != nil {
		return "", f.deleteErr
	}
	delete(f.files, path)
	f.deletes = append(f.deletes, path)
	f.commits++
	return fmt.Sprintf("commit-%d", f.commits), nil
}

func newScriptFixture(t *testing.T) (*mockScriptRepo, *fakeScriptStore, *ScriptUseCase) {
	t.Helper()
	repo := newMockScriptRepo()
	store := newFakeScriptStore()
	return repo, store, NewScriptUseCase(repo, store, nil)
}

func validScript() *Script {
	return &Script{
		Name:     "deploy",
		Project:  "web",
		Label:    "release",
		Language: "python",
		Descr:    "deploy app",
		Status:   true,
	}
}

func TestScriptUseCase_Create(t *testing.T) {
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		_, _, uc := newScriptFixture(t)

		_, err := uc.Create(ctx, nil, []byte("x"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		_, err = uc.Create(ctx, &Script{Project: "web", Label: "release"}, []byte("x"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Script{Name: "deploy", Label: "release"}, []byte("x"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, &Script{Name: "deploy", Project: "web"}, []byte("x"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, validScript(), []byte("   \n"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeMissingParam))

		_, err = uc.Create(ctx, validScript(), bytes.Repeat([]byte("a"), maxScriptContentSize+1))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))

		bad := validScript()
		bad.Project = "web/evil"
		_, err = uc.Create(ctx, bad, []byte("x"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeInvalidParam))
	})

	t.Run("success stores content and metadata", func(t *testing.T) {
		repo, store, uc := newScriptFixture(t)

		script := validScript()
		script.Username = "  alice  "
		created, err := uc.Create(ctx, script, []byte("print('hi')"))
		require.NoError(t, err)
		require.NotNil(t, created)
		assert.NotZero(t, created.ID)
		assert.Equal(t, "alice", created.Username)
		assert.Equal(t, []byte("print('hi')"), store.files["web/release/deploy.py"])
		assert.Contains(t, store.saves, "web/release/deploy.py")
		assert.Len(t, repo.scripts, 1)
	})

	t.Run("duplicate business key", func(t *testing.T) {
		repo, store, uc := newScriptFixture(t)
		seed := validScript()
		_, err := repo.Create(ctx, seed)
		require.NoError(t, err)

		_, err = uc.Create(ctx, validScript(), []byte("print('hi')"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
		assert.Empty(t, store.saves)
	})

	t.Run("store failure does not persist metadata", func(t *testing.T) {
		repo, store, uc := newScriptFixture(t)
		store.saveErr = errors.New("git down")

		_, err := uc.Create(ctx, validScript(), []byte("print('hi')"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeExternalError))
		assert.Empty(t, repo.scripts)
	})

	t.Run("metadata failure rolls back the file", func(t *testing.T) {
		repo, store, uc := newScriptFixture(t)
		repo.createErr = errors.New("db down")

		_, err := uc.Create(ctx, validScript(), []byte("print('hi')"))
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDBError))
		assert.NotContains(t, store.files, "web/release/deploy.py")
		assert.Contains(t, store.deletes, "web/release/deploy.py")
	})
}

func TestScriptUseCase_Update(t *testing.T) {
	ctx := context.Background()
	repo, store, uc := newScriptFixture(t)

	created, err := uc.Create(ctx, validScript(), []byte("old"))
	require.NoError(t, err)

	t.Run("metadata only does not touch git", func(t *testing.T) {
		before := len(store.saves)
		script := *created
		script.Descr = "updated description"
		updated, err := uc.Update(ctx, &script, nil)
		require.NoError(t, err)
		assert.Equal(t, "updated description", updated.Descr)
		assert.Len(t, store.saves, before)
	})

	t.Run("content update keeps the path", func(t *testing.T) {
		script := *created
		updated, err := uc.Update(ctx, &script, []byte("new"))
		require.NoError(t, err)
		assert.Equal(t, created.ID, updated.ID)
		assert.Equal(t, []byte("new"), store.files["web/release/deploy.py"])
		assert.Empty(t, store.deletes)
	})

	t.Run("rename without content moves the file", func(t *testing.T) {
		script := *created
		script.Name = "deploy2"
		_, err := uc.Update(ctx, &script, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("new"), store.files["web/release/deploy2.py"])
		assert.NotContains(t, store.files, "web/release/deploy.py")
		assert.Contains(t, store.deletes, "web/release/deploy.py")
	})

	t.Run("rename with content writes the new path", func(t *testing.T) {
		script := *created
		script.Name = "deploy3"
		_, err := uc.Update(ctx, &script, []byte("newer"))
		require.NoError(t, err)
		assert.Equal(t, []byte("newer"), store.files["web/release/deploy3.py"])
		assert.NotContains(t, store.files, "web/release/deploy2.py")
	})

	t.Run("duplicate rename is rejected", func(t *testing.T) {
		other := *validScript()
		other.Name = "other"
		_, err := repo.Create(ctx, &other)
		require.NoError(t, err)

		script := *created
		script.Name = "other"
		_, err = uc.Update(ctx, &script, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeDuplicatedKey))
	})

	t.Run("missing script", func(t *testing.T) {
		script := *created
		script.ID = 9999
		_, err := uc.Update(ctx, &script, nil)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})
}

func TestScriptUseCase_ContentAndDelete(t *testing.T) {
	ctx := context.Background()
	repo, store, uc := newScriptFixture(t)

	created, err := uc.Create(ctx, validScript(), []byte("print('hi')"))
	require.NoError(t, err)

	t.Run("get content", func(t *testing.T) {
		content, err := uc.GetContent(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, []byte("print('hi')"), content)

		_, err = uc.GetContent(ctx, 9999)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})

	t.Run("delete removes file and metadata", func(t *testing.T) {
		err := uc.Delete(ctx, created.ID)
		require.NoError(t, err)
		assert.NotContains(t, store.files, "web/release/deploy.py")
		assert.Empty(t, repo.scripts)

		err = uc.Delete(ctx, created.ID)
		require.Error(t, err)
		assert.True(t, errorx.IsCode(err, errorx.CodeRecordNotFound))
	})
}

func TestScriptUseCase_StoreRequired(t *testing.T) {
	ctx := context.Background()
	uc := NewScriptUseCase(newMockScriptRepo(), nil, nil)

	_, err := uc.Create(ctx, validScript(), []byte("x"))
	require.Error(t, err)
	assert.True(t, errorx.IsCode(err, errorx.CodeConfigError))

	_, err = uc.GetContent(ctx, 1)
	require.Error(t, err)
	assert.True(t, errorx.IsCode(err, errorx.CodeConfigError))
}

func TestScriptRepoPath(t *testing.T) {
	tests := []struct {
		name     string
		script   *Script
		wantPath string
		wantErr  bool
	}{
		{
			name:     "language extension",
			script:   &Script{Project: "web", Label: "release", Name: "deploy", Language: "python"},
			wantPath: "web/release/deploy.py",
		},
		{
			name:     "name already has extension",
			script:   &Script{Project: "web", Label: "release", Name: "deploy.py", Language: "python"},
			wantPath: "web/release/deploy.py",
		},
		{
			name:     "unknown language falls back to txt",
			script:   &Script{Project: "web", Label: "release", Name: "deploy", Language: "brainfuck"},
			wantPath: "web/release/deploy.txt",
		},
		{
			name:    "path separator rejected",
			script:  &Script{Project: "web", Label: "release", Name: "de/ploy"},
			wantErr: true,
		},
		{
			name:    "dot dot rejected",
			script:  &Script{Project: "web", Label: "..", Name: "deploy"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scriptRepoPath(tt.script)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, got)
		})
	}
}
