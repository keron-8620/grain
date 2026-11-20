package fileutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyFile(t *testing.T) {
	ctx := context.Background()

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// 创建源文件
	srcFile, err := os.CreateTemp(tempDir, "src")
	require.NoError(t, err)
	srcFilePath := srcFile.Name()
	srcContent := "test content"
	_, err = srcFile.WriteString(srcContent)
	require.NoError(t, err)
	_ = srcFile.Close()

	// 测试复制到新文件
	dstFilePath := filepath.Join(tempDir, "dst.txt")
	err = CopyFile(ctx, srcFilePath, dstFilePath)
	assert.NoError(t, err)

	// 验证目标文件存在且内容正确
	dstContent, err := os.ReadFile(dstFilePath)
	assert.NoError(t, err)
	assert.Equal(t, srcContent, string(dstContent))

	// 测试复制到目录
	subdirPath := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subdirPath, 0755)
	require.NoError(t, err)

	err = CopyFile(ctx, srcFilePath, subdirPath)
	assert.NoError(t, err)

	// 验证文件已复制到目录
	copiedFilePath := filepath.Join(subdirPath, filepath.Base(srcFilePath))
	exists, err := pathExists(copiedFilePath)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestCopyDir(t *testing.T) {
	ctx := context.Background()

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// 创建源目录结构
	srcDir := filepath.Join(tempDir, "src")
	err = os.Mkdir(srcDir, 0755)
	require.NoError(t, err)

	// 在源目录中创建文件
	srcFile, err := os.CreateTemp(srcDir, "test")
	require.NoError(t, err)
	_, err = srcFile.WriteString("test content")
	require.NoError(t, err)
	_ = srcFile.Close()

	// 创建子目录
	srcSubdir := filepath.Join(srcDir, "subdir")
	err = os.Mkdir(srcSubdir, 0755)
	require.NoError(t, err)

	// 在子目录中创建文件
	srcSubfile, err := os.CreateTemp(srcSubdir, "test")
	require.NoError(t, err)
	_, err = srcSubfile.WriteString("subdir content")
	require.NoError(t, err)
	_ = srcSubfile.Close()

	// 测试复制目录（不包含内容）
	dstDir := filepath.Join(tempDir, "dst")
	err = CopyDir(ctx, srcDir, dstDir, false)
	assert.NoError(t, err)

	// 验证目标目录结构
	// 当copyContents为false且dst不存在时，dest等于dst，而不是filepath.Join(dst, filepath.Base(src))
	exists, err := pathExists(dstDir)
	assert.NoError(t, err)
	assert.True(t, exists)

	// 测试复制目录到已存在的目录
	existingDir := filepath.Join(tempDir, "existing")
	err = os.Mkdir(existingDir, 0755)
	require.NoError(t, err)

	err = CopyDir(ctx, srcDir, existingDir, false)
	assert.NoError(t, err)

	// 验证目录已复制到已存在的目录下
	expectedSubDir := filepath.Join(existingDir, "src")
	exists, err = pathExists(expectedSubDir)
	assert.NoError(t, err)
	assert.True(t, exists)

	// 测试复制目录内容
	dstContentDir := filepath.Join(tempDir, "dst_content")
	err = os.Mkdir(dstContentDir, 0755)
	require.NoError(t, err)

	err = CopyDir(ctx, srcDir, dstContentDir, true)
	assert.NoError(t, err)

	// 验证目标目录中包含源目录的内容
	expectedFile := filepath.Join(dstContentDir, filepath.Base(srcFile.Name()))
	exists, err = pathExists(expectedFile)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestCopyDirWithSymlink(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// 模拟 mon 程序包结构：jre 为指向包内目录的相对符号链接
	srcDir := filepath.Join(tempDir, "src")
	jreDir := filepath.Join(srcDir, "database", "flyway", "jre")
	require.NoError(t, os.MkdirAll(filepath.Join(jreDir, "lib"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(jreDir, "release"), []byte("jre-release"), 0644))
	require.NoError(t, os.Symlink("./database/flyway/jre", filepath.Join(srcDir, "jre")))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "start.sh"), []byte("#!/bin/sh"), 0755))
	require.NoError(t, os.Symlink("start.sh", filepath.Join(srcDir, "run.sh")))

	dstDir := filepath.Join(tempDir, "dst")
	require.NoError(t, CopyDir(ctx, srcDir, dstDir, true))

	// 链接应被复制为链接本身，链接目标保持不变
	expectedLinks := map[string]string{
		"jre":    "./database/flyway/jre",
		"run.sh": "start.sh",
	}
	for name, wantTarget := range expectedLinks {
		info, err := os.Lstat(filepath.Join(dstDir, name))
		require.NoError(t, err)
		require.NotZero(t, info.Mode()&os.ModeSymlink, "%s 应该是符号链接", name)

		gotTarget, err := os.Readlink(filepath.Join(dstDir, name))
		require.NoError(t, err)
		assert.Equal(t, wantTarget, gotTarget)
	}

	// 通过链接可以访问到已复制的目录内容
	content, err := os.ReadFile(filepath.Join(dstDir, "jre", "release"))
	require.NoError(t, err)
	assert.Equal(t, "jre-release", string(content))

	// 重复复制：链接目标一致时应直接跳过，不报错
	require.NoError(t, CopyDir(ctx, srcDir, dstDir, true))

	// 链接目标不一致时应重建
	require.NoError(t, os.Remove(filepath.Join(dstDir, "run.sh")))
	require.NoError(t, os.Symlink("other.sh", filepath.Join(dstDir, "run.sh")))
	require.NoError(t, CopyDir(ctx, srcDir, dstDir, true))

	gotTarget, err := os.Readlink(filepath.Join(dstDir, "run.sh"))
	require.NoError(t, err)
	assert.Equal(t, "start.sh", gotTarget)
}

func TestSyncNewFilesWithSymlink(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	srcDir := filepath.Join(tempDir, "src")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "database", "jre"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "database", "jre", "release"), []byte("jre"), 0644))
	require.NoError(t, os.Symlink("./database/jre", filepath.Join(srcDir, "jre")))

	dstDir := filepath.Join(tempDir, "dst")
	require.NoError(t, os.MkdirAll(dstDir, 0755))

	require.NoError(t, SyncNewFiles(ctx, srcDir, dstDir, true))

	info, err := os.Lstat(filepath.Join(dstDir, "jre"))
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
	gotTarget, err := os.Readlink(filepath.Join(dstDir, "jre"))
	require.NoError(t, err)
	assert.Equal(t, "./database/jre", gotTarget)

	// 目标已存在同名条目时跳过，不覆盖
	require.NoError(t, os.Remove(filepath.Join(dstDir, "jre")))
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, "jre"), []byte("keep"), 0644))
	require.NoError(t, SyncNewFiles(ctx, srcDir, dstDir, true))

	content, err := os.ReadFile(filepath.Join(dstDir, "jre"))
	require.NoError(t, err)
	assert.Equal(t, "keep", string(content))
}

func TestSyncNewFiles(t *testing.T) {
	ctx := context.Background()

	t.Run("同步目录内容且跳过已存在文件", func(t *testing.T) {
		tempDir := t.TempDir()

		srcDir := filepath.Join(tempDir, "src")
		dstDir := filepath.Join(tempDir, "dst")
		require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "sub"), 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(dstDir, "sub"), 0755))

		// 源目录文件
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "exist.txt"), []byte("src-exist"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "new.txt"), []byte("src-new"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "sub", "sub_exist.txt"), []byte("src-sub-exist"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "sub", "sub_new.txt"), []byte("src-sub-new"), 0644))

		// 目标目录已有文件（内容与源不同）和目标特有文件
		require.NoError(t, os.WriteFile(filepath.Join(dstDir, "exist.txt"), []byte("dst-exist"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dstDir, "sub", "sub_exist.txt"), []byte("dst-sub-exist"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dstDir, "custom.txt"), []byte("dst-custom"), 0644))

		// 执行同步（copyContents = true）
		err := SyncNewFiles(ctx, srcDir, dstDir, true)
		assert.NoError(t, err)

		// 验证1: 已存在的文件不被覆盖
		existContent, err := os.ReadFile(filepath.Join(dstDir, "exist.txt"))
		require.NoError(t, err)
		assert.Equal(t, "dst-exist", string(existContent))

		subExistContent, err := os.ReadFile(filepath.Join(dstDir, "sub", "sub_exist.txt"))
		require.NoError(t, err)
		assert.Equal(t, "dst-sub-exist", string(subExistContent))

		// 验证2: 新增文件被正常复制
		newContent, err := os.ReadFile(filepath.Join(dstDir, "new.txt"))
		require.NoError(t, err)
		assert.Equal(t, "src-new", string(newContent))

		subNewContent, err := os.ReadFile(filepath.Join(dstDir, "sub", "sub_new.txt"))
		require.NoError(t, err)
		assert.Equal(t, "src-sub-new", string(subNewContent))

		// 验证3: 目标独有的文件依然保留
		customContent, err := os.ReadFile(filepath.Join(dstDir, "custom.txt"))
		require.NoError(t, err)
		assert.Equal(t, "dst-custom", string(customContent))
	})

	t.Run("copyContents为false且目标已存在", func(t *testing.T) {
		tempDir := t.TempDir()

		srcDir := filepath.Join(tempDir, "src")
		dstDir := filepath.Join(tempDir, "dst")
		require.NoError(t, os.MkdirAll(srcDir, 0755))
		require.NoError(t, os.MkdirAll(dstDir, 0755))

		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("content-a"), 0644))

		// dstDir 存在时，copyContents = false 会在 dstDir 下创建 src 子目录
		err := SyncNewFiles(ctx, srcDir, dstDir, false)
		assert.NoError(t, err)

		expectedFile := filepath.Join(dstDir, "src", "a.txt")
		exists, err := pathExists(expectedFile)
		assert.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("同步单个文件", func(t *testing.T) {
		tempDir := t.TempDir()

		srcFile := filepath.Join(tempDir, "file.txt")
		require.NoError(t, os.WriteFile(srcFile, []byte("src-file"), 0644))

		// 1. 目标不存在，复制成功
		dstFile1 := filepath.Join(tempDir, "dst1.txt")
		err := SyncNewFiles(ctx, srcFile, dstFile1, false)
		assert.NoError(t, err)
		c1, err := os.ReadFile(dstFile1)
		require.NoError(t, err)
		assert.Equal(t, "src-file", string(c1))

		// 2. 目标已存在，跳过不覆盖
		dstFile2 := filepath.Join(tempDir, "dst2.txt")
		require.NoError(t, os.WriteFile(dstFile2, []byte("dst2-original"), 0644))
		err = SyncNewFiles(ctx, srcFile, dstFile2, false)
		assert.NoError(t, err)
		c2, err := os.ReadFile(dstFile2)
		require.NoError(t, err)
		assert.Equal(t, "dst2-original", string(c2))

		// 3. 目标为目录，文件不存在时拷贝入目录
		subDir := filepath.Join(tempDir, "target_dir")
		require.NoError(t, os.MkdirAll(subDir, 0755))
		err = SyncNewFiles(ctx, srcFile, subDir, false)
		assert.NoError(t, err)
		c3, err := os.ReadFile(filepath.Join(subDir, "file.txt"))
		require.NoError(t, err)
		assert.Equal(t, "src-file", string(c3))
	})

	t.Run("上下文取消", func(t *testing.T) {
		tempDir := t.TempDir()
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err := SyncNewFiles(cancelCtx, tempDir, filepath.Join(tempDir, "dst"), true)
		assert.Error(t, err)
	})
}
