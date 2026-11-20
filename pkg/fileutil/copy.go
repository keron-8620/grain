package fileutil

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"emperror.dev/errors"
)

// CopyFile 从源路径复制单个文件到目标路径。
// 保留文件权限、修改时间（mtime），访问时间（atime）使用默认值。
// 示例:
//
//	CopyFile(context.Background(), "/tmp/src.txt", "/tmp/dst.txt") // 直接复制
//	CopyFile(context.Background(), "/tmp/src.txt", "/tmp/dir/")    // 复制到目录（自动拼接文件名）
func CopyFile(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return errors.WrapIf(err, "上下文已取消")
	}

	// 公共校验
	if err := ValidatePath(ctx, src); err != nil {
		return errors.WithMessage(err, "源路径校验失败")
	}
	if err := ValidatePath(ctx, dst); err != nil {
		return errors.WithMessage(err, "目标路径校验失败")
	}

	// 获取源文件信息
	srcInfo, err := GetFileInfo(ctx, src)
	if err != nil {
		return errors.WithMessage(err, "获取源文件信息失败")
	}
	if srcInfo.IsDir() {
		return errors.Errorf("源路径是目录，无法复制为文件, src=%s", src)
	}

	// 处理目标路径（如果是目录，自动拼接文件名）
	dst = CleanPath(dst)
	dstInfo, err := GetFileInfo(ctx, dst)
	if err == nil {
		if IsSameFile(srcInfo, dstInfo) {
			return nil // 相同文件，无需操作
		}
		if dstInfo.IsDir() {
			dst = filepath.Join(dst, filepath.Base(src))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.WithMessage(err, "检查目标路径失败")
	}

	// 确保父目录存在（继承源文件权限）
	if err = EnsureParentDir(ctx, dst, srcInfo.Mode().Perm()); err != nil {
		return errors.WithMessage(err, "确保父目录存在失败")
	}

	// 打开源文件（只读）
	srcFile, err := os.Open(src) // #nosec G304
	if err != nil {
		return errors.WithMessagef(err, "打开源文件失败, src=%s", src)
	}
	defer func() { _ = srcFile.Close() }()

	// 创建目标文件（继承源权限）
	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode().Perm()) // #nosec G304
	if err != nil {
		return errors.WithMessagef(err, "创建目标文件失败, dst=%s", dst)
	}
	defer func() { _ = dstFile.Close() }()

	// 带缓冲区复制（64KB 适配大多数场景）
	buffer := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(dstFile, srcFile, buffer); err != nil {
		return errors.WithMessage(err, "复制文件内容失败")
	}

	// 同步到磁盘（确保数据落盘）
	if err := dstFile.Sync(); err != nil {
		return errors.WithMessage(err, "同步目标文件到磁盘失败")
	}

	// 保留修改时间（atime 用源文件的，无需设为当前时间）
	if err := os.Chtimes(dst, srcInfo.ModTime(), srcInfo.ModTime()); err != nil {
		return errors.WithMessagef(err, "设置文件时间失败, dst=%s", dst)
	}

	return nil
}

// copySymlink 复制符号链接本身（不跟随链接目标）。
// 若目标已存在且指向相同的链接目标则跳过，否则先移除再重建。
func copySymlink(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return errors.WrapIf(err, "上下文已取消")
	}

	if err := ValidatePath(ctx, src); err != nil {
		return errors.WithMessage(err, "源路径校验失败")
	}
	if err := ValidatePath(ctx, dst); err != nil {
		return errors.WithMessage(err, "目标路径校验失败")
	}

	linkTarget, err := os.Readlink(src)
	if err != nil {
		return errors.WithMessagef(err, "读取符号链接失败, src=%s", src)
	}

	switch dstInfo, lErr := os.Lstat(dst); {
	case lErr == nil:
		if dstInfo.Mode()&os.ModeSymlink != 0 {
			if existing, rErr := os.Readlink(dst); rErr == nil && existing == linkTarget {
				return nil // 链接目标一致，无需操作
			}
		}
		if err := os.RemoveAll(dst); err != nil {
			return errors.WithMessagef(err, "清理已存在的目标路径失败, dst=%s", dst)
		}
	case !errors.Is(lErr, os.ErrNotExist):
		return errors.WithMessagef(lErr, "检查目标路径失败, dst=%s", dst)
	}

	if err := os.Symlink(linkTarget, dst); err != nil {
		return errors.WithMessagef(
			err,
			"创建符号链接失败, src=%s, dst=%s, link_target=%s",
			src,
			dst,
			linkTarget,
		)
	}

	return nil
}

// CopyDir 复制目录树从源到目标
// copyContents 为 true: 复制 src 内的所有内容到 dst（类似 cp -r src/. dst）
// copyContents 为 false: 复制 src 目录本身到 dst（类似 cp -r src dst）
// 符号链接按链接本身复制，不跟随链接目标。
// 示例:
//
//	CopyDir(context.Background(), "/tmp/src", "/tmp/dst", false) // 结果: /tmp/dst/src
//	CopyDir(context.Background(), "/tmp/src", "/tmp/dst", true)  // 结果: /tmp/dst/[src内的文件]
func CopyDir(ctx context.Context, src, dst string, copyContents bool) error {
	if err := ctx.Err(); err != nil {
		return errors.WrapIf(err, "上下文已取消")
	}
	// 公共校验
	if err := ValidatePath(ctx, src); err != nil {
		return errors.WithMessage(err, "源路径校验失败")
	}
	if err := ValidatePath(ctx, dst); err != nil {
		return errors.WithMessage(err, "目标路径校验失败")
	}

	// 获取源目录信息
	srcInfo, err := GetFileInfo(ctx, src)
	if err != nil {
		return errors.WithMessage(err, "获取源目录信息失败")
	}
	if !srcInfo.IsDir() {
		return errors.Errorf("源路径是文件，无法复制为目录, src=%s", src)
	}

	// 确定目标路径
	dest := dst
	if !copyContents {
		dstInfo, err := GetFileInfo(ctx, dst)
		if err == nil {
			if IsSameFile(srcInfo, dstInfo) {
				return nil // 相同目录，无需操作
			}
			if dstInfo.IsDir() {
				dest = filepath.Join(dst, filepath.Base(src))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.WithMessage(err, "检查目标路径失败")
		}
	}

	// 创建目标目录（继承源权限）
	if err = MkdirAll(ctx, dest, srcInfo.Mode().Perm()); err != nil {
		return errors.WithMessagef(err, "创建目标目录失败, dest=%s", dest)
	}

	// 读取源目录条目
	entries, err := os.ReadDir(src)
	if err != nil {
		return errors.WithMessagef(err, "读取源目录条目失败, src=%s", src)
	}

	// 遍历并复制所有条目
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dest, entry.Name())

		// 直接用 entry.Info()，避免重复 os.Stat
		entryInfo, err := entry.Info()
		if err != nil {
			return errors.WithMessagef(err, "获取条目信息失败, entry_name=%s", entry.Name())
		}

		switch {
		case entryInfo.Mode()&os.ModeSymlink != 0:
			// 符号链接必须复制链接本身：entry.Info() 使用 Lstat，
			// 若改用 CopyFile 会跟随链接，指向目录时会被误判为目录而失败。
			if err := copySymlink(ctx, srcPath, dstPath); err != nil {
				return errors.WithMessagef(
					err,
					"复制符号链接失败, src_path=%s, dst_path=%s",
					srcPath,
					dstPath,
				)
			}
		case entryInfo.IsDir():
			// 递归复制子目录（子目录始终复制内容）
			if err := CopyDir(ctx, srcPath, dstPath, true); err != nil {
				return errors.WithMessagef(err, "复制子目录失败, src_path=%s, dst_path=%s", srcPath, dstPath)
			}
		default:
			// 复制文件
			if err := CopyFile(ctx, srcPath, dstPath); err != nil {
				return errors.WithMessagef(err, "复制文件失败, src_path=%s, dst_path=%s", srcPath, dstPath)
			}
		}
	}

	// 保留目录修改时间
	if err := os.Chtimes(dest, srcInfo.ModTime(), srcInfo.ModTime()); err != nil {
		return errors.WithMessagef(err, "设置目录时间失败, dest=%s", dest)
	}

	return nil
}

// SyncNewFiles 同步文件或目录树，当目标存在同名文件就跳过，不存在就拷贝。
// copyContents 为 true: 复制 src 目录内的所有内容到 dst（类似 cp -r src/. dst）
// copyContents 为 false: 复制 src 目录本身到 dst（类似 cp -r src dst）
// 示例:
//
//	SyncNewFiles(context.Background(), "/tmp/src", "/tmp/dst", false) // 结果: /tmp/dst/src (跳过已存在文件)
//	SyncNewFiles(context.Background(), "/tmp/src", "/tmp/dst", true)  // 结果: /tmp/dst/[src内的文件] (跳过已存在文件)
func SyncNewFiles(ctx context.Context, src, dst string, copyContents bool) error {
	if err := ctx.Err(); err != nil {
		return errors.WrapIf(err, "上下文已取消")
	}

	// 公共校验
	if err := ValidatePath(ctx, src); err != nil {
		return errors.WithMessage(err, "源路径校验失败")
	}
	if err := ValidatePath(ctx, dst); err != nil {
		return errors.WithMessage(err, "目标路径校验失败")
	}

	// 获取源信息
	srcInfo, err := GetFileInfo(ctx, src)
	if err != nil {
		return errors.WithMessage(err, "获取源路径信息失败")
	}

	// 如果源路径是单个文件
	if !srcInfo.IsDir() {
		target := CleanPath(dst)
		dstInfo, err := GetFileInfo(ctx, target)
		if err == nil {
			if IsSameFile(srcInfo, dstInfo) {
				return nil // 相同文件，无需操作
			}
			if dstInfo.IsDir() {
				target = filepath.Join(target, filepath.Base(src))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.WithMessage(err, "检查目标路径失败")
		}

		// 检查目标文件是否存在，存在同名文件则跳过
		if _, err := os.Lstat(target); err == nil {
			return nil
		} else if !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
			return errors.WithMessagef(err, "检查目标文件失败, dst_path=%s", target)
		}

		return CopyFile(ctx, src, target)
	}

	// 确定目标路径
	dest := dst
	if !copyContents {
		dstInfo, err := GetFileInfo(ctx, dst)
		if err == nil {
			if IsSameFile(srcInfo, dstInfo) {
				return nil // 相同目录，无需操作
			}
			if dstInfo.IsDir() {
				dest = filepath.Join(dst, filepath.Base(src))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.WithMessage(err, "检查目标路径失败")
		}
	}

	// 创建目标目录（继承源权限）
	if err = MkdirAll(ctx, dest, srcInfo.Mode().Perm()); err != nil {
		return errors.WithMessagef(err, "创建目标目录失败, dest=%s", dest)
	}

	// 读取源目录条目
	entries, err := os.ReadDir(src)
	if err != nil {
		return errors.WithMessagef(err, "读取源目录条目失败, src=%s", src)
	}

	// 遍历并同步所有条目
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return errors.WrapIf(err, "上下文已取消")
		}

		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dest, entry.Name())

		// 直接用 entry.Info()，避免重复 os.Stat
		entryInfo, err := entry.Info()
		if err != nil {
			return errors.WithMessagef(err, "获取条目信息失败, entry_name=%s", entry.Name())
		}

		switch {
		case entryInfo.Mode()&os.ModeSymlink != 0:
			// 符号链接同样遵循“目标存在则跳过”的同步策略
			if _, err := os.Lstat(dstPath); err == nil {
				continue
			} else if !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
				return errors.WithMessagef(err, "检查目标路径失败, dst_path=%s", dstPath)
			}

			if err := copySymlink(ctx, srcPath, dstPath); err != nil {
				return errors.WithMessagef(
					err,
					"同步符号链接失败, src_path=%s, dst_path=%s",
					srcPath,
					dstPath,
				)
			}
		case entryInfo.IsDir():
			// 递归同步子目录（子目录始终复制内容）
			if err := SyncNewFiles(ctx, srcPath, dstPath, true); err != nil {
				return errors.WithMessagef(err, "同步子目录失败, src_path=%s, dst_path=%s", srcPath, dstPath)
			}
		default:
			// 检查目标是否存在同名文件/条目，存在则跳过
			if _, err := os.Lstat(dstPath); err == nil {
				continue
			} else if !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
				return errors.WithMessagef(err, "检查目标文件失败, dst_path=%s", dstPath)
			}

			// 不存在则复制文件
			if err := CopyFile(ctx, srcPath, dstPath); err != nil {
				return errors.WithMessagef(err, "复制新文件失败, src_path=%s, dst_path=%s", srcPath, dstPath)
			}
		}
	}

	// 保留目录修改时间
	if err := os.Chtimes(dest, srcInfo.ModTime(), srcInfo.ModTime()); err != nil {
		return errors.WithMessagef(err, "设置目录时间失败, dest=%s", dest)
	}

	return nil
}
