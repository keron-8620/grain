package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"Debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"   ", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"WARNING", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"unknown", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseLevel(tt.input))
		})
	}
}

func TestOrDefault(t *testing.T) {
	assert.Equal(t, 10, orDefault(0, 10))
	assert.Equal(t, 10, orDefault(-5, 10))
	assert.Equal(t, 25, orDefault(25, 10))
}

func TestShortenFilePath(t *testing.T) {
	longPath := filepath.Join("home", "user", "project", "grain", "pkg", "logx", "logx.go")
	short := shortenFilePath(longPath)
	expected := filepath.Join("pkg", "logx", "logx.go")
	assert.Equal(t, expected, short)

	shortPath := "main.go"
	assert.Equal(t, "main.go", shortenFilePath(shortPath))
}

func TestNewLumLogger(t *testing.T) {
	t.Run("nil options", func(t *testing.T) {
		lum, err := NewLumLogger(nil, "/tmp/test.log")
		assert.Error(t, err)
		assert.Nil(t, lum)
	})

	t.Run("missing log path", func(t *testing.T) {
		opts := &Options{}
		lum, err := NewLumLogger(opts, "")
		assert.Error(t, err)
		assert.Nil(t, lum)
	})

	t.Run("valid with default options", func(t *testing.T) {
		opts := &Options{
			MaxSize:    0, // 应使用默认值 10
			MaxAge:     0, // 应使用默认值 30
			MaxBackups: 0, // 应使用默认值 10
			LocalTime:  true,
			Compress:   true,
		}
		lum, err := NewLumLogger(opts, "/tmp/test.log")
		require.NoError(t, err)
		require.NotNil(t, lum)
		assert.Equal(t, "/tmp/test.log", lum.Filename)
		assert.Equal(t, 10, lum.MaxSize)
		assert.Equal(t, 30, lum.MaxAge)
		assert.Equal(t, 10, lum.MaxBackups)
		assert.True(t, lum.LocalTime)
		assert.True(t, lum.Compress)
	})

	t.Run("fallback to opts.Filename", func(t *testing.T) {
		opts := &Options{
			Filename: "/tmp/from_opts.log",
			MaxSize:  20,
		}
		lum, err := NewLumLogger(opts, "")
		require.NoError(t, err)
		require.NotNil(t, lum)
		assert.Equal(t, "/tmp/from_opts.log", lum.Filename)
		assert.Equal(t, 20, lum.MaxSize)
	})
}

func TestNew(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("nil options", func(t *testing.T) {
		logger, closer, err := New(nil)
		assert.Error(t, err)
		assert.Nil(t, logger)
		assert.Nil(t, closer)
	})

	t.Run("pure stdout output", func(t *testing.T) {
		opts := &Options{
			Level:        "debug",
			Format:       "json",
			EnableStdout: true,
			EnableFile:   false,
		}
		logger, closer, err := New(opts)
		require.NoError(t, err)
		require.NotNil(t, logger)
		require.NotNil(t, closer)
		assert.NoError(t, closer())

		// 验证打印不发生 panic
		logger.Debug("test stdout debug")
	})

	t.Run("pure file output with JSON format", func(t *testing.T) {
		logFile := filepath.Join(tempDir, "file_only.log")
		opts := &Options{
			Level:        "info",
			Format:       "json",
			Filename:     logFile,
			EnableStdout: false,
			EnableFile:   true,
			AddSource:    true,
		}
		logger, closer, err := New(opts)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Info("file only message", slog.String("key", "val"))
		assert.NoError(t, closer())

		data, err := os.ReadFile(logFile)
		require.NoError(t, err)
		content := string(data)
		assert.Contains(t, content, "file only message")
		assert.Contains(t, content, `"key":"val"`)
		// 校验 AddSource 是否生效且被截短
		var logEntry map[string]any
		err = json.Unmarshal([]byte(strings.TrimSpace(content)), &logEntry)
		require.NoError(t, err)
		assert.Equal(t, "INFO", logEntry["level"])
		assert.NotNil(t, logEntry["source"])
	})

	t.Run("text format output", func(t *testing.T) {
		logFile := filepath.Join(tempDir, "text.log")
		opts := &Options{
			Level:      "warn",
			Format:     "text",
			Filename:   logFile,
			EnableFile: true,
		}
		logger, closer, err := New(opts)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Warn("warning text msg")
		assert.NoError(t, closer())

		data, err := os.ReadFile(logFile)
		require.NoError(t, err)
		assert.Contains(t, string(data), "level=WARN")
		assert.Contains(t, string(data), "msg=\"warning text msg\"")
	})

	t.Run("fallback to stdout when neither specified and no filename", func(t *testing.T) {
		opts := &Options{
			Level: "info",
		}
		logger, closer, err := New(opts)
		require.NoError(t, err)
		require.NotNil(t, logger)
		assert.NoError(t, closer())
		logger.Info("fallback stdout")
	})

	t.Run("fallback to file when neither specified but filename given", func(t *testing.T) {
		logFile := filepath.Join(tempDir, "auto_file.log")
		opts := &Options{
			Level:    "info",
			Filename: logFile,
		}
		logger, closer, err := New(opts)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Info("auto file msg")
		assert.NoError(t, closer())

		data, err := os.ReadFile(logFile)
		require.NoError(t, err)
		assert.Contains(t, string(data), "auto file msg")
	})
}

func TestDynamicLevel(t *testing.T) {
	buf := &bytes.Buffer{}
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)

	handler := NewContextHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: lv,
	}), lv)
	logger := slog.New(handler)

	// 验证初始状态：Info 输出，Debug 过滤
	logger.Debug("debug-1")
	assert.Empty(t, buf.String())

	logger.Info("info-1")
	assert.Contains(t, buf.String(), "info-1")
	buf.Reset()

	// 动态调整为 Debug
	assert.True(t, SetLevel(logger, slog.LevelDebug))
	logger.Debug("debug-2")
	assert.Contains(t, buf.String(), "debug-2")
	buf.Reset()

	// 动态调整为 Warn (通过字符串)
	require.NoError(t, SetLevelString(logger, "warn"))
	logger.Info("info-2")
	assert.Empty(t, buf.String())
	logger.Warn("warn-1")
	assert.Contains(t, buf.String(), "warn-1")
	buf.Reset()

	// 验证派生 Logger 级别联动
	subLogger := logger.With(slog.String("module", "sub")).WithGroup("grp")
	subLogger.Info("sub-info-filtered")
	assert.Empty(t, buf.String())

	// 将父 Logger 改回 Info，派生 Logger 实时生效
	require.NoError(t, SetLevelString(logger, "info"))
	subLogger.Info("sub-info-emitted")
	assert.Contains(t, buf.String(), "sub-info-emitted")
	assert.Contains(t, buf.String(), "module")
}

func TestDefaultLogger(t *testing.T) {
	origDefault := slog.Default()
	defer slog.SetDefault(origDefault)

	buf := &bytes.Buffer{}
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	handler := NewContextHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: lv,
	}), lv)
	customLogger := slog.New(handler)

	SetDefault(customLogger)
	assert.Equal(t, customLogger, Default())

	// 测试全局调整级别
	assert.True(t, SetDefaultLevel(slog.LevelWarn))
	assert.Equal(t, slog.LevelWarn, lv.Level())

	require.NoError(t, SetDefaultLevelString("debug"))
	assert.Equal(t, slog.LevelDebug, lv.Level())
}
