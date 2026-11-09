package logx

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Options 日志配置项
type Options struct {
	Level        string         `mapstructure:"level" json:"level" yaml:"level"`
	LevelVar     *slog.LevelVar `mapstructure:"-" json:"-" yaml:"-"`                // 可选：外部传入的动态日志级别控制器
	Format       string         `mapstructure:"format" json:"format" yaml:"format"` // json / text
	Filename     string         `mapstructure:"filename" json:"filename" yaml:"filename"`
	EnableStdout bool           `mapstructure:"enable_stdout" json:"enable_stdout" yaml:"enable_stdout"`
	EnableFile   bool           `mapstructure:"enable_file" json:"enable_file" yaml:"enable_file"`
	AddSource    bool           `mapstructure:"add_source" json:"add_source" yaml:"add_source"`
	MaxSize      int            `mapstructure:"max_size" json:"max_size" yaml:"max_size"`
	MaxAge       int            `mapstructure:"max_age" json:"max_age" yaml:"max_age"`
	MaxBackups   int            `mapstructure:"max_backups" json:"max_backups" yaml:"max_backups"`
	LocalTime    bool           `mapstructure:"local_time" json:"local_time" yaml:"local_time"`
	Compress     bool           `mapstructure:"compress" json:"compress" yaml:"compress"`
}

// NewLumLogger 创建基于 lumberjack 的滚动文件日志写入器
// 如果 logPath 不为空，优先使用 logPath，否则使用 opts.Filename
func NewLumLogger(opts *Options, logPath string) (*lumberjack.Logger, error) {
	if opts == nil {
		return nil, errors.New("log config is missing")
	}

	targetPath := strings.TrimSpace(logPath)
	if targetPath == "" {
		targetPath = strings.TrimSpace(opts.Filename)
	}
	if targetPath == "" {
		return nil, errors.New("log file path is missing")
	}

	return &lumberjack.Logger{
		Filename:   targetPath,
		MaxSize:    orDefault(opts.MaxSize, 10), // MB
		MaxAge:     orDefault(opts.MaxAge, 30),  // days
		MaxBackups: orDefault(opts.MaxBackups, 10),
		LocalTime:  opts.LocalTime,
		Compress:   opts.Compress,
	}, nil
}

// New 根据 Options 初始化 slog.Logger，并返回日志句柄与资源释放函数
func New(opts *Options) (*slog.Logger, func() error, error) {
	if opts == nil {
		return nil, nil, errors.New("log config is missing")
	}

	var writers []io.Writer
	var closer func() error = func() error { return nil }

	enableStdout := opts.EnableStdout
	enableFile := opts.EnableFile

	// 如果未显式开启任何输出源，进行智能推导
	if !enableStdout && !enableFile {
		if strings.TrimSpace(opts.Filename) != "" {
			enableFile = true
		} else {
			enableStdout = true
		}
	}

	if enableStdout {
		writers = append(writers, os.Stdout)
	}

	if enableFile {
		lumLog, err := NewLumLogger(opts, opts.Filename)
		if err != nil {
			return nil, nil, fmt.Errorf("init lumberjack logger: %w", err)
		}
		writers = append(writers, lumLog)
		closer = lumLog.Close
	}

	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	writer := io.MultiWriter(writers...)

	// 动态日志级别支持：若未指定则自动分配 LevelVar，实现全局与派生 Logger 级别联动
	levelVar := opts.LevelVar
	initialLevel := parseLevel(opts.Level)
	if levelVar == nil {
		levelVar = new(slog.LevelVar)
		levelVar.Set(initialLevel)
		opts.LevelVar = levelVar
	} else if strings.TrimSpace(opts.Level) != "" {
		levelVar.Set(initialLevel)
	}

	handOpts := &slog.HandlerOptions{
		AddSource: opts.AddSource,
		Level:     levelVar,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				if source, ok := a.Value.Any().(*slog.Source); ok && source != nil {
					source.File = shortenFilePath(source.File)
				}
			}
			return a
		},
	}

	var handler slog.Handler
	if strings.EqualFold(strings.TrimSpace(opts.Format), "text") {
		handler = slog.NewTextHandler(writer, handOpts)
	} else {
		handler = slog.NewJSONHandler(writer, handOpts)
	}

	handler = NewContextHandler(handler, levelVar)
	return slog.New(handler), closer, nil
}

// LevelVarFromLogger 从 Logger 中提取绑定的 LevelVar 控制器
func LevelVarFromLogger(logger *slog.Logger) *slog.LevelVar {
	if logger == nil {
		return nil
	}
	if ch, ok := logger.Handler().(*ContextHandler); ok {
		return ch.LevelVar()
	}
	return nil
}

// SetLevel 动态调整 Logger 的日志输出级别
func SetLevel(logger *slog.Logger, level slog.Level) bool {
	lv := LevelVarFromLogger(logger)
	if lv == nil {
		return false
	}
	lv.Set(level)
	return true
}

// SetLevelString 通过字符串名称（debug/info/warn/error）动态调整 Logger 日志输出级别
func SetLevelString(logger *slog.Logger, levelStr string) error {
	lv := LevelVarFromLogger(logger)
	if lv == nil {
		return errors.New("logger does not support dynamic level adjustment: LevelVar not found")
	}
	lv.Set(parseLevel(levelStr))
	return nil
}

// SetDefault 将指定的 logger 设置为全局默认日志器
func SetDefault(logger *slog.Logger) {
	if logger == nil {
		return
	}
	slog.SetDefault(logger)
}

// Default 返回当前的全局默认日志器
func Default() *slog.Logger {
	return slog.Default()
}

// SetDefaultLevel 动态调整全局默认日志器的级别
func SetDefaultLevel(level slog.Level) bool {
	return SetLevel(slog.Default(), level)
}

// SetDefaultLevelString 通过字符串动态调整全局默认日志器的级别
func SetDefaultLevelString(levelStr string) error {
	return SetLevelString(slog.Default(), levelStr)
}

func parseLevel(s string) slog.Level {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return slog.LevelInfo
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(trimmed)); err == nil {
		return lvl
	}
	switch strings.ToLower(trimmed) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// shortenFilePath 截断较长的绝对路径，保留相对结构（最后 3 级目录）
func shortenFilePath(file string) string {
	file = filepath.Clean(filepath.ToSlash(file))
	parts := strings.Split(file, string(filepath.Separator))
	if len(parts) > 3 {
		return filepath.Join(parts[len(parts)-3:]...)
	}
	return file
}
