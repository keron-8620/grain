package logx

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

type Options struct {
	Level      string `mapstructure:"level" json:"level" yaml:"level"`
	Format     string `mapstructure:"format" json:"format" yaml:"format"`
	MaxSize    int    `mapstructure:"max_size" json:"max_size" yaml:"max_size"`
	MaxAge     int    `mapstructure:"max_age" json:"max_age" yaml:"max_age"`
	MaxBackups int    `mapstructure:"max_backups" json:"max_backups" yaml:"max_backups"`
	LocalTime  bool   `mapstructure:"local_time" json:"local_time" yaml:"local_time"`
	Compress   bool   `mapstructure:"compress" json:"compress" yaml:"compress"`
}

func New(opts *Options, logPath string) (*slog.Logger, error) {
	if opts == nil {
		return nil, errors.New("log config is missing")
	}

	lumLog := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    orDefault(opts.MaxSize, 10), // MB
		MaxAge:     orDefault(opts.MaxAge, 30),  // days
		MaxBackups: orDefault(opts.MaxBackups, 10),
		LocalTime:  opts.LocalTime,
		Compress:   opts.Compress,
	}
	writer := io.MultiWriter(os.Stdout, lumLog)

	level := parseLevel(opts.Level)
	handOpts := &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}

	var handler slog.Handler
	if strings.ToLower(strings.TrimSpace(opts.Format)) == "text" {
		handler = slog.NewTextHandler(writer, handOpts)
	} else {
		handler = slog.NewJSONHandler(writer, handOpts)
	}

	return slog.New(handler), nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
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
