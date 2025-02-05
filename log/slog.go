package log

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/haoran-mc/tcp-reset/config"
)

const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

func init() {
	slogLevel := slog.LevelInfo
	switch config.Conf.LogLevel {
	case LevelError:
		slogLevel = slog.LevelError
	case LevelWarn:
		slogLevel = slog.LevelWarn
	case LevelInfo:
		slogLevel = slog.LevelInfo
	case LevelDebug:
		slogLevel = slog.LevelDebug
	}
	textHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
	})
	slog.SetDefault(slog.New(textHandler))
	fmt.Println("==> log level(slog): " + slogLevel.Level().String())
}
