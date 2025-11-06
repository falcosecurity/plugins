package config

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
)

const (
	HookCreate = 1 << iota
	HookStart
	HookRemove

	defaultLabelMaxLen = 100
)

type SocketsEngine struct {
	Enabled bool     `json:"enabled"`
	Sockets []string `json:"sockets"`
}

type EngineCfg struct {
	SocketsEngines map[string]SocketsEngine `json:"engines"`
	LabelMaxLen    int                      `json:"label_max_len"`
	WithSize       bool                     `json:"with_size"`
	HostRoot       string                   `json:"host_root"`
	Hooks          byte                     `json:"hooks"`
	LogLevel       logLevel                 `json:"log_level"`
}

// logLevel wraps slog.Level to support JSON unmarshaling from string
type logLevel slog.Level

func (l *logLevel) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try unmarshaling as integer
		var i int
		if err2 := json.Unmarshal(data, &i); err2 != nil {
			return err
		}
		*l = logLevel(i)
		return nil
	}
	*l = logLevel(toSlogLevel(s))
	return nil
}

func (l logLevel) Level() slog.Level {
	return slog.Level(l)
}

var c EngineCfg

// updateSlogHandler updates the default slog handler with the current log level from config
func updateSlogHandler() {
	level := c.LogLevel.Level()
	// If log level is zero (not set), default to error
	if level == 0 {
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(newFalcoLogHandler(os.Stdout, level)))
}

// Init sets cfg default values
func init() {
	c.LabelMaxLen = defaultLabelMaxLen
	c.WithSize = false
	// We will always override it when called by C++ plugin.
	// By default, for go-worker executable (make exe) and go-worker tests,
	// we attach remove hook too.
	c.Hooks = HookCreate | HookRemove
	// Set default slog handler with Falco log format
	// Format: Thu Nov 06 11:46:17 2025: [container-engine] [info]: message
	updateSlogHandler()
}

func Load(initCfg string) error {
	err := json.Unmarshal([]byte(initCfg), &c)
	if err != nil {
		return err
	}
	// Update the slog handler with the new log level if it was set in config
	updateSlogHandler()
	slog.Default().LogAttrs(context.Background(), slog.LevelDebug, "container-engine logger initialized", slog.String("log_level", levelToString(c.LogLevel.Level())))
	return nil
}

func Get() EngineCfg {
	return c
}

func GetLabelMaxLen() int {
	return c.LabelMaxLen
}

func GetWithSize() bool {
	return c.WithSize
}

func GetHostRoot() string {
	return c.HostRoot
}

func IsHookEnabled(hook byte) bool {
	return c.Hooks&hook != 0
}
