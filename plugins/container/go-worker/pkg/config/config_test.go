package config

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogLevel_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantLevel slog.Level
		wantError bool
	}{
		{
			name:      "trace level from string",
			json:      `"trace"`,
			wantLevel: LevelTrace,
			wantError: false,
		},
		{
			name:      "debug level from string",
			json:      `"debug"`,
			wantLevel: slog.LevelDebug,
			wantError: false,
		},
		{
			name:      "info level from string",
			json:      `"info"`,
			wantLevel: slog.LevelInfo,
			wantError: false,
		},
		{
			name:      "warn level from string",
			json:      `"warn"`,
			wantLevel: slog.LevelWarn,
			wantError: false,
		},
		{
			name:      "error level from string",
			json:      `"error"`,
			wantLevel: slog.LevelError,
			wantError: false,
		},
		{
			name:      "unknown level defaults to info",
			json:      `"unknown"`,
			wantLevel: slog.LevelInfo,
			wantError: false,
		},
		{
			name:      "level from integer",
			json:      `-4`,
			wantLevel: slog.LevelDebug,
			wantError: false,
		},
		{
			name:      "trace level from integer",
			json:      `-8`,
			wantLevel: LevelTrace,
			wantError: false,
		},
		{
			name:      "invalid json",
			json:      `{invalid}`,
			wantLevel: 0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var l logLevel
			err := json.Unmarshal([]byte(tt.json), &l)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantLevel, l.Level())
			}
		})
	}
}

func TestEngineCfg_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantCfg   EngineCfg
		wantError bool
	}{
		{
			name: "full config with trace log level",
			json: `{
				"engines": {
					"cri": {
						"enabled": true,
						"sockets": ["/var/run/cri.sock"]
					}
				},
				"label_max_len": 200,
				"with_size": true,
				"host_root": "/host",
				"hooks": 7,
				"log_level": "trace"
			}`,
			wantCfg: EngineCfg{
				SocketsEngines: map[string]SocketsEngine{
					"cri": {
						Enabled: true,
						Sockets: []string{"/var/run/cri.sock"},
					},
				},
				LabelMaxLen: 200,
				WithSize:    true,
				HostRoot:    "/host",
				Hooks:       7,
				LogLevel:    logLevel(LevelTrace),
			},
			wantError: false,
		},
		{
			name: "config with debug log level as string",
			json: `{
				"log_level": "debug"
			}`,
			wantCfg: EngineCfg{
				LogLevel: logLevel(slog.LevelDebug),
			},
			wantError: false,
		},
		{
			name: "config with info log level as string",
			json: `{
				"log_level": "info"
			}`,
			wantCfg: EngineCfg{
				LogLevel: logLevel(slog.LevelInfo),
			},
			wantError: false,
		},
		{
			name: "config with warn log level as string",
			json: `{
				"log_level": "warn"
			}`,
			wantCfg: EngineCfg{
				LogLevel: logLevel(slog.LevelWarn),
			},
			wantError: false,
		},
		{
			name: "config with error log level as string",
			json: `{
				"log_level": "error"
			}`,
			wantCfg: EngineCfg{
				LogLevel: logLevel(slog.LevelError),
			},
			wantError: false,
		},
		{
			name: "config with log level as integer",
			json: `{
				"log_level": -8
			}`,
			wantCfg: EngineCfg{
				LogLevel: logLevel(LevelTrace),
			},
			wantError: false,
		},
		{
			name: "config with unknown log level defaults to info",
			json: `{
				"log_level": "unknown"
			}`,
			wantCfg: EngineCfg{
				LogLevel: logLevel(slog.LevelInfo),
			},
			wantError: false,
		},
		{
			name: "config without log level",
			json: `{
				"label_max_len": 150
			}`,
			wantCfg: EngineCfg{
				LabelMaxLen: 150,
				LogLevel:    logLevel(0), // zero value
			},
			wantError: false,
		},
		{
			name: "invalid json",
			json: `{
				"log_level": {invalid}
			}`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg EngineCfg
			err := json.Unmarshal([]byte(tt.json), &cfg)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantCfg.LogLevel, cfg.LogLevel)
				if tt.wantCfg.LabelMaxLen != 0 {
					assert.Equal(t, tt.wantCfg.LabelMaxLen, cfg.LabelMaxLen)
				}
				if tt.wantCfg.HostRoot != "" {
					assert.Equal(t, tt.wantCfg.HostRoot, cfg.HostRoot)
				}
				if tt.wantCfg.Hooks != 0 {
					assert.Equal(t, tt.wantCfg.Hooks, cfg.Hooks)
				}
				if len(tt.wantCfg.SocketsEngines) > 0 {
					assert.Equal(t, tt.wantCfg.SocketsEngines, cfg.SocketsEngines)
				}
			}
		})
	}
}

func TestLogLevel_Level(t *testing.T) {
	tests := []struct {
		name     string
		logLevel logLevel
		want     slog.Level
	}{
		{
			name:     "trace level",
			logLevel: logLevel(LevelTrace),
			want:     LevelTrace,
		},
		{
			name:     "debug level",
			logLevel: logLevel(slog.LevelDebug),
			want:     slog.LevelDebug,
		},
		{
			name:     "info level",
			logLevel: logLevel(slog.LevelInfo),
			want:     slog.LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.logLevel.Level())
		})
	}
}
