package config

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFalcoLogHandler_Enabled(t *testing.T) {
	tests := []struct {
		name         string
		handlerLevel slog.Level
		checkLevel   slog.Level
		wantEnabled  bool
	}{
		{
			name:         "trace level enabled when handler is trace",
			handlerLevel: LevelTrace,
			checkLevel:   LevelTrace,
			wantEnabled:  true,
		},
		{
			name:         "debug level enabled when handler is trace",
			handlerLevel: LevelTrace,
			checkLevel:   slog.LevelDebug,
			wantEnabled:  true,
		},
		{
			name:         "info level enabled when handler is trace",
			handlerLevel: LevelTrace,
			checkLevel:   slog.LevelInfo,
			wantEnabled:  true,
		},
		{
			name:         "trace level disabled when handler is debug",
			handlerLevel: slog.LevelDebug,
			checkLevel:   LevelTrace,
			wantEnabled:  false,
		},
		{
			name:         "debug level enabled when handler is debug",
			handlerLevel: slog.LevelDebug,
			checkLevel:   slog.LevelDebug,
			wantEnabled:  true,
		},
		{
			name:         "info level enabled when handler is debug",
			handlerLevel: slog.LevelDebug,
			checkLevel:   slog.LevelInfo,
			wantEnabled:  true,
		},
		{
			name:         "info level enabled when handler is info",
			handlerLevel: slog.LevelInfo,
			checkLevel:   slog.LevelInfo,
			wantEnabled:  true,
		},
		{
			name:         "debug level disabled when handler is info",
			handlerLevel: slog.LevelInfo,
			checkLevel:   slog.LevelDebug,
			wantEnabled:  false,
		},
		{
			name:         "warn level enabled when handler is info",
			handlerLevel: slog.LevelInfo,
			checkLevel:   slog.LevelWarn,
			wantEnabled:  true,
		},
		{
			name:         "error level enabled when handler is info",
			handlerLevel: slog.LevelInfo,
			checkLevel:   slog.LevelError,
			wantEnabled:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newFalcoLogHandler(&bytes.Buffer{}, tt.handlerLevel)
			ctx := context.Background()
			assert.Equal(t, tt.wantEnabled, handler.Enabled(ctx, tt.checkLevel))
		})
	}
}

func TestFalcoLogHandler_Handle(t *testing.T) {
	tests := []struct {
		name      string
		level     slog.Level
		message   string
		attrs     []slog.Attr
		wantParts []string
	}{
		{
			name:    "trace level log",
			level:   LevelTrace,
			message: "test trace message",
			wantParts: []string{
				": [container-engine] [trace]: test trace message",
			},
		},
		{
			name:    "debug level log",
			level:   slog.LevelDebug,
			message: "test debug message",
			wantParts: []string{
				": [container-engine] [debug]: test debug message",
			},
		},
		{
			name:    "info level log",
			level:   slog.LevelInfo,
			message: "test info message",
			wantParts: []string{
				": [container-engine] [info]: test info message",
			},
		},
		{
			name:    "warn level log",
			level:   slog.LevelWarn,
			message: "test warn message",
			wantParts: []string{
				": [container-engine] [warn]: test warn message",
			},
		},
		{
			name:    "error level log",
			level:   slog.LevelError,
			message: "test error message",
			wantParts: []string{
				": [container-engine] [error]: test error message",
			},
		},
		{
			name:    "log with attributes",
			level:   slog.LevelInfo,
			message: "test message",
			attrs: []slog.Attr{
				slog.String("key1", "value1"),
				slog.Int("key2", 42),
			},
			wantParts: []string{
				": [container-engine] [info]: test message",
				"key1=value1",
				"key2=42",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := newFalcoLogHandler(&buf, LevelTrace) // Set to trace to allow all levels

			ctx := context.Background()
			record := slog.NewRecord(time.Now(), tt.level, tt.message, 0)
			for _, attr := range tt.attrs {
				record.AddAttrs(attr)
			}

			err := handler.Handle(ctx, record)
			require.NoError(t, err)

			output := buf.String()
			// Check that output contains timestamp (format: YYYY-MM-DD)
			assert.Contains(t, output, "202")
			// Check that output contains all expected parts
			for _, part := range tt.wantParts {
				assert.Contains(t, output, part)
			}
			// Check that output ends with newline
			assert.True(t, strings.HasSuffix(output, "\n"), "output should end with newline")
		})
	}
}

func TestFalcoLogHandler_Handle_Format(t *testing.T) {
	var buf bytes.Buffer
	handler := newFalcoLogHandler(&buf, LevelTrace)

	ctx := context.Background()
	now := time.Date(2025, 11, 6, 11, 46, 17, 0, time.UTC)
	record := slog.NewRecord(now, slog.LevelInfo, "test message", 0)

	err := handler.Handle(ctx, record)
	require.NoError(t, err)

	output := buf.String()
	// Check Falco log format: Thu Nov 06 11:46:17 2025: [container-engine] [info]: test message
	assert.Contains(t, output, "Thu Nov 06 11:46:17 2025: [container-engine] [info]: test message")
}

func TestFalcoLogHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	handler := newFalcoLogHandler(&buf, LevelTrace)

	attrs := []slog.Attr{
		slog.String("service", "test"),
		slog.Int("version", 1),
	}
	handlerWithAttrs := handler.WithAttrs(attrs).(*falcoLogHandler)

	// Verify attrs were added
	assert.Equal(t, 2, len(handlerWithAttrs.attrs))
	assert.Equal(t, "service", handlerWithAttrs.attrs[0].Key)
	assert.Equal(t, "test", handlerWithAttrs.attrs[0].Value.String())
	assert.Equal(t, "version", handlerWithAttrs.attrs[1].Key)
	assert.Equal(t, int64(1), handlerWithAttrs.attrs[1].Value.Int64())

	// Verify original handler unchanged
	assert.Equal(t, 0, len(handler.attrs))

	// Test that attrs appear in output
	ctx := context.Background()
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	err := handlerWithAttrs.Handle(ctx, record)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, " service=test")
	assert.Contains(t, output, " version=1")
}

func TestLevelToString(t *testing.T) {
	tests := []struct {
		name  string
		level slog.Level
		want  string
	}{
		{
			name:  "trace level",
			level: LevelTrace,
			want:  "trace",
		},
		{
			name:  "debug level",
			level: slog.LevelDebug,
			want:  "debug",
		},
		{
			name:  "info level",
			level: slog.LevelInfo,
			want:  "info",
		},
		{
			name:  "warn level",
			level: slog.LevelWarn,
			want:  "warn",
		},
		{
			name:  "error level",
			level: slog.LevelError,
			want:  "error",
		},
		{
			name:  "unknown level",
			level: slog.Level(999),
			want:  "ERROR+991", // Default slog.String() format
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, levelToString(tt.level))
		})
	}
}

func TestToSlogLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{
			name:  "trace",
			level: "trace",
			want:  LevelTrace,
		},
		{
			name:  "debug",
			level: "debug",
			want:  slog.LevelDebug,
		},
		{
			name:  "info",
			level: "info",
			want:  slog.LevelInfo,
		},
		{
			name:  "warn",
			level: "warn",
			want:  slog.LevelWarn,
		},
		{
			name:  "warning",
			level: "warning",
			want:  slog.LevelWarn,
		},
		{
			name:  "error",
			level: "error",
			want:  slog.LevelError,
		},
		{
			name:  "unknown defaults to info",
			level: "unknown",
			want:  slog.LevelInfo,
		},
		{
			name:  "empty defaults to info",
			level: "",
			want:  slog.LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toSlogLevel(tt.level))
		})
	}
}

func TestNewFalcoLogHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := newFalcoLogHandler(&buf, slog.LevelInfo)

	assert.NotNil(t, handler)
	assert.Equal(t, slog.LevelInfo, handler.level)
	assert.Equal(t, &buf, handler.writer)
	assert.Equal(t, 0, len(handler.attrs))
	assert.Equal(t, 0, len(handler.groups))
}
