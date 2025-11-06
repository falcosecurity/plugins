package config

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// falcoLogHandler implements slog.Handler with Falco's log format:
// Thu Nov 06 11:46:17 2025: [container-engine] [info]: message
type falcoLogHandler struct {
	writer io.Writer
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

func newFalcoLogHandler(w io.Writer, level slog.Level) *falcoLogHandler {
	return &falcoLogHandler{
		writer: w,
		level:  level,
		attrs:  []slog.Attr{},
		groups: []string{},
	}
}

func (h *falcoLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *falcoLogHandler) Handle(ctx context.Context, record slog.Record) error {
	// Format: Thu Nov 06 11:46:17 2025: [container-engine] [info]: message
	timestamp := record.Time.Format("Mon Jan 02 15:04:05 2006:")
	levelStr := levelToString(record.Level)

	// Build the log line
	var buf strings.Builder
	buf.WriteString(timestamp)
	buf.WriteString(" [container-engine] [")
	buf.WriteString(levelStr)
	buf.WriteString("]: ")
	buf.WriteString(record.Message)

	// Add attributes if any
	if len(h.attrs) > 0 || record.NumAttrs() > 0 {
		// Add handler-level attributes
		for _, attr := range h.attrs {
			buf.WriteString(" ")
			buf.WriteString(attr.Key)
			buf.WriteString("=")
			buf.WriteString(fmt.Sprintf("%v", attr.Value.Any()))
		}
		// Add record attributes
		record.Attrs(func(attr slog.Attr) bool {
			buf.WriteString(" ")
			buf.WriteString(attr.Key)
			buf.WriteString("=")
			buf.WriteString(fmt.Sprintf("%v", attr.Value.Any()))
			return true
		})
	}

	buf.WriteString("\n")
	_, err := h.writer.Write([]byte(buf.String()))
	return err
}

func (h *falcoLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &falcoLogHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  append(h.attrs, attrs...),
		groups: h.groups,
	}
}

func (h *falcoLogHandler) WithGroup(name string) slog.Handler {
	return &falcoLogHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  h.attrs,
		groups: append(h.groups, name),
	}
}

const LevelTrace slog.Level = -8

func toSlogLevel(level string) slog.Level {
	switch level {
	case "trace":
		return LevelTrace
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// levelToString converts a slog.Level to its string representation,
// handling custom levels like LevelTrace.
func levelToString(level slog.Level) string {
	switch level {
	case LevelTrace:
		return "trace"
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return level.String()
	}
}
