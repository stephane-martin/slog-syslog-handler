package slogsysloghandler

import (
	"bytes"
	"context"
	"log/slog"
	"log/syslog"
	"sync"
)

type SyslogHandler struct {
	opts         *slog.HandlerOptions
	buf          *bytes.Buffer
	jsonHandler  slog.Handler
	textHandler  slog.Handler
	syslogWriter *syslog.Writer
	mu           *sync.Mutex
	writeJson    bool
}

var emptyAttr slog.Attr

func removeLevel(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		if a.Key == slog.LevelKey || a.Key == slog.TimeKey {
			return slog.Attr{}
		}
	}
	return a
}

func wrapReplaceAttr(repl func([]string, slog.Attr) slog.Attr) func([]string, slog.Attr) slog.Attr {
	if repl == nil {
		return removeLevel
	}
	return func(groups []string, a slog.Attr) slog.Attr {
		return removeLevel(groups, repl(groups, a))
	}
}

func NewSyslogHandler(w *syslog.Writer, writeJson bool, opts *slog.HandlerOptions) *SyslogHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{
			ReplaceAttr: removeLevel,
		}
	} else {
		opts = &slog.HandlerOptions{
			ReplaceAttr: wrapReplaceAttr(opts.ReplaceAttr),
			Level:       opts.Level,
			AddSource:   opts.AddSource,
		}
	}
	h := &SyslogHandler{
		opts:         opts,
		buf:          new(bytes.Buffer),
		mu:           new(sync.Mutex),
		syslogWriter: w,
		writeJson:    writeJson,
	}
	if writeJson {
		h.jsonHandler = slog.NewJSONHandler(h.buf, opts)
	} else {
		h.textHandler = slog.NewTextHandler(h.buf, opts)
	}
	return h
}

func (h *SyslogHandler) Enabled(_ context.Context, l slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return l >= minLevel
}

func (h *SyslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandler := &SyslogHandler{
		opts:         h.opts,
		buf:          new(bytes.Buffer),
		mu:           new(sync.Mutex),
		syslogWriter: h.syslogWriter,
		writeJson:    h.writeJson,
	}
	if h.writeJson {
		newHandler.jsonHandler = h.jsonHandler.WithAttrs(attrs)
	} else {
		newHandler.textHandler = h.textHandler.WithAttrs(attrs)
	}
	return newHandler
}

func (h *SyslogHandler) WithGroup(name string) slog.Handler {
	if h.writeJson {
		return h.jsonHandler.WithGroup(name)
	}
	return h.textHandler.WithGroup(name)
}

func (h *SyslogHandler) Handle(ctx context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if h.writeJson {
		if err := h.jsonHandler.Handle(ctx, record); err != nil {
			return err
		}
	} else {
		if err := h.textHandler.Handle(ctx, record); err != nil {
			return err
		}
	}
	msg := h.buf.String()
	switch {
	case record.Level <= slog.LevelDebug:
		return h.syslogWriter.Debug(msg)
	case record.Level == slog.LevelInfo:
		return h.syslogWriter.Info(msg)
	case record.Level == slog.LevelWarn:
		return h.syslogWriter.Warning(msg)
	case record.Level == slog.LevelError:
		return h.syslogWriter.Err(msg)
	case record.Level > slog.LevelDebug && record.Level < slog.LevelInfo:
		return h.syslogWriter.Info(msg)
	case record.Level > slog.LevelInfo && record.Level < slog.LevelWarn:
		return h.syslogWriter.Notice(msg)
	case record.Level > slog.LevelWarn && record.Level < slog.LevelError:
		return h.syslogWriter.Err(msg)
	default:
		return h.syslogWriter.Crit(msg)
	}
}
