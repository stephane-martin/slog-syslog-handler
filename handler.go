package slogsysloghandler

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
)

type SyslogLogger interface {
	Debug(string) error
	Info(string) error
	Notice(string) error
	Warning(string) error
	Err(string) error
	Crit(string) error
}

type SyslogHandler struct {
	opts         *slog.HandlerOptions
	buf          *bytes.Buffer
	jsonHandler  slog.Handler
	textHandler  slog.Handler
	syslogWriter SyslogLogger
	mu           *sync.Mutex
	writeJson    bool
}

func NewLogger(w SyslogLogger, writeJson bool, opts *slog.HandlerOptions) *slog.Logger {
	return slog.New(NewSyslogHandler(w, writeJson, opts))
}

func NewSyslogHandler(w SyslogLogger, writeJson bool, opts *slog.HandlerOptions) *SyslogHandler {
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

var emptyAttr slog.Attr

func removeLevel(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		if a.Key == slog.LevelKey || a.Key == slog.TimeKey {
			return emptyAttr
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

func (h *SyslogHandler) Enabled(_ context.Context, l slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return l >= minLevel
}

func (h *SyslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// the Mutex protects the buffer from concurrent writes
	// because we allocate another buffer in the new handler,
	// we don't need to share the same mutex with the new handler.
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
	newHandler := &SyslogHandler{
		opts:         h.opts,
		buf:          new(bytes.Buffer),
		mu:           new(sync.Mutex),
		syslogWriter: h.syslogWriter,
		writeJson:    h.writeJson,
	}
	if h.writeJson {
		newHandler.jsonHandler = h.jsonHandler.WithGroup(name)
	} else {
		newHandler.textHandler = h.textHandler.WithGroup(name)
	}
	return newHandler
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
	msg := string(bytes.TrimSpace(h.buf.Bytes()))
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
